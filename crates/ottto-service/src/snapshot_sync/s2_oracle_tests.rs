//! Scan-level Claude Tail oracle rows using the existing synthetic pipeline.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, Mode, RouteResult,
};
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::StateV2ColdSession;

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;

// State stores require canonical ancestors; CI deliberately gives TMPDIR a
// symlink, just as macOS does. Canonicalize before creating any fixture paths.
fn corpus(name: &str) -> Corpus {
    let mut c = Corpus::new(name);
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    c
}

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
    hinted(c, index, limit, sampled, &[])
}

/// A page that also receives the watcher's exact path hints. Re-listing is
/// paced (`LISTING_INTERVAL_SECONDS`), so within one test second an append is
/// seen through the hint the daemon's watcher gives it.
fn hinted(c: &Corpus, index: ScanIndex, limit: usize, sampled: bool, hints: &[PathBuf]) -> Page {
    let mut page = c.raw(
        &E2ScanFixture::capturing_identity(),
        index,
        limit,
        sampled,
        hints,
    );
    page.enrich(c);
    page
}

/// Commit the native page's exact ACKs and context receipts to the same
/// live database; the next caller gets the production cold load.
fn commit(session: &StateV2ColdSession, page: Page) -> ScanIndex {
    commit_with_progress(session, page).0
}

fn commit_with_progress(
    session: &StateV2ColdSession,
    mut page: Page,
) -> (ScanIndex, SnapshotUploadProgress) {
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
    (session.save_reload(&mut page.index), progress)
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
    let mut c = corpus(name);
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

/// [money] A restarted Tail and an evicted owner preserve two-account
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
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        let prior = commit(&session, seed);
        append(&path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
        append(
            &c.root.join(format!("{ROOT}/subagents/agent-000.jsonl")),
            &line(ROOT, "agent-later", "2026-08-02T07:04:00Z", 3),
        );
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
        scanner.evict(&prior);
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

/// [money] A body the server deferred for its identity (503) waits as a due
/// retry. Its unchanged file re-folds from the committed Tail, with no Full,
/// to the cold Full's body and placement (two accounts, a mid-session switch,
/// a side call and an evidence gap). The retried body is one finalized item,
/// POSTed once per upload and cleared only by its exact ACK. A session that
/// owes a head-CAS answer reads the same body through a native Full. A
/// challenge whose session holds no saved base can carry no answer: the
/// upload-context activation leaves it unmirrored, so the due retry, a
/// twin's family pull and growth continue from stored state to the cold
/// Full's body, and its ordinary accept clears it.
#[test]
fn an_identity_deferred_retry_refolds_to_the_cold_full_body() {
    with_e2(|| {
        let (mut c, path) = placement_corpus("s2-identity-deferred-retry");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        seed.finish();
        let refused = seed
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .expect("the root body")
            .snapshot_fingerprint
            .clone();
        // The server sheds the root for its identity; its siblings ACK.
        let shed =
            |batch: &[SnapshotItem]| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
                match batch
                    .iter()
                    .position(|item| item.snapshot_fingerprint == refused)
                {
                    Some(index) => Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                        code: Some(
                            crate::snapshot_client::UploadShedCode::OriginalIdentityUnavailable,
                        ),
                    })
                    .context(ShedSnapshotIndexes(vec![index]))),
                    None => ack(batch),
                }
            };
        let mut progress = e2_progress();
        let _ = upload(&seed.scan.snapshots, &mut progress, shed);
        assert!(!progress.accepted_fingerprints.contains(&refused));
        let held = progress.quarantined_fingerprints.get_mut(&refused).unwrap();
        assert_eq!(
            held.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        held.retry_after_unix_seconds = 0; // due now
        seed.index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        accept_upload_context_acks_for_test(
            &mut seed.index,
            &seed.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        seed.index
            .retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        let mut prior = session.save_reload(&mut seed.index);
        prior.activate_quarantine_witness_for_test(SOURCE);

        let mut cold_page = page(&c, ScanIndex::default(), 100, false);
        cold_page
            .scan
            .snapshots
            .retain(|item| item.source_session_id == ROOT);
        let cold = result(&cold_page, Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive control: two placed accounts in the retried session"
        );

        let retried = page(&c, prior.clone(), 100, true);
        assert_eq!(retried.modes.0, 0, "the due retry re-folds, never Full");
        let bodies = retried
            .scan
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == ROOT)
            .collect::<Vec<_>>();
        assert_eq!(bodies.len(), 1, "finalize carries the retried body once");
        assert_eq!(bodies[0].snapshot_fingerprint, refused, "the same body");
        let warm = result(&retried, Mode::Restart);
        money_oracle::assert_equivalent(&cold, &warm);
        let mut wrong = warm.clone();
        wrong.snapshots.get_mut(ROOT).unwrap()["request_evidence"][0]["provider_workspace_hash"] =
            json!("f".repeat(64));
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &wrong)).is_err()
        );

        // The held body is leased, POSTed once, and only an exact ACK clears it.
        progress.prepare_quarantine_retries(&prior.quarantined_snapshot_fingerprints);
        assert!(progress.active_quarantine_retries.contains(&refused));
        let leased = progress.clone();
        let posts = |sent: &[Vec<u8>]| {
            sent.iter()
                .map(|bytes| {
                    let wire: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                    json_array(&wire["snapshots"])
                        .iter()
                        .filter(|item| item["snapshot_fingerprint"] == refused.as_str())
                        .count()
                })
                .sum::<usize>()
        };
        let mut inexact = progress.clone();
        let (status, _, _) = upload(&retried.scan.snapshots, &mut inexact, |batch| {
            let mut response = ack(batch)?;
            for entity in &mut response.accepted_entities {
                entity.body_witness_digest = Some("0".repeat(64));
            }
            Ok(response)
        });
        assert!(!matches!(status, Ok(ResumableUploadResult::Completed)));
        assert!(!inexact.accepted_fingerprints.contains(&refused));
        assert_eq!(
            inexact.quarantined_fingerprints[&refused].disposition,
            SnapshotQuarantineDisposition::RetryPending,
            "a witness-mismatched ACK clears nothing"
        );
        let (status, sent, _) = upload(&retried.scan.snapshots, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(posts(&sent), 1, "POSTed exactly once");
        assert!(progress.accepted_fingerprints.contains(&refused));
        assert!(!progress.quarantined_fingerprints.contains_key(&refused));

        // A session that owes a head-CAS answer reads Full, to the same body.
        let mut owed = prior.clone();
        owed.activate_head_conflict_sessions([cache_session_key(ROOT)].into());
        let answered = page(&c, owed, 100, true);
        assert!(answered.modes.0 > 0, "the owed answer reads a native Full");
        money_oracle::assert_equivalent(&cold, &result(&answered, Mode::ColdFull));

        // A base-less challenge (no saved head or cache state, no attempt),
        // mirrored the production way; a saved base is the mirrored control.
        let key = cache_session_key(ROOT);
        let mut challenged = leased.clone();
        challenged.head_conflict_challenges.insert(
            key.clone(),
            HeadConflictChallenge {
                challenge: "c".repeat(64),
                stale_revision_v2_hash: "d".repeat(64),
                answer_attempts: 0,
                last_answer_unix: 0,
            },
        );
        assert!(!challenged.accepted_cache_heads.contains_key(&key));
        assert!(!challenged.accepted_cache_states.contains_key(&key));
        let mut based = challenged.clone();
        based
            .accepted_cache_heads
            .insert(key.clone(), "e".repeat(64));
        let activated = |progress: &SnapshotUploadProgress| {
            let mut index = prior.clone();
            activate_source_upload_context(
                SOURCE,
                "e2-synthetic-destination".into(),
                &mut index,
                &mut progress.clone(),
            );
            index
        };
        assert!(!activated(&challenged).head_conflict_owed(&key), "no base");
        assert!(activated(&based).head_conflict_owed(&key), "control");
        let same_sessions = |cold: &mut Page, warm: &Page| {
            cold.scan.snapshots.retain(|item| {
                warm.scan
                    .snapshots
                    .iter()
                    .any(|warm| warm.source_session_id == item.source_session_id)
            });
        };

        // The due retry re-folds to the cold Full; the base-holding control
        // still reads Full.
        let refolded = page(&c, activated(&challenged), 100, true);
        assert_eq!(refolded.modes.0, 0, "a base-less challenge re-folds");
        let refolded_route = result(&refolded, Mode::Restart);
        money_oracle::assert_equivalent(&cold, &refolded_route);
        // Its requests are class-pure: the body travels in the class its own
        // cache patch selects, never under another body's CAS contract.
        money_oracle::assert_class_pure_requests(&refolded_route);
        let mirrored = page(&c, activated(&based), 100, true);
        assert!(mirrored.modes.0 > 0, "control: a saved base reads Full");

        // No answer can attach: the POSTs carry no rescan claim, the exact
        // ACK settles the body, and the ordinary accept clears the challenge.
        let mut items = refolded.scan.snapshots.clone();
        for item in &mut items {
            item.cache_base_head_etag = challenged
                .accepted_cache_heads
                .get(&cache_session_key(&item.source_session_id))
                .cloned();
        }
        assert_eq!(
            attach_head_conflict_answers(&mut items, &challenged, current_unix_seconds()),
            0
        );
        let mut settled = challenged.clone();
        let (status, sent, _) = upload(&items, &mut settled, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(posts(&sent), 1, "POSTed exactly once");
        for bytes in &sent {
            let wire: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            for item in json_array(&wire["snapshots"]) {
                for claim in [
                    "conflict_head_challenge",
                    "forced_full_rescan",
                    "rescan_from_revision_hash",
                ] {
                    assert!(item.get(claim).is_none(), "{claim}");
                    assert!(item["semantic_envelope"].get(claim).is_none(), "{claim}");
                }
            }
        }
        assert!(
            settled.accepted_fingerprints.contains(&refused),
            "exact ACK"
        );
        assert!(!settled.quarantined_fingerprints.contains_key(&refused));
        assert!(
            !settled.head_conflict_challenges.contains_key(&key),
            "the ordinary accept clears it"
        );

        // ForcedFamily: a twin copy the page reads pulls the family in. The
        // base-less session reads exactly as an unchallenged one; mirrored,
        // the pulled root reads Full instead.
        let twin = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &std::fs::read_to_string(&path).unwrap(),
            "2026-08-02T07:05:00Z",
        );
        let pulled = |progress: &SnapshotUploadProgress| {
            hinted(
                &c,
                activated(progress),
                100,
                true,
                std::slice::from_ref(&twin),
            )
        };
        let plain = pulled(&leased);
        let family = pulled(&challenged);
        assert_eq!(family.modes, plain.modes, "base-less reads as unchallenged");
        assert!(
            pulled(&based).modes.0 > plain.modes.0,
            "control: the pulled root is selected, and mirrored reads Full"
        );
        let mut family_cold = page(&c, ScanIndex::default(), 100, false);
        same_sessions(&mut family_cold, &family);
        let family_cold = result(&family_cold, Mode::ColdFull);
        assert!(accounts(&family_cold).len() >= 2, "positive control");
        money_oracle::assert_equivalent(&family_cold, &result(&family, Mode::Restart));
        std::fs::remove_file(&twin).unwrap();
        c.births.remove(&twin);

        // Growth reads a Tail append to the cold Full's body.
        append(&path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
        let grown = hinted(
            &c,
            activated(&challenged),
            100,
            true,
            std::slice::from_ref(&path),
        );
        assert_eq!(grown.modes.0, 0, "a base-less grown file never reads Full");
        assert!(grown.modes.1 > 0, "it continues as an append");
        let mut grown_cold = page(&c, ScanIndex::default(), 100, false);
        same_sessions(&mut grown_cold, &grown);
        let grown_cold = result(&grown_cold, Mode::ColdFull);
        assert!(accounts(&grown_cold).len() >= 2, "positive control");
        money_oracle::assert_equivalent(&grown_cold, &result(&grown, Mode::Restart));

        // The answer is accepted and the challenge clears, so the next
        // prepare mirrors none. The next pass continues the session's files
        // from the Tail: the root's growth and its subagent member's growth
        // (the member the family pull brings in) read no Full and miss no
        // stored head.
        let mut cleared = commit(&session, answered);
        cleared.activate_head_conflict_sessions(BTreeSet::new());
        append(&path, &line(ROOT, "after-clear", "2026-08-02T07:05:00Z", 6));
        append(
            &c.root.join(format!("{ROOT}/subagents/agent-000.jsonl")),
            &line(ROOT, "after-clear-agent", "2026-08-02T07:05:00Z", 3),
        );
        let misses = || {
            crate::snapshots::e2_pipeline_scan_fixture::tail_counter_for_test(
                "tail_db_loads",
                "miss",
            )
        };
        let before = misses();
        let next = page(&c, cleared, 100, true);
        assert_eq!(misses() - before, 0, "no stored-head miss after the clear");
        assert_eq!(next.modes.0, 0, "no Full after the clear, members included");
        assert!(next.modes.1 > 0, "the growth reads Tail");
    });
}

fn json_array(value: &serde_json::Value) -> &[serde_json::Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

/// [money] A census deadline withholds a NEW copied file, so it gains no
/// index entry. After the save and reload its committed head, custody and
/// never acceptance, still continues it: the unchanged walk reads no
/// transcript byte and growth reads Tail. The released body and its
/// placement equal the cold Full's.
#[test]
fn held_new_file_continues_from_its_committed_head() {
    held_new_file_continues(false);
}

/// [regress] The same after a restart: RAM holds nothing of the held file,
/// and its durable custody (census record and committed head) continues it.
#[test]
fn held_new_file_continues_after_a_restart() {
    held_new_file_continues(true);
}

fn held_new_file_continues(restart: bool) {
    use crate::snapshots::claude_request_census::with_walk_deadline_for_test as deadline;
    with_e2(|| {
        let mut c = corpus(&format!("s2-held-new-continues-{restart}"));
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.evidence_for(
            COPY,
            &[api_login(COPY, "own", 20, '1', Some('7'))],
            &[trace_for(COPY, "own", "")],
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut progress = e2_progress();
        // The root, then the one-time identity-contract re-arm.
        let mut prior = ScanIndex::default();
        for _ in 0..2 {
            let settled = ready(&c, &scanner, prior.clone(), 100, true);
            prior = settle_captured_holds(&c, &prior, settled, &mut progress);
        }
        let accepted_before = progress.accepted_fingerprints.clone();
        let path = c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "root", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let key = path.to_string_lossy().into_owned();
        let mut first = c.raw(&scanner, prior.clone(), 100, true, &[]);
        deadline(|| first.enrich(&c));
        assert_withheld(&first, COPY, "external census unavailable");
        let prior = settle_captured_holds(&c, &prior, first, &mut progress);
        assert!(
            !prior.files.contains_key(&key),
            "a held NEW file has no entry"
        );
        let restarted = E2ScanFixture::capturing_identity();
        let scanner = if restart {
            let route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&prior).unwrap();
            crate::snapshots::e2_pipeline_scan_fixture::continue_route_for_test(
                &restarted.cache,
                &route,
            );
            &restarted
        } else {
            &scanner
        };

        let (mut unchanged, consumed) =
            fixture::observe_consumed(|| c.raw(scanner, prior.clone(), 100, true, &[]));
        assert_eq!(unchanged.modes, (0, 0, 1), "the committed head continues");
        assert_eq!(
            consumed, 0,
            "an unchanged held file reads no transcript byte"
        );
        deadline(|| unchanged.enrich(&c));
        assert_withheld(&unchanged, COPY, "external census still unavailable");
        let prior = settle_captured_holds(&c, &prior, unchanged, &mut progress);
        assert!(!prior.files.contains_key(&key));
        assert_eq!(progress.accepted_fingerprints, accepted_before);

        // Pre-birth, so growth alone cannot release the all-copied hold.
        append(&path, &line(COPY, "own", "2026-08-02T07:01:00Z", 20));
        let mut grown = c.raw(scanner, prior.clone(), 100, true, &[]);
        assert_eq!(grown.modes, (0, 1, 0), "growth reads past the head only");
        grown.enrich(&c);
        let warm = result(&grown, Mode::Restart);
        assert!(
            warm.snapshots.contains_key(COPY),
            "external evidence releases it"
        );
        let unrouted =
            crate::snapshots::e2_pipeline_scan_fixture::route_for_test(SOURCE, None, prior);
        let cold = result(&page(&c, unrouted, 100, false), Mode::ColdFull);
        money_oracle::assert_equivalent(&cold, &warm);
        grown.finish();
    });
}

/// [money] Pages use fresh owners and cold graph loads at every boundary.
/// Accumulated emitted bodies equal the single cold Full upload.
#[test]
fn restart_between_pages_matches_single_full() {
    with_e2(|| {
        let mut c = corpus("s2-restart-pages");
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
        assert_eq!(consumed, 0, "quiet restart: no transcript consumption");
    });
}

/// [money] A partial entity ACK cannot settle the sibling. Retry bodies stay
/// exact and the resulting accepted placement agrees with the cold Full.
#[test]
fn partial_ack_keeps_the_unaccepted_sibling_owed() {
    with_e2(|| {
        let (c, path) = placement_corpus("s2-partial-ack");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        append(&path, "{broken\n");
        append(
            &path,
            &line(ROOT, "partial-later", "2026-08-02T07:04:00Z", 6),
        );
        append(
            &c.root.join(format!("{ROOT}/subagents/agent-000.jsonl")),
            &line(ROOT, "partial-agent", "2026-08-02T07:04:00Z", 3),
        );
        let current = page(&c, prior, 100, true);
        assert_eq!(current.modes.0, 0, "partial ACK uses a stored Tail");
        assert!(current.modes.1 > 0);
        let cold_page = page(&c, ScanIndex::default(), 100, false);
        let cold = result(&cold_page, Mode::ColdFull);
        assert_eq!(current.scan.malformed_json_line_count, 1);
        assert_eq!(
            serde_json::to_value(&current.index).unwrap()["terminal_jsonl_dispositions"],
            serde_json::to_value(&cold_page.index).unwrap()["terminal_jsonl_dispositions"]
        );
        let loss_body = current
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .unwrap();
        let loss_fingerprint = loss_body.snapshot_fingerprint.clone();
        let loss_witness = snapshot_upload_body_witness(loss_body);
        let mut progress = e2_progress();
        // Patched and unpatched bodies may travel in separate requests; only
        // the request holding the other entity carries the refusal.
        let (status, batches, _) = upload(&current.scan.snapshots, &mut progress, |items| {
            let mut response = ack(items)?;
            // Preserve the existing partial outcome while exactly ACKing
            // the loss-bearing root and leaving its other entity owed.
            let Some(other) = response
                .accepted_entities
                .iter()
                .position(|entity| entity.source_session_id != ROOT)
            else {
                return Ok(response);
            };
            let mut refused = response.accepted_entities.remove(other);
            response.accepted -= 1;
            // Cache rows put the request under head-CAS: the refusal then
            // carries the server's challenge instead of a head.
            refused.head_challenge = refused.head_etag.take().map(|_| "c".repeat(64));
            response.conflict_entities.push(refused);
            Ok(response)
        });
        assert_eq!(
            status.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        assert!(progress.accepted_fingerprints.contains(&loss_fingerprint));
        assert_eq!(
            progress.accepted_body_witnesses.get(&loss_fingerprint),
            Some(&loss_witness)
        );
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
        assert_eq!(
            restored.accepted_body_witnesses.get(&loss_fingerprint),
            Some(&loss_witness)
        );
        assert!(current.scan.snapshots.iter().any(|item| !progress
            .accepted_fingerprints
            .contains(&item.snapshot_fingerprint)));
    });
}

/// [money] A saved accepted extent ahead of all available bytes, with no
/// independent shrink proof. No floor holds the file (D158): whatever the
/// scan reads, it never re-emits a smaller body, and any body it sends is the
/// cold Full's.
#[test]
fn scan_behind_accepted_never_reemits_a_smaller_body() {
    with_e2(|| {
        let mut c = corpus("s2-scan-behind-accepted");
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
        // An evidence-only clear removes the current-census shrink proof,
        // without relaxing the accepted extent we are testing.
        prior
            .files
            .get_mut(key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let current = page(&c, prior, 100, true);
        let mut observed = result(&current, Mode::Restart);
        let sent = current
            .scan
            .snapshots
            .iter()
            .any(|item| item.source_session_id == ROOT);
        if sent {
            money_oracle::assert_no_smaller_reemit(
                ROOT,
                &prior_body,
                &observed,
                &prior_body,
                false,
            );
        } else {
            observed.accepted = prior_body.accepted.clone();
            money_oracle::assert_no_smaller_reemit(ROOT, &prior_body, &observed, &prior_body, true);
            assert_eq!(
                current.index.files[key].last_upload_body_witness,
                current.committed.files[key].last_upload_body_witness
            );
        }
    });
}

/// [money] A bad physical record preserves valid siblings through durable
/// Tail and later appends, matching byte-zero Full including placement.
#[test]
fn bad_record_tail_matches_full_and_keeps_valid_siblings() {
    with_e2(|| {
        let mut c = corpus("s2-lossy-prefix");
        let path = c.root(ROOT, &line(ROOT, "a", AT, 10));
        let sibling = c.root(COPY, &line(COPY, "sibling", AT, 5));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let scanner = E2ScanFixture::capturing_identity();
        scanner.on_committed_route(session.path());
        let read = |index, hints: &[PathBuf]| {
            let mut page = c.raw(&scanner, index, 100, true, hints);
            page.enrich(&c);
            page
        };
        let initial = read(index, &[]);
        let mut previous = result(&initial, Mode::ColdFull);
        accepted(&mut previous, &initial.scan.snapshots);
        let prior = commit(&session, initial);
        append(
            &path,
            &(String::from("{broken\n") + &line(ROOT, "b", "2026-08-02T07:01:00Z", 20)),
        );
        append(
            &sibling,
            &line(COPY, "sibling-later", "2026-08-02T07:01:00Z", 7),
        );
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let current = read(prior, &[]);
        assert_eq!(current.modes.0, 0);
        assert!(current.modes.1 > 0);
        assert_eq!(current.scan.malformed_json_line_count, 1);
        assert_eq!(
            current
                .scan
                .snapshots
                .iter()
                .find(|s| s.source_session_id == ROOT)
                .unwrap()
                .input_tokens,
            30
        );
        let emitted = result(&current, Mode::Restart);
        money_oracle::assert_no_smaller_reemit(ROOT, &previous, &emitted, &cold, false);
        // The changed sibling is offered before its exact ACK; suppression
        // must never substitute for receiving that body's witness.
        let sibling_item = current
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == COPY)
            .unwrap();
        assert_eq!(sibling_item.input_tokens, 12);
        let sibling_fingerprint = sibling_item.snapshot_fingerprint.clone();
        let sibling_witness = snapshot_upload_body_witness(sibling_item);
        assert!(!current
            .committed
            .accepted_snapshot_fingerprint_recorded(&sibling_fingerprint));
        let (prior, progress) = commit_with_progress(&session, current);
        assert!(prior.accepted_snapshot_fingerprint_recorded(&sibling_fingerprint));
        // A file stores a set digest, not an individual entity witness.
        // Compare the exact-body ACK at its native per-entity boundary.
        assert_eq!(
            progress.accepted_body_witnesses.get(&sibling_fingerprint),
            Some(&sibling_witness)
        );
        let continuation = crate::snapshots::e2_pipeline_scan_fixture::continuation_for_test(
            SOURCE,
            &scanner.cache,
            &prior,
            path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            continuation.sealed_offset(),
            std::fs::metadata(&path).unwrap().len()
        );
        append(&path, &line(ROOT, "c", "2026-08-02T07:02:00Z", 30));
        // Apply the same root selection before serialization on both routes.
        let select_root = |page: &mut Page| {
            page.scan.snapshots.retain(|s| s.source_session_id == ROOT);
        };
        let mut cold_page = page(&c, ScanIndex::default(), 100, false);
        select_root(&mut cold_page);
        let cold = result(&cold_page, Mode::ColdFull);
        let mut replay = read(prior, &[path, sibling]);
        assert!(
            !replay
                .scan
                .snapshots
                .iter()
                .any(|item| item.source_session_id == COPY),
            "only the exact ACK above suppresses the unchanged sibling"
        );
        // Same-generation growth continues the saved head despite its loss.
        assert_eq!(replay.modes, (0, 1, 0));
        let dispositions = |page: &Page| {
            serde_json::to_value(&page.index).unwrap()["terminal_jsonl_dispositions"].clone()
        };
        let cold_loss = dispositions(&cold_page);
        let losses = cold_loss.as_object().unwrap();
        assert_eq!(losses.len(), 1);
        assert_eq!(
            losses.values().next().unwrap()["loss"]["malformed_json_line_count"],
            1
        );
        assert_eq!(dispositions(&replay), cold_loss);
        assert_eq!(
            replay
                .scan
                .snapshots
                .iter()
                .find(|s| s.source_session_id == ROOT)
                .unwrap()
                .input_tokens,
            60
        );
        // Select before serialization so the real uploader derives the
        // envelope contracts from exactly the bodies being compared.
        select_root(&mut replay);
        money_oracle::assert_equivalent(&cold, &result(&replay, Mode::Restart));
    });
}

/// [money] Fixed-evidence path twins converge through real scan + exact ACK
/// + database reload. A settled family is never selected on later walks.
fn assert_family_converges(c: &Corpus, session: &StateV2ColdSession, mut index: ScanIndex) {
    let mut counts = Vec::new();
    let cold = result(&page(c, ScanIndex::default(), 100, false), Mode::ColdFull);
    for pass in 0..6 {
        let current = page(c, index, 100, true);
        if pass == 0 {
            money_oracle::assert_equivalent(&cold, &result(&current, Mode::Restart));
        }
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

/// [money] Resolved path twins stop selecting with evidence fixed. The later
/// twin's own turn is after the copy proof cutoff, so the same-session page
/// proof dedupes its copied request whenever both twins are read.
#[test]
fn forced_family_converges_after_resolve() {
    with_e2(|| {
        let mut c = corpus("s2-family-convergence");
        c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "a", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "a", AT, 10) + &line(ROOT, "b", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
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
        let (c, _) = placement_corpus("s2-changed-account");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let first = page(&c, index, 100, true);
        let before = result(&first, Mode::ColdFull);
        let prior = commit(&session, first);
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
        // Root and child depend on this sidecar: select SourceChanged while
        // keeping each file's previous exact upload-context receipt valid.
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

/// D62 guard: the census deadline holds past the expired hold's pass too.
/// That pass's body was the hold's one delivery; the hold never restarts, and
/// nothing selects afterwards.
#[test]
fn e2_pipeline_resumed_prefix_hold_expired_under_deadline_never_restarts_the_hold() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-prefix-expiry-deadline");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut progress = e2_progress();
        let scanner = E2ScanFixture::default();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, true);
        let mut prior = settle(&c, &old, original, &mut progress);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        let under_deadline = |prior: ScanIndex| {
            let mut page = c.raw(&scanner, prior, 100, true, &[]);
            crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                page.enrich(&c);
            });
            page
        };
        for _ in 1..=3 {
            let page = under_deadline(prior.clone());
            prior = settle(&c, &prior, page, &mut progress);
        }
        let after = under_deadline(prior);
        assert!(
            body(&after, COPY).is_none(),
            "the expired hold never restarts"
        );
    });
}

mod pause_guard_oracle_tests;
