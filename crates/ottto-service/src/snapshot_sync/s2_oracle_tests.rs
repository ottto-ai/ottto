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
    commit_finished_with_progress(session, page)
}

fn commit_finished_with_progress(
    session: &StateV2ColdSession,
    mut page: Page,
) -> (ScanIndex, SnapshotUploadProgress) {
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

/// [money] Deferred session ticks keep every append at the committed Tail cursor.
#[test]
fn battery_skipped_ticks_preserve_all_appends() {
    with_e2(|| {
        let (c, path) = placement_corpus("battery-appends");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        let agent_path = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.record_scan_success(start, 1);
        cadence.set_power_stretch(3);
        let mut suffix_bytes = 0;
        // Appends at three skipped observations; the third 5-minute tick scans.
        for (n, seconds) in [1, 300, 600].into_iter().enumerate() {
            let suffix = line(ROOT, &format!("battery-{n}"), "2026-08-02T07:04:00Z", 6);
            suffix_bytes += suffix.len() as u64;
            append(&path, &suffix);
            let agent_suffix = line(
                ROOT,
                &format!("battery-agent-{n}"),
                "2026-08-02T07:04:00Z",
                3,
            );
            suffix_bytes += agent_suffix.len() as u64;
            append(&agent_path, &agent_suffix);
            cadence.record_file_event(start + Duration::from_secs(seconds));
            assert!(!cadence
                .next_scan_after(start + Duration::from_secs(seconds))
                .is_zero());
        }
        assert!(cadence
            .next_scan_after(start + SNAPSHOT_SYNC_INTERVAL * 3)
            .is_zero());
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let (stored, bytes) =
            fixture::observe_consumed(|| hinted(&c, prior, 100, true, &[path, agent_path]));
        assert_eq!(bytes, suffix_bytes, "every skipped byte read exactly once");
        assert_eq!(stored.modes.0, 0, "same cursor, no Full");
        assert!(stored.modes.1 > 0, "all skipped appends read by Tail");
        money_oracle::assert_equivalent(&cold, &result(&stored, Mode::Restart));
    });
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
            |batch: &[&SnapshotItem]| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
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
            attach_head_conflict_answers(&mut items, &challenged, current_unix_seconds(), |_| {
                false
            }),
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

/// [money] Updated-file row of `shed_save_commits_heads_only_for_kept_entries`:
/// a shed partial save keeps an appended file's committed entry and head, so
/// its unACKed turn stays owed. The next page reads it by Tail, once: the
/// body and its placement (two accounts, a switch, a side call and an
/// evidence gap) equal a cold Full's.
#[test]
fn shed_save_keeps_an_appended_turn_owed_once() {
    use crate::snapshots::e2_pipeline_scan_fixture::{
        continuation_for_test, route_of, save_reload_for_test,
    };
    with_e2(|| {
        let (c, path) = placement_corpus("s2-shed-appended-owed");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        let prior = commit(&session, seed);
        let agent = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
        append(&path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
        append(
            &agent,
            &line(ROOT, "agent-later", "2026-08-02T07:04:00Z", 3),
        );
        let grown = [path.clone(), agent];
        let head = |index: &ScanIndex| {
            continuation_for_test(SOURCE, &scanner.cache, index, path.to_str().unwrap())
                .map(|head| head.sealed_offset())
        };
        let kept = head(&prior);
        assert!(kept.is_some(), "the seed commits a head");
        // The upload sheds before any ACK: only the partial checkpoint saves.
        let mut shed = c.raw(&scanner, prior.clone(), 100, true, &grown);
        shed.enrich(&c);
        let holds = shed.finish();
        assert!(shed.modes.1 > 0, "the shed page reads the append");
        let route = route_of(&shed.committed).unwrap();
        let progress_path = snapshot_upload_progress_path(&route);
        let durable = std::fs::read(&progress_path).map_or_else(
            |_| e2_progress(),
            |bytes| serde_json::from_slice(&bytes).unwrap(),
        );
        let mut saved = checkpoint_partial_snapshot_index(
            &shed.index,
            &shed.committed,
            &durable,
            &shed.scan.snapshots,
            Some(&shed.scan),
            &holds.held_fingerprints,
            &route,
            &progress_path,
            || Ok(()),
        )
        .unwrap();
        let prior = save_reload_for_test(&mut saved, &c.base.join("scan-index.json"));
        assert_eq!(head(&prior), kept, "the shed save keeps the committed head");
        let mut owed = hinted(&c, prior, 100, true, &grown);
        assert_eq!(owed.modes.0, 0, "the kept head continues: no Full");
        assert!(owed.modes.1 > 0, "the appended turn reads by Tail");
        assert!(
            owed.scan
                .snapshots
                .iter()
                .any(|item| item.source_session_id == ROOT),
            "the unACKed turn stays owed"
        );
        let mut cold_page = page(&c, ScanIndex::default(), 100, false);
        cold_page.scan.snapshots.retain(|item| {
            owed.scan
                .snapshots
                .iter()
                .any(|owed| owed.source_session_id == item.source_session_id)
        });
        let cold = result(&cold_page, Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive control: two placed accounts"
        );
        money_oracle::assert_equivalent(&cold, &result(&owed, Mode::Restart));
        owed.finish();
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
        // Positive control: upload-context stamps crossed each cold reload.
        let proof = serde_json::to_value(&index.upload_context_proof).unwrap();
        assert!(proof["entity_stamps"]
            .as_object()
            .is_some_and(|stamps| !stamps.is_empty()));
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
            ResumableUploadResult::Deferred {
                count: 1,
                isolated: 1,
                identity_503: 0
            }
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
        progress.save_fixture(&progress_path).unwrap();
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
/// independent shrink proof. No floor holds the file: whatever the
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

mod pause_guard_oracle_tests;

mod subagent_twin_tests;

#[path = "unkept_requeue_oracle_tests.rs"]
mod unkept_requeue_oracle_tests;

#[path = "context_posture_refold_tests.rs"]
mod context_posture_refold_tests;

/// [money] A lone 413 keeps prior accepted money and retries without an ACK or retirement.
#[test]
fn lone_413_keeps_money_pending_until_exact_ack() {
    with_e2(|| {
        let (c, path) = placement_corpus("lone-413");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let seed = page(&c, index, 100, true);
        let mut prior = result(&seed, Mode::ColdFull);
        accepted(&mut prior, &seed.scan.snapshots);
        let (index, mut progress) = commit_with_progress(&session, seed);
        append(&path, &line(ROOT, "after-413", "2026-08-02T07:04:00Z", 6));
        let candidate = hinted(&c, index, 100, true, &[path]);
        let lone = candidate
            .scan
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == ROOT)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(lone.len(), 1);
        let cold_page = page(&c, ScanIndex::default(), 100, false);
        let cold_items = cold_page
            .scan
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == ROOT)
            .cloned()
            .collect::<Vec<_>>();
        let cold = RouteResult::emitted(
            Mode::ColdFull,
            SOURCE,
            upload(&cold_items, &mut e2_progress(), ack).1,
            &cold_items,
        );
        assert!(accounts(&cold).len() >= 2);
        let before = progress.accepted_fingerprints.clone();
        let accepted_bodies = progress.accepted_body_witnesses.clone();
        progress.fresh_context_body_acks.clear();
        let receipts = progress.fresh_context_body_acks.clone();
        for _ in 0..2 {
            let (outcome, _, _) = upload(&lone, &mut progress, |_| {
                Err(anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
                    "local snapshot upload",
                    "snapshot_batch",
                    413,
                    false,
                )))
            });
            let error = outcome.unwrap_err();
            assert!(error
                .downcast_ref::<UploadFailureDiagnostics>()
                .unwrap()
                .is_snapshot_batch_too_large());
            assert!(error.downcast_ref::<UploadShed>().is_none());
            assert!(progress.permanent_rejections.is_empty());
            assert!(progress.active_quarantine_retries.is_empty());
            assert_eq!(progress.accepted_fingerprints, before);
            assert_eq!(progress.accepted_body_witnesses, accepted_bodies);
            assert_eq!(progress.fresh_context_body_acks, receipts);
            assert!(progress.quarantined_fingerprints.is_empty());
            progress = serde_json::from_value(serde_json::to_value(&progress).unwrap()).unwrap();
        }
        let mut held = RouteResult::emitted(Mode::Restart, SOURCE, vec![], &[]);
        held.accepted = prior.accepted.clone();
        money_oracle::assert_held(ROOT, &prior, &held, &cold);
        let (outcome, sent, _) = upload(&lone, &mut progress, ack);
        assert_eq!(outcome.unwrap(), ResumableUploadResult::Completed);
        money_oracle::assert_equivalent(
            &cold,
            &RouteResult::emitted(Mode::Restart, SOURCE, sent, &lone),
        );
    });
}

/// [money] Returning quarantines use the same native body and post-ACK placement
/// as cold Full, including an indexed subagent owner and a progress-first crash.
#[test]
fn current_again_quarantines_retry_root_and_subagent_without_changing_money() {
    with_e2(|| {
        let (c, root_path) = placement_corpus("current-again-quarantines");
        let child_path = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
        let cold_page = page(&c, ScanIndex::default(), 100, false);
        let cold = result(&cold_page, Mode::ColdFull);
        assert!(accounts(&cold).len() >= 2);
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        seed.finish();
        let mut progress = e2_progress();
        progress
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        for item in &seed.scan.snapshots {
            progress.quarantine_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(item),
            );
        }
        assert!(progress.retain_current_quarantines(&BTreeSet::new(), &seed.index));
        seed.index
            .retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        let mut prior = session.save_reload(&mut seed.index);
        let terminal = prior.quarantined_snapshot_fingerprints.clone();
        assert!(progress.retain_current_quarantines(&prior.current_snapshot_fingerprints(), &prior));
        assert!(progress
            .quarantined_fingerprints
            .values()
            .all(|r| r.failed_reconstruction_count == 1 && r.retry_after_unix_seconds == 0));
        let progress_path = c.base.join("retry-progress.json");
        progress.save_fixture(&progress_path).unwrap();
        // Crash before index save: progress is pending and the index is terminal.
        prior = ScanIndex::load(session.path()).unwrap();
        progress = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            snapshot_quarantine_witness(SOURCE),
        )
        .unwrap();
        progress
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        assert_eq!(prior.quarantined_snapshot_fingerprints, terminal);
        assert!(progress.prepare_quarantine_retries(&prior.quarantined_snapshot_fingerprints));
        progress.save_fixture(&progress_path).unwrap();
        let hints =
            save_terminal_contract_claims_for_scan(&mut prior, &progress, session.path()).unwrap();
        assert_eq!(
            hints.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([root_path, child_path.clone()])
        );
        let saved = ScanIndex::load(session.path()).unwrap();
        assert_eq!(
            saved.quarantined_snapshot_fingerprints,
            progress.quarantined_fingerprints
        );
        prior.activate_quarantine_witness_for_test(SOURCE);
        let queued = c.raw(&scanner, prior, 0, true, &hints);
        assert!(queued.scan.snapshots.is_empty());
        let child_fp = seed
            .scan
            .snapshots
            .iter()
            .find(|i| i.source_session_id == format!("{ROOT}_agent-000"))
            .unwrap()
            .snapshot_fingerprint
            .clone();
        assert!(queued.index.quarantine_retry_is_queued(&child_fp));
        assert!(!progress.defer_held_quarantine_retries(
            &queued.scan.snapshots,
            &queued.index,
            SOURCE
        ));
        // A bounded page may leave a family member queued. Resume its retained
        // queue without re-hinting an already selected owner ahead of its sibling.
        let mut retry = hinted(&c, queued.index, 100, true, &[]);
        let mut offered = Vec::new();
        for _ in 0..8 {
            retry.finish();
            assert_eq!(
                retry.modes.0, 0,
                "stored Tail retry must not cause a Full read"
            );
            offered.append(&mut retry.scan.snapshots);
            if retry.scan.census_complete {
                break;
            }
            retry = hinted(&c, retry.index, 100, true, &[]);
        }
        assert!(
            retry.scan.census_complete,
            "drain the retained family queue"
        );
        retry.scan.snapshots = offered;
        assert_eq!(
            retry
                .scan
                .snapshots
                .iter()
                .filter(|i| i.snapshot_fingerprint == child_fp)
                .count(),
            1
        );
        let child_key = child_path.to_str().unwrap();
        assert!(retry.index.file_snapshot_fingerprints[child_key].contains(&child_fp));
        let (status, batches, _) = upload(&retry.scan.snapshots, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let mut actual =
            RouteResult::emitted(Mode::Restart, SOURCE, batches, &retry.scan.snapshots);
        actual.accepted_identity_buckets = Some(
            serde_json::to_value(
                retry
                    .scan
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
        money_oracle::assert_equivalent(&cold, &actual);
        progress.save_fixture(&progress_path).unwrap();
        // A second crash after the durable ACK cannot restore the old retry.
        let mut restored = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            snapshot_quarantine_witness(SOURCE),
        )
        .unwrap();
        assert!(!restored.prepare_quarantine_retries(&saved.quarantined_snapshot_fingerprints));
        assert!(restored.active_quarantine_retries.is_empty());
        retry
            .index
            .retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        retry
            .index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        accept_upload_context_acks_for_test(
            &mut retry.index,
            &retry.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        assert!(retry.index.files[child_key]
            .upload_context_receipt
            .is_some());
        let mut prior = session.save_reload(&mut retry.index);
        assert!(
            save_terminal_contract_claims_for_scan(&mut prior, &restored, session.path())
                .unwrap()
                .is_empty()
        );
        let mut quiet = page(&c, prior, 100, true);
        quiet.finish();
        assert!(quiet.scan.snapshots.is_empty());
    });
}

mod family_census_tests;

// Direct scan fixtures walk the live Claude identity census. These small
// files each fit in its one 4 KiB head sample. Compute the exact permitted
// anchor bytes from fixture lengths BEFORE observing the scan; parser/body
// bytes and every other I/O class remain forbidden by the shared oracle.
fn owner_return_anchor_window(c: &Corpus) -> u64 {
    c.births
        .keys()
        .map(|path| match std::fs::metadata(path) {
            Ok(metadata) => {
                assert!(metadata.len() <= 4096);
                metadata.len()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("synthetic identity metadata: {error}"),
        })
        .sum()
}

/// [money] A fresh claim selects the original published custody after two other
/// owners. The ordinary native scan and stored Tail conserve a real two-account
/// fixture, including a switch, side call, evidence gap and tagged shares.
#[test]
#[serial]
fn owner_return_keeps_the_placement_oracle_and_quiet_restart() {
    if !crate::test_isolation::run_here() {
        return;
    }
    with_e2(|| {
        let (c, path) = placement_corpus("owner-return-placement");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &c.support);
        let secrets = c.base.join("synthetic-secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", "https://api.ottto.net");
        let namespace = "a".repeat(64);
        let index_path = c
            .support
            .join("snapshots/destinations")
            .join(&namespace)
            .join("claude_code-scan-index-v3.json");
        let progress =
            serde_json::to_vec(&json!({"schema_version":3,"destination_namespace_hash":namespace}))
                .unwrap();
        let (session, index) =
            StateV2ColdSession::publish_at(&ScanIndex::default(), &index_path, &progress);
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        let prior = commit(&session, seed);
        crate::control::owner_return_seed_for_test(&namespace, "owner-a");
        let device = LocalDeviceBinding {
            device_id: "placement-b".into(),
            machine_id: Some("machine_test".into()),
            sources: vec!["claude_code".into()],
        };
        for (user, id) in [
            ("owner-b", "placement-b"),
            ("owner-c", "placement-c"),
            ("owner-a", "placement-a-return"),
        ] {
            let device = LocalDeviceBinding {
                device_id: id.into(),
                ..device.clone()
            };
            let selected = crate::control::owner_return_credential_for_test(
                &device,
                &format!("secret-{id}"),
                user,
            );
            if user == "owner-a" {
                assert_eq!(selected, namespace);
            } else {
                assert_ne!(selected, namespace);
            }
        }
        // No index/progress migration or synthetic ACK is part of selection.
        let restored = ScanIndex::load(&index_path).unwrap();
        append(&path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
        append(
            &c.root.join(format!("{ROOT}/subagents/agent-000.jsonl")),
            &line(ROOT, "agent-later", "2026-08-02T07:04:00Z", 3),
        );
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive placed-account control"
        );
        let uninterrupted = result(&page(&c, prior, 100, true), Mode::Ram);
        let returned_page = page(&c, restored, 100, true);
        let returned = result(&returned_page, Mode::Restart);
        money_oracle::assert_equivalent(&cold, &uninterrupted);
        money_oracle::assert_equivalent(&cold, &returned);
        let saved = commit(&session, returned_page);
        let anchor_window = owner_return_anchor_window(&c);
        let (quiet, io) = fixture::observe_codex_quiet(|| page(&c, saved, 100, true));
        let mut quiet_route = result(&quiet, Mode::Restart);
        quiet_route.io = io;
        money_oracle::assert_quiet_restart_with_anchor_window(&quiet_route, anchor_window);
    });
}

/// [money] The returning owner's saved accepted heads survive the server's
/// switch cutoff. Pre-cutoff owed activity stays excluded; a spanning session
/// remains a whole session, using the ordinary cutoff and oracle paths.
#[test]
fn owner_return_cutoff_keeps_prior_heads_and_whole_spanning_sessions() {
    with_e2(|| {
        let (c, path) = placement_corpus("owner-return-cutoff");
        let initial = page(&c, ScanIndex::default(), 100, false);
        let mut prior = result(&initial, Mode::ColdFull);
        accepted(&mut prior, &initial.scan.snapshots);
        for cutoff in ["2026-08-02T07:10:00Z", "2026-08-02T07:11:00Z"] {
            let mut owed = page(&c, ScanIndex::default(), 100, false);
            let count = owed.scan.snapshots.len();
            let state = crate::backfill::BackfillState {
                backfill_cutoff_at: Some(cutoff.into()),
                ..Default::default()
            };
            assert_eq!(
                apply_backfill_cutoff(&mut owed.scan.snapshots, &state),
                count
            );
            let mut held = result(&owed, Mode::Restart);
            held.accepted = prior.accepted.clone();
            for entity in prior.snapshots.keys() {
                // All pre-cutoff entities are held; compare each independently
                // using the real accepted body's exact witness.
                let mut one = prior.clone();
                one.snapshots.retain(|key, _| key == entity);
                one.normalized
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .for_each(|batch| {
                        batch["snapshots"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|body| body["source_session_id"] == entity.as_str());
                    });
                one.normalized
                    .as_array_mut()
                    .unwrap()
                    .retain(|batch| !batch["snapshots"].as_array().unwrap().is_empty());
                money_oracle::assert_held(entity, &prior, &held, &one);
                money_oracle::assert_no_smaller_reemit(entity, &prior, &held, &one, true);
            }
        }
        append(
            &path,
            &line(ROOT, "after-return", "2026-08-02T07:12:00Z", 7),
        );
        let whole = page(&c, ScanIndex::default(), 100, false);
        let expected = whole
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .unwrap()
            .input_tokens;
        let mut spanning = page(&c, ScanIndex::default(), 100, false);
        let state = crate::backfill::BackfillState {
            backfill_cutoff_at: Some("2026-08-02T07:11:00Z".into()),
            ..Default::default()
        };
        apply_backfill_cutoff(&mut spanning.scan.snapshots, &state);
        assert_eq!(
            spanning
                .scan
                .snapshots
                .iter()
                .find(|item| item.source_session_id == ROOT)
                .unwrap()
                .input_tokens,
            expected
        );
    });
}

/// [money] Accepted original/copy state remains in its original custody after
/// the original disappears and another owner is installed. Selection grants no
/// new acceptance and the unchanged survivor keeps its saved body and proofs.
#[test]
#[serial]
fn owner_return_keeps_deleted_original_copy_custody() {
    if !crate::test_isolation::run_here() {
        return;
    }
    with_e2(|| {
        let mut c = corpus("owner-return-copy");
        let original = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &c.support);
        let secrets = c.base.join("synthetic-secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", "https://api.ottto.net");
        let namespace = "a".repeat(64);
        let index_path = c
            .support
            .join("snapshots/destinations")
            .join(&namespace)
            .join("claude_code-scan-index-v3.json");
        let progress =
            serde_json::to_vec(&json!({"schema_version":3,"destination_namespace_hash":namespace}))
                .unwrap();
        let (session, index) =
            StateV2ColdSession::publish_at(&ScanIndex::default(), &index_path, &progress);
        let scanner = E2ScanFixture::default();
        let first = ready(&c, &scanner, index, 100, true);
        let prior = commit(&session, first);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "r1", AT, 10) + &line(COPY, "branch-own", "2026-08-02T07:03:10Z", 0)),
            "2026-08-02T07:03:00Z",
        );
        let copied = ready(&c, &scanner, prior, 100, true);
        assert_eq!(
            body(&copied, COPY).unwrap().removed_request_count,
            Some(1),
            "accepted original proves the removal"
        );
        let mut prior_money = result(&copied, Mode::ColdFull);
        accepted(&mut prior_money, &copied.scan.snapshots);
        let prior = commit(&session, copied);
        std::fs::remove_file(original).unwrap();
        let left = ready(&c, &scanner, prior, 100, true);
        assert!(
            left.scan.snapshots.is_empty(),
            "unchanged survivor emits nothing new"
        );
        let prior = commit(&session, left);
        let stored = stored_bodies(&prior);
        crate::control::owner_return_seed_for_test(&namespace, "owner-a");
        for (user, id) in [("owner-b", "copy-b"), ("owner-a", "copy-a-return")] {
            let device = LocalDeviceBinding {
                device_id: id.into(),
                machine_id: Some("machine_test".into()),
                sources: vec!["claude_code".into()],
            };
            let selected = crate::control::owner_return_credential_for_test(
                &device,
                &format!("secret-{id}"),
                user,
            );
            if user == "owner-a" {
                assert_eq!(selected, namespace);
            }
        }
        let restored = ScanIndex::load(&index_path).unwrap();
        assert_eq!(stored_bodies(&restored), stored);
        let anchor_window = owner_return_anchor_window(&c);
        let (quiet, io) = fixture::observe_codex_quiet(|| {
            ready(&c, &E2ScanFixture::default(), restored, 100, true)
        });
        let mut observed = result(&quiet, Mode::Restart);
        observed.io = io;
        observed.accepted = prior_money.accepted.clone();
        money_oracle::assert_quiet_restart_with_anchor_window(&observed, anchor_window);
        money_oracle::assert_held(COPY, &prior_money, &observed, &prior_money);
        money_oracle::assert_no_smaller_reemit(COPY, &prior_money, &observed, &prior_money, true);
        assert_eq!(stored_bodies(&quiet.index), stored);
    });
}
