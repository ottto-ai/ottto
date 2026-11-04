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
        scanner.evict_for_pressure(&prior);
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

/// Failure context for the lossy row: scan counters and every index field
/// that names the lossy file.
fn lossy_diag(label: &str, page: &Page, key: &str) -> String {
    let scan = &page.scan;
    let fields = serde_json::to_value(&page.committed)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, v)| v.to_string().contains(key))
        .map(|(k, v)| {
            let text = v.to_string().chars().take(1500).collect::<String>();
            format!("{k}={text}")
        })
        .collect::<Vec<_>>();
    format!(
        "\n[{label}] modes={:?} discovered={} scanned={} limit_skipped={} \
         malformed={} census_complete={} emitted={:?} decode_hold={} \
         len={:?}\n committed_entry={:?}\n after_entry={:?}\n fields={fields:?}",
        page.modes,
        scan.discovered_file_count,
        scan.scanned_file_count,
        scan.skipped_file_count_due_to_limit,
        scan.malformed_json_line_count,
        scan.census_complete,
        scan.snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<Vec<_>>(),
        page.committed.decode_holds_file(key),
        std::fs::metadata(key).map(|m| m.len()).ok(),
        page.committed.files.get(key),
        page.index.files.get(key),
    )
}

/// [money] A lossy append gets no new stored authority. Repeated reads from
/// the last good head retain the cold Full's money and loss disclosures.
#[test]
fn lossy_prefix_retains_the_previous_head_and_matches_full() {
    with_e2(|| {
        let mut c = corpus("s2-lossy-prefix");
        let path = c.root(ROOT, &line(ROOT, "a", AT, 10));
        let sibling = c.root(COPY, &line(COPY, "sibling", AT, 5));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let initial = page(&c, index, 100, true);
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
        let current = page(&c, prior, 100, true);
        let key = path.to_str().unwrap().to_owned();
        let mut diag = format!(
            "cold emitted={:?}",
            cold.snapshots.keys().collect::<Vec<_>>()
        );
        diag += &lossy_diag("lossy", &current, &key);
        assert_eq!(current.modes.0, 0, "{diag}");
        assert!(current.modes.1 > 0, "{diag}");
        let mut held = result(&current, Mode::Restart);
        held.accepted = previous.accepted.clone();
        money_oracle::assert_held(ROOT, &previous, &held, &cold);
        let prior = commit(&session, current);
        // The lossy completion set no marker and kept the pre-append entry,
        // so unchanged bytes would rightly skip: they reproduce the same hold.
        // New bytes after the lossy point, seen through the watcher hint,
        // re-select the file; the Tail continues from the retained head.
        append(&path, &line(ROOT, "c", "2026-08-02T07:02:00Z", 30));
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        let replay = hinted(&c, prior, 100, true, std::slice::from_ref(&path));
        diag += &lossy_diag("replay", &replay, &key);
        assert_eq!(
            replay.modes.0, 0,
            "lossy completion must leave the old head{diag}"
        );
        assert!(
            replay.modes.1 > 0,
            "the old seal must replay the lossy suffix{diag}"
        );
        // Nothing new is emitted: the root is held again, as in a cold Full
        // of the same bytes, and the sibling is unchanged since the lossy
        // page, so that page's emitted sibling body is the stored path's.
        assert!(replay.scan.snapshots.is_empty(), "{diag}");
        assert!(!cold.snapshots.contains_key(ROOT), "{diag}");
        money_oracle::assert_held(ROOT, &previous, &held, &cold);
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
