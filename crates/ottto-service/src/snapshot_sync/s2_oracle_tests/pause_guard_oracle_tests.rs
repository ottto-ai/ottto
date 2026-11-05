//! Pause guard oracle rows: a paused re-emission list holds adoption only,
//! never `e2` emission. Every emitted body is compared with the cold Full of
//! the same bytes under the installed list.
use super::*;

fn list_path(c: &Corpus) -> PathBuf {
    c.support
        .join("snapshots/claude_code-reemission-exclusions.txt")
}

/// A damaged list file: the list pauses adoption and keeps no digest.
fn pause(c: &Corpus) {
    std::fs::write(list_path(c), "malformed synthetic list\n").unwrap();
}

/// The installed list again: no protected sessions.
fn resume(c: &Corpus) {
    std::fs::write(
        list_path(c),
        "# installed synthetic list, no protected sessions\n",
    )
    .unwrap();
}

fn assert_paused(page: &Page) {
    assert_eq!(
        page.index.claude_reemission_list_status_for_test(),
        "unreadable",
        "precondition: the list pauses adoption"
    );
}

fn grow(c: &Corpus, path: &Path) {
    append(path, &line(ROOT, "later", "2026-08-02T07:04:00Z", 6));
    append(
        &c.root.join(format!("{ROOT}/subagents/agent-000.jsonl")),
        &line(ROOT, "agent-later", "2026-08-02T07:04:00Z", 3),
    );
}

fn body_witnesses(page: &Page) -> BTreeMap<String, String> {
    page.scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect()
}

/// [money] G1: an accepted `e2` family that grows while the list is paused
/// uploads the same literal bodies, placement and side call as the unpaused
/// cold Full, through the emission seam and the resend hook.
#[test]
fn paused_list_unlisted_family_uploads_e2_literal() {
    with_e2(|| {
        let (c, path) = placement_corpus("g1-paused-growth");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        grow(&c, &path);
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive control: two placed accounts"
        );
        pause(&c);
        let mut paused = page(&c, prior, 100, true);
        assert_paused(&paused);
        assert_eq!(paused.modes.0, 0, "growth under a pause reads Tail");
        money_oracle::assert_equivalent(&cold, &result(&paused, Mode::Restart));
        let literals = |page: &Page| {
            page.scan
                .snapshots
                .iter()
                .filter(|item| {
                    crate::snapshots::claude_request_money::is_request_owned_literal(item)
                })
                .count()
        };
        let emitted = literals(&paused);
        assert!(emitted > 0, "the emission seam keeps the literal");
        paused.finish();
        assert_eq!(literals(&paused), emitted, "the resend hook keeps it too");
    });
}

/// [money] G2: owed, unchanged history of an accepted family stays held while
/// the list is paused: no body, and its accepted body and revision stay.
#[test]
fn paused_list_owed_unchanged_history_held() {
    with_e2(|| {
        let mut c = corpus("g2-paused-owed");
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
        assert!(prior.re_owe_effective_upload_body_witness_revision(key, 2));
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        pause(&c);
        let current = page(&c, prior, 100, true);
        assert_paused(&current);
        let mut held = result(&current, Mode::Restart);
        held.accepted = prior_body.accepted.clone();
        money_oracle::assert_held(ROOT, &prior_body, &held, &cold);
        assert_eq!(
            current.index.files[key].last_upload_body_witness,
            current.committed.files[key].last_upload_body_witness
        );
        assert_eq!(
            current.index.files[key].effective_upload_body_witness_revision,
            2
        );
    });
}

/// [money] G3: a family first uploaded while the list is paused sends the
/// unpaused body but stamps nothing; it stays held while the pause lasts.
/// Once the list is back it is adopted: anything it sends again is the
/// accepted body itself, it stamps, and a quiet restart reads nothing.
#[test]
fn e2_uploaded_under_pause_restamps_after_resume_counted_once() {
    with_e2(|| {
        let (c, _) = placement_corpus("g3-paused-new");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert!(
            accounts(&cold).len() >= 2,
            "positive control: two placed accounts"
        );
        pause(&c);
        let first = page(&c, index, 100, true);
        assert_paused(&first);
        let sent = result(&first, Mode::Restart);
        money_oracle::assert_equivalent(&cold, &sent);
        let prior = commit(&session, first);
        assert!(!prior.files.is_empty());
        for (key, entry) in &prior.files {
            assert!(
                entry.effective_upload_body_witness_revision < 3,
                "a pause stamps nothing: {key}"
            );
        }
        let still_paused = page(&c, prior.clone(), 100, true);
        assert!(
            still_paused.scan.snapshots.is_empty(),
            "owed under a pause: held"
        );
        resume(&c);
        let resumed = page(&c, prior, 100, true);
        let resent = result(&resumed, Mode::Restart);
        for (entity, body) in &resent.snapshots {
            assert_eq!(
                Some(body),
                sent.snapshots.get(entity),
                "a re-send is the accepted body: {entity}"
            );
        }
        let settled = commit(&session, resumed);
        for (key, entry) in &settled.files {
            assert_eq!(
                entry.effective_upload_body_witness_revision, 3,
                "adopted once the list is back: {key}"
            );
        }
        let (quiet, consumed) = fixture::observe_consumed(|| page(&c, settled, 100, true));
        assert!(quiet.scan.snapshots.is_empty());
        assert_eq!(quiet.modes.0, 0, "quiet restart read Full");
        assert_eq!(consumed, 0, "quiet restart: no transcript consumption");
    });
}

/// [money] G6: under a pause, a lost ACK settles nothing; the restart from
/// the last saved index sends the same bodies, equal to the unpaused cold
/// Full. A partial answer settles only the accepted entity.
#[test]
fn paused_e2_ack_loss_restart_exact_receipt() {
    with_e2(|| {
        let (c, path) = placement_corpus("g6-paused-ack-loss");
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, index, 100, true));
        grow(&c, &path);
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        pause(&c);
        let lost = page(&c, prior.clone(), 100, true);
        assert_paused(&lost);
        let mut progress = e2_progress();
        let (status, _, _) = upload(&lost.scan.snapshots, &mut progress, |_| {
            Err(anyhow::anyhow!("synthetic response lost after store"))
        });
        assert!(status.is_err());
        assert!(
            progress.accepted_fingerprints.is_empty(),
            "no answer settles nothing"
        );
        // Crash before the index save: restart from the last saved index.
        let replay = page(&c, prior, 100, true);
        assert_eq!(
            body_witnesses(&replay),
            body_witnesses(&lost),
            "the replay sends the same bodies"
        );
        money_oracle::assert_equivalent(&cold, &result(&replay, Mode::Restart));
        let mut progress = e2_progress();
        // Patched and unpatched bodies travel in separate requests; the
        // server refuses one entity overall.
        let mut refused_once = false;
        let (status, _, _) = upload(&replay.scan.snapshots, &mut progress, |items| {
            let mut response = ack(items)?;
            if std::mem::replace(&mut refused_once, true) {
                return Ok(response);
            }
            let mut refused = response.accepted_entities.pop().unwrap();
            response.accepted -= 1;
            refused.head_etag = None;
            // Head-CAS covers the request once an item carries cache
            // observations, so a conflict carries a head challenge.
            if items.iter().any(|item| item.cache_observations.is_some()) {
                refused.head_challenge = Some("c".repeat(64));
            }
            response.conflict_entities.push(refused);
            Ok(response)
        });
        assert_eq!(
            status.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(
            progress.accepted_fingerprints.len(),
            replay.scan.snapshots.len() - 1,
            "only the exact ACK settles"
        );
    });
}

/// [money] G7: pages restored from the database between appends while the
/// list is paused emit, together, the cold Full's bodies; a quiet restart
/// then reads nothing.
#[test]
fn paused_e2_partial_restore_preserves_accepted() {
    with_e2(|| {
        let mut c = corpus("g7-paused-pages");
        let root = c.root(ROOT, &line(ROOT, "a", AT, 10));
        let copy = c.root(COPY, &line(COPY, "b", AT, 20));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let mut index = commit(&session, page(&c, index, 100, true));
        pause(&c);
        let mut items = BTreeMap::new();
        for (path, session_id, request) in [(&root, ROOT, "a2"), (&copy, COPY, "b2")] {
            append(path, &line(session_id, request, "2026-08-02T07:01:00Z", 7));
            let current = page(&c, index, 100, true);
            assert_paused(&current);
            assert_eq!(current.modes.0, 0, "the stored head continues");
            for item in &current.scan.snapshots {
                items.insert(item.source_session_id.clone(), item.clone());
            }
            index = commit(&session, current);
        }
        let ((quiet, modes), consumed) = fixture::observe_consumed(|| {
            let quiet = page(&c, index, 100, true);
            let modes = quiet.modes;
            (quiet, modes)
        });
        assert!(quiet.scan.snapshots.is_empty());
        assert_eq!(modes.0, 0);
        assert_eq!(consumed, 0, "quiet restart: no transcript consumption");
        resume(&c);
        let mut cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert_eq!(items.len(), 2);
        let items: Vec<_> = items.into_values().collect();
        let (status, batches, _) = upload(&items, &mut e2_progress(), ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let mut warm = RouteResult::emitted(Mode::Restart, SOURCE, batches, &items);
        // Independent page ACKs: body placement is compared, not one ledger.
        cold.accepted_identity_buckets = None;
        warm.accepted_identity_buckets = None;
        money_oracle::assert_equivalent(&cold, &warm);
    });
}
