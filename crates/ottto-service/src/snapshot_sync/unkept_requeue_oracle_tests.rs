//! Native partial-checkpoint transitions, using the shared emitted-money oracle.
use super::*;

const SESSIONS: [&str; 3] = [
    "019fa111-2222-7333-8444-555555555551",
    "019fa111-2222-7333-8444-555555555552",
    "019fa111-2222-7333-8444-555555555553",
];

fn response_line(source: SnapshotSource, session: &str, turn: u64) -> String {
    match source {
        SnapshotSource::ClaudeCode => line(session, &format!("req-{session}-{turn}"), AT, 10),
        SnapshotSource::Codex => {
            json!({"timestamp":AT,"type":"event_msg",
            "payload":{"type":"token_count","info":{"model":"gpt-5.2",
                "total_token_usage":{"input_tokens":turn*10,"output_tokens":turn*2},
                "last_token_usage":{"input_tokens":10,"output_tokens":2}}}})
            .to_string()
                + "\n"
        }
        SnapshotSource::Pi => {
            json!({"type":"message","id":format!("a{turn}"),
            "parentId":"u0","timestamp":AT,"message":{"role":"assistant",
                "provider":"openai","model":"gpt-5.4","api":"openai-responses",
                "responseId":format!("response-{turn}"),"timestamp":AT,"stopReason":"stop",
                "usage":{"input":10,"output":2,"totalTokens":12,"cost":{"total":0.001}}}})
            .to_string()
                + "\n"
        }
    }
}

fn native_corpus(source: SnapshotSource) -> (Corpus, Vec<PathBuf>) {
    native_corpus_of(source, &SESSIONS)
}

fn native_corpus_of(source: SnapshotSource, sessions: &[&str]) -> (Corpus, Vec<PathBuf>) {
    let mut c = corpus("unkept-native-oracle");
    let paths = sessions
        .iter()
        .map(|session| {
            let header = match source {
                SnapshotSource::ClaudeCode => String::new(),
                SnapshotSource::Codex => {
                    json!({"type":"session_meta","timestamp":AT,
                "payload":{"id":session,"timestamp":AT}})
                    .to_string()
                        + "\n"
                }
                SnapshotSource::Pi => {
                    json!({"type":"session","version":3,"id":session,
                "timestamp":AT,"cwd":"/tmp/synthetic"})
                    .to_string()
                        + "\n"
                        + &json!({"type":"message","id":"u0","timestamp":AT,
                    "message":{"role":"user","content":[]}})
                        .to_string()
                        + "\n"
                }
            };
            c.root(session, &(header + &response_line(source, session, 1)))
        })
        .collect();
    (c, paths)
}

fn native_page(
    source: SnapshotSource,
    c: &Corpus,
    prior: ScanIndex,
    limit: usize,
    sampled: bool,
) -> Page {
    let scanner = E2ScanFixture::capturing_identity();
    if source == SOURCE {
        let mut page = c.raw(&scanner, prior, limit, sampled, &[]);
        page.enrich(c);
        assert!(page.finish().held_fingerprints.is_empty());
        assert_eq!(scanner.full_reasons().iter().sum::<usize>(), page.modes.0);
        eprintln!("unkept Full reasons: {:?}", scanner.full_reasons());
        return page;
    }
    let committed = prior.clone();
    let (mut index, mut scan, modes) = scanner.scan_other_page(
        source,
        std::slice::from_ref(&c.root),
        &c.support,
        prior,
        sampled,
        limit,
        &[],
    );
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(source, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    assert_eq!(scanner.full_reasons().iter().sum::<usize>(), modes.0);
    eprintln!("unkept Full reasons: {:?}", scanner.full_reasons());
    Page {
        cache: scanner.cache.clone(),
        committed,
        index,
        scan,
        modes,
        disposition: Default::default(),
        released: Default::default(),
        stats: Default::default(),
        delivered: None,
        upload_policy: SnapshotUploadPolicy::default(),
    }
}

fn progress(source: SnapshotSource) -> SnapshotUploadProgress {
    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    progress
}

fn send(
    source: SnapshotSource,
    page: &Page,
    progress: &mut SnapshotUploadProgress,
    respond: impl FnMut(&[SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, RouteResult) {
    let (status, batches, _) = upload_source_under(
        source,
        SnapshotUploadPolicy::default(),
        &page.scan.snapshots,
        progress,
        respond,
    );
    let sent = batches
        .iter()
        .flat_map(|bytes| {
            let wire: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            wire["snapshots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["snapshot_fingerprint"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    let items = page
        .scan
        .snapshots
        .iter()
        .filter(|item| sent.contains(&item.snapshot_fingerprint))
        .cloned()
        .collect::<Vec<_>>();
    let mut route = RouteResult::emitted(Mode::Ram, source, batches, &items);
    if source == SnapshotSource::Codex {
        route.codex_evidence = fixture::codex_evidence(&page.index, &page.scan);
    }
    route.modes = page.modes;
    route.accepted_identity_buckets = Some(
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
    (status, route)
}

fn accept(source: SnapshotSource, page: &Page) -> RouteResult {
    let (status, result) = send(source, page, &mut progress(source), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    result
}

fn checkpoint(
    page: &Page,
    progress: &mut SnapshotUploadProgress,
    index_path: &Path,
    cause: Option<crate::snapshots::UnsettledUploadCause>,
) -> ScanIndex {
    let progress_path = snapshot_upload_progress_path(index_path);
    if progress.ack_recovery.is_none() {
        progress.ack_recovery =
            crate::snapshots::ProgressRecovery::for_index(&page.committed, index_path)
                .unwrap()
                .map(Box::new);
    }
    progress.save(&progress_path).unwrap();
    checkpoint_partial_snapshot_index_with_audit_release(
        &page.index,
        &page.committed,
        progress,
        &page.scan.snapshots,
        Some(&page.scan),
        &BTreeSet::new(),
        index_path,
        &progress_path,
        || Ok(()),
        None,
        cause,
        None,
        Default::default(),
    )
    .unwrap()
}

fn commit_native(source: SnapshotSource, session: &StateV2ColdSession, page: Page) -> ScanIndex {
    commit_native_with_progress(source, session, page).0
}

fn commit_native_with_progress(
    source: SnapshotSource,
    session: &StateV2ColdSession,
    mut page: Page,
) -> (ScanIndex, SnapshotUploadProgress) {
    let mut progress = progress(source);
    assert_eq!(
        send(source, &page, &mut progress, ack).0.unwrap(),
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

/// [regress] New and updated files stay queued on a retained traversal after
/// shed, upload error or pre-upload recovery, across an in-process page or restart.
/// [money] Each native retry equals cold Full, including the accepted placement ledger.
#[test]
#[serial]
fn retained_unkept_revisions_requeue_for_every_source_and_failure() {
    use crate::snapshots::UnsettledUploadCause::{Shed, UploadError};
    with_e2(|| {
        for source in [SOURCE, SnapshotSource::Codex, SnapshotSource::Pi] {
            for updated in [false, true] {
                for cause in [Some(Shed), Some(UploadError), None] {
                    for restart in [false, true] {
                        let (c, paths) = native_corpus(source);
                        let db_source = match source {
                            SOURCE => Source::Claude,
                            SnapshotSource::Codex => Source::Codex,
                            SnapshotSource::Pi => Source::Pi,
                        };
                        let (session, mut prior) = StateV2ColdSession::publish(
                            db_source,
                            &ScanIndex::default(),
                            &c.base.join("state"),
                        );
                        if updated {
                            prior = commit_native(
                                source,
                                &session,
                                native_page(source, &c, prior, 100, true),
                            );
                            for (path, session) in paths.iter().zip(SESSIONS) {
                                append(path, &response_line(source, session, 2));
                            }
                        }
                        let cold = accept(
                            source,
                            &native_page(source, &c, ScanIndex::default(), 100, false),
                        );
                        assert_eq!(cold.snapshots.len(), 3, "nonempty cold control");
                        let (first, first_bytes) =
                            fixture::observe_consumed(|| native_page(source, &c, prior, 2, true));
                        assert_eq!(first.scan.scanned_file_count, 2);
                        assert!(!first.scan.census_complete, "retained traversal");
                        assert!(first_bytes > 0, "native transcript acquisition");
                        let mut progress = progress(source);
                        if cause.is_some() {
                            let outcome = if cause == Some(Shed) {
                                PipelineUpload::Shed
                            } else {
                                PipelineUpload::UploadError
                            };
                            let (status, _) = send(source, &first, &mut progress, |_| {
                                if outcome == PipelineUpload::Shed {
                                    Err(anyhow::Error::new(UploadShed {
                                        status: 503,
                                        retry_after: None,
                                        code: None,
                                    }))
                                } else {
                                    Err(anyhow!("synthetic upload error"))
                                }
                            });
                            if cause == Some(Shed) {
                                assert!(matches!(
                                    status.unwrap(),
                                    ResumableUploadResult::Shed { .. }
                                ));
                            } else {
                                assert!(status.is_err());
                            }
                        }
                        let mut owed = checkpoint(&first, &mut progress, session.path(), cause);
                        let mut cadence = crate::adaptive_collector::SourceCadence::new(
                            crate::adaptive_collector::CadenceConfig::cost_first(
                                Duration::from_secs(60),
                            ),
                        );
                        let mut now = Instant::now();
                        for repeated in 0..2 {
                            cadence.record_scan_failure(now);
                            let wait = cadence.next_scan_after(now);
                            assert!(!wait.is_zero());
                            let (((), bytes), samples) =
                                crate::transcript_acquisition::capture_sample_reads(|| {
                                    fixture::observe_consumed(|| {
                                        assert!(
                                            cadence.next_scan_after(
                                                now + wait - Duration::from_nanos(1)
                                            ) > Duration::ZERO
                                        );
                                        if cause == Some(Shed) {
                                            let previous_deadline = source_upload_deadlines()
                                                .lock()
                                                .unwrap()
                                                .get(source.api_slug())
                                                .copied();
                                            defer_source_uploads(source, Duration::from_secs(60));
                                            assert!(
                                                source_upload_backoff_remaining(source).is_some()
                                            );
                                            // Test clock release through the existing source deadline owner.
                                            source_upload_deadlines().lock().unwrap().insert(
                                                source.api_slug(),
                                                Instant::now() - Duration::from_secs(1),
                                            );
                                            assert!(
                                                source_upload_backoff_remaining(source).is_none()
                                            );
                                            if let Some(previous) = previous_deadline {
                                                source_upload_deadlines()
                                                    .lock()
                                                    .unwrap()
                                                    .insert(source.api_slug(), previous);
                                            }
                                        }
                                    })
                                });
                            assert_eq!(bytes, 0, "no scan before ordinary/source eligibility");
                            assert!(samples.is_empty());
                            now += wait;
                            assert_eq!(cadence.next_scan_after(now), Duration::ZERO);
                            if cause.is_some() {
                                let (again, bytes) = fixture::observe_consumed(|| {
                                    native_page(source, &c, owed, 2, true)
                                });
                                assert!(!again.scan.census_complete);
                                let mut posts = 0;
                                let (status, _) = send(source, &again, &mut progress, |_| {
                                    posts += 1;
                                    if cause == Some(Shed) {
                                        Err(anyhow::Error::new(UploadShed {
                                            status: 503,
                                            retry_after: None,
                                            code: None,
                                        }))
                                    } else {
                                        Err(anyhow!("synthetic repeated upload error"))
                                    }
                                });
                                assert!(posts > 0);
                                assert!(
                                    status.is_err()
                                        || matches!(status, Ok(ResumableUploadResult::Shed { .. }))
                                );
                                eprintln!(
                                    "repeated={repeated} bytes={bytes} modes={:?}",
                                    again.modes
                                );
                                owed = checkpoint(&again, &mut progress, session.path(), cause);
                            }
                        }
                        if restart {
                            owed = ScanIndex::load(session.path()).unwrap();
                        }
                        crate::snapshots::state_v2::release_collection_page_limit_for_test(&owed);
                        let (retry, consumed) =
                            fixture::observe_consumed(|| native_page(source, &c, owed, 100, true));
                        assert_eq!(
                            retry.scan.scanned_file_count, 3,
                            "two owed files plus unread sibling"
                        );
                        let mut route = accept(source, &retry);
                        route.mode = if restart { Mode::Restart } else { Mode::Ram };
                        route.io.consumed = consumed;
                        money_oracle::assert_equivalent(&cold, &route);
                        for entity in &SESSIONS {
                            money_oracle::assert_no_smaller_reemit(
                                entity, &cold, &route, &cold, false,
                            );
                        }
                        eprintln!("unkept {source:?} updated={updated} cause={cause:?} restart={restart}: bytes={consumed} modes={:?}", retry.modes);
                        let settled = commit_native(source, &session, retry);
                        let opens = crate::snapshots::all_transcript_opens_for_test();
                        let ((quiet, quiet_bytes), samples) =
                            crate::transcript_acquisition::capture_sample_reads(|| {
                                fixture::observe_consumed(|| {
                                    native_page(source, &c, settled, 100, true)
                                })
                            });
                        assert!(quiet.scan.snapshots.is_empty());
                        assert_eq!(quiet.modes.0, 0);
                        assert_eq!(quiet_bytes, 0, "settled restart consumes no transcript");
                        if source == SOURCE {
                            assert_eq!(
                                crate::snapshots::all_transcript_opens_for_test() - opens,
                                paths.len(),
                                "clean follow-up identity-opens each file once, reads none"
                            );
                            assert!(samples.is_empty());
                            let mut control = accept(source, &quiet);
                            control.mode = Mode::Restart;
                            control.io = fixture::IoBytes {
                                consumed: quiet_bytes,
                                cheap_checks: Some(0),
                                anchor_reads: Some(0),
                                other_reads: Some(0),
                                ..Default::default()
                            };
                            money_oracle::assert_quiet_restart_zero_bytes(&control);
                        }
                    }
                }
            }
        }
    });
}

/// [regress] At page limit 1 a failed, non-audit, re-queued key joins the
/// back of the census queue: the other pending key is read first, then it.
#[test]
#[serial]
fn unkept_non_audit_key_rotates_at_page_limit_one() {
    with_e2(|| {
        let (c, paths) = native_corpus_of(SOURCE, &SESSIONS[..2]);
        let (session, prior) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let selected = |page: &Page| {
            page.scan
                .snapshots
                .iter()
                .map(|item| {
                    let slot = SESSIONS
                        .iter()
                        .position(|session| *session == item.source_session_id)
                        .unwrap();
                    paths[slot].to_str().unwrap().to_string()
                })
                .collect::<Vec<_>>()
        };
        let first = native_page(SOURCE, &c, prior, 1, true);
        assert_eq!(first.scan.scanned_file_count, 1);
        assert!(!first.scan.census_complete, "retained traversal");
        let [failed] = <[String; 1]>::try_from(selected(&first)).unwrap();
        let other = paths
            .iter()
            .map(|path| path.to_str().unwrap().to_string())
            .find(|key| *key != failed)
            .unwrap();
        let mut progress = progress(SOURCE);
        let (status, _) = send(SOURCE, &first, &mut progress, |_| {
            Err(anyhow!("synthetic upload error"))
        });
        assert!(status.is_err());
        let mut owed = checkpoint(
            &first,
            &mut progress,
            session.path(),
            Some(crate::snapshots::UnsettledUploadCause::UploadError),
        );
        assert_eq!(
            crate::snapshots::e2_pipeline_scan_fixture::pending_keys_for_test(&owed),
            BTreeSet::from([failed.clone(), other.clone()]),
            "the failed key is re-queued beside the other pending key"
        );
        let mut order = Vec::new();
        for remaining in [BTreeSet::from([failed.clone()]), BTreeSet::new()] {
            let page = native_page(SOURCE, &c, owed, 1, true);
            let [key] = <[String; 1]>::try_from(selected(&page)).unwrap();
            order.push(key);
            owed = commit_native(SOURCE, &session, page);
            if !remaining.is_empty() {
                assert_eq!(
                    crate::snapshots::e2_pipeline_scan_fixture::pending_keys_for_test(&owed),
                    remaining
                );
            }
        }
        assert_eq!(
            order,
            [other, failed],
            "the other key is selected first; the failed key comes back after it"
        );
    });
}

/// [money] A receiver-stored body with a lost ACK is an idempotent replacement;
/// growth before retry follows ordinary update rules and preserves accepted buckets.
#[test]
fn lost_ack_retry_preserves_receiver_money_and_account_switches() {
    const GAP: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    with_e2(|| {
        for grows in [false, true] {
            let (mut c, path) = placement_corpus("unkept-lost-ack");
            // A separate listed root carries the evidence-gap control: one
            // valid tag, then a present but invalid login. ROOT stays on e2.
            crate::snapshots::write_claude_reemission_list_for_test(&c.support, &[GAP]);
            // Independent pending roots keep the walk alive after root + agent.
            c.root(COPY, &line(COPY, "sibling", AT, 9));
            c.root(
                GAP,
                &(line(GAP, "g1", AT, 10) + &line(GAP, "g2", "2026-08-02T07:01:00Z", 12)),
            );
            c.evidence_for(
                GAP,
                &[
                    api_login(GAP, "g1", 10, '4', Some('5')),
                    super::super::state_v2_money_tests::tagged_api_for(GAP, "g2", 12, None),
                ],
                &[trace_for(GAP, "g1", ""), trace_for(GAP, "g2", "")],
            );
            let (session, prior) = StateV2ColdSession::publish(
                Source::Claude,
                &ScanIndex::default(),
                &c.base.join("state"),
            );
            let scanner = E2ScanFixture::capturing_identity();
            let mut first = c.raw(&scanner, prior, 1, true, std::slice::from_ref(&path));
            first.enrich(&c);
            assert!(first.finish().held_fingerprints.is_empty());
            assert!(!first.scan.census_complete);
            let mut destination = BTreeMap::new();
            let mut receiver = progress(SOURCE);
            let mut sender = progress(SOURCE);
            let (status, _) = send(SOURCE, &first, &mut sender, |items| {
                for item in items {
                    destination.insert(item.source_session_id.clone(), item.clone());
                }
                // The receiver records the stored identity shares; this exact
                // response is lost before the sender can validate it.
                let (status, _, _) = upload(items, &mut receiver, ack);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                Err(anyhow!("synthetic lost ACK"))
            });
            assert!(status.is_err());
            assert!(sender.accepted_fingerprints.is_empty());
            let receiver_before = first
                .scan
                .snapshots
                .iter()
                .map(|item| {
                    (
                        item.source_session_id.clone(),
                        serde_json::to_value(
                            receiver
                                .accepted_identity_buckets
                                .get(&item.source_session_id),
                        )
                        .unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut owed = checkpoint(
                &first,
                &mut sender,
                session.path(),
                Some(crate::snapshots::UnsettledUploadCause::UploadError),
            );
            if grows {
                append(
                    &path,
                    &line(ROOT, "after-switch", "2026-08-02T07:04:00Z", 6),
                );
                c.evidence(
                    &[
                        api_login(ROOT, "a", 10, '1', Some('7')),
                        api_login(ROOT, "b", 20, '2', Some('8')),
                        api_login(ROOT, "agent", 5, '2', Some('8')),
                        api_login(ROOT, "side", 4, '2', Some('8')),
                        api_login(ROOT, "after-switch", 6, '3', Some('9')),
                    ],
                    &[
                        trace("a", ""),
                        trace("b", ""),
                        trace("agent", "agent-000"),
                        trace("side", ""),
                        trace("after-switch", ""),
                    ],
                );
            }
            owed = ScanIndex::load(session.path())
                .inspect(|loaded| {
                    assert_eq!(loaded.generation, owed.generation);
                })
                .unwrap();
            crate::snapshots::state_v2::release_collection_page_limit_for_test(&owed);
            let mut retry = page(&c, owed, 100, true);
            assert!(retry.finish().held_fingerprints.is_empty());
            let cold_page = page(&c, ScanIndex::default(), 100, false);
            let cold = result(&cold_page, Mode::ColdFull);
            assert!(
                accounts(&cold).len() >= 2,
                "switch and independent accounts"
            );
            assert!(
                cold.snapshots
                    .values()
                    .any(|body| body["request_identity_refusals"].as_u64().unwrap_or(0) > 0),
                "evidence gap"
            );
            assert!(
                cold.snapshots
                    .values()
                    .any(|body| body["request_count"].as_u64().unwrap_or(0) >= 4),
                "native side call"
            );
            let (status, route) = send(SOURCE, &retry, &mut sender, |items| {
                for item in items {
                    if !grows {
                        if let Some(stored) = destination.get(&item.source_session_id) {
                            assert_eq!(
                                canonical(stored),
                                canonical(item),
                                "stable reconstructed body"
                            );
                        }
                    }
                    destination.insert(item.source_session_id.clone(), item.clone());
                }
                let (status, _, _) = upload(items, &mut receiver, ack);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                ack(items)
            });
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            money_oracle::assert_equivalent(&cold, &route);
            for entity in cold.snapshots.keys() {
                let actual =
                    serde_json::to_value(receiver.accepted_identity_buckets.get(entity)).unwrap();
                let expected =
                    serde_json::to_value(sender.accepted_identity_buckets.get(entity)).unwrap();
                for field in ["shares", "proved", "missing", "incomplete", "key_epoch"] {
                    assert_eq!(actual[field], expected[field], "receiver identity/{field}");
                    if !grows {
                        if let Some(before) = receiver_before.get(entity) {
                            assert_eq!(
                                actual[field], before[field],
                                "stable accepted prefix/{field}"
                            );
                        }
                    }
                }
            }
            for (entity, body) in &cold.snapshots {
                let stored = destination
                    .get(entity)
                    .expect("receiver stored every entity");
                assert_eq!(
                    stored.request_count,
                    body["request_count"].as_u64().unwrap()
                );
                assert_eq!(
                    serde_json::to_value(&stored.model_usage).unwrap(),
                    body["model_usage"]
                );
                assert_eq!(
                    serde_json::to_value(&stored.usage_buckets).unwrap(),
                    body["usage_buckets"]
                );
            }
        }
    });
}

/// [regress] A Claude append selected only by a watcher hint is observed at
/// candidate stat and is requeued after failure without another directory walk.
#[test]
fn watcher_only_append_requeues_after_a_partial_checkpoint() {
    with_e2(|| {
        let (mut c, path) = placement_corpus("unkept-watcher-only");
        let pending = SESSIONS[..2]
            .iter()
            .map(|id| c.root(id, &line(id, "pending", AT, 1)))
            .collect::<Vec<_>>();
        let (session, prior) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let prior = commit(&session, page(&c, prior, 100, true));
        let mut retained = prior.clone();
        crate::snapshots::e2_pipeline_scan_fixture::retain_indexed_walk_with_pending_for_test(
            &mut retained,
            SOURCE,
            std::slice::from_ref(&c.root),
            "2026-08-02T08:00:00Z",
            183,
            &pending,
        );
        append(&path, &line(ROOT, "hint-append", "2026-08-02T07:04:00Z", 6));
        let mut first = hinted(&c, retained, 2, true, std::slice::from_ref(&path));
        assert!(first.finish().held_fingerprints.is_empty());
        assert_eq!(first.scan.scanned_file_count, 1);
        assert!(!first.scan.census_complete);
        let mut progress = progress(SOURCE);
        let owed = checkpoint(
            &first,
            &mut progress,
            session.path(),
            Some(crate::snapshots::UnsettledUploadCause::Shed),
        );
        crate::snapshots::state_v2::release_collection_page_limit_for_test(&owed);
        let mut retry = page(&c, owed, 100, true);
        assert!(retry.finish().held_fingerprints.is_empty());
        assert!(retry
            .scan
            .snapshots
            .iter()
            .any(|item| item.source_session_id == ROOT));
        let first_route = accept(SOURCE, &first);
        let retry_route = accept(SOURCE, &retry);
        money_oracle::assert_equivalent(&first_route, &retry_route);
    });
}

/// [money] Only exact durable stored-body ACKs settle a file's full incidence.
/// Invalid/partial responses, not-stored custody and a mixed file retain the
/// accepted prefix while the ordinary retry produces cold Full money; a
/// refused ref's debt is its quarantine custody: when due, its entity is
/// re-read and re-sent with the current body, settling only on its own ACK.
#[test]
fn ack_failure_boundaries_preserve_file_debt_and_accepted_placement() {
    with_e2(|| {
        for fault in [
            "durable_ack",
            "malformed_ack",
            "partial_ack",
            "not_stored",
            "mixed_file",
        ] {
            let (mut c, root) = placement_corpus("unkept-ack-boundaries");
            c.root(COPY, &line(COPY, "sibling", AT, 9));
            let sibling = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
            c.root(sibling, &line(sibling, "second-sibling", AT, 9));
            let agent = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
            let (session, prior) = StateV2ColdSession::publish(
                Source::Claude,
                &ScanIndex::default(),
                &c.base.join("state"),
            );
            let mut initial = page(&c, prior, 100, true);
            let mut prior_body = result(&initial, Mode::ColdFull);
            accepted(&mut prior_body, &initial.scan.snapshots);
            let mut destination = initial
                .scan
                .snapshots
                .iter()
                .cloned()
                .map(|item| (item.source_session_id.clone(), item))
                .collect::<BTreeMap<_, _>>();
            initial.finish();
            let (prior, mut sender) = commit_native_with_progress(SOURCE, &session, initial);
            append(
                &root,
                &line(ROOT, "boundary-root", "2026-08-02T07:04:00Z", 6),
            );
            append(
                &agent,
                &line(ROOT, "boundary-agent", "2026-08-02T07:04:00Z", 3),
            );
            let scanner = E2ScanFixture::capturing_identity();
            let mut current = c.raw(&scanner, prior, 3, true, &[root.clone(), agent.clone()]);
            current.enrich_with(&c, Some(&mut sender.accepted_identity_buckets));
            assert!(current.finish().held_fingerprints.is_empty());
            assert_eq!(current.scan.snapshots.len(), 2);
            assert!(!current.scan.census_complete);
            let all = current
                .scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect::<BTreeSet<_>>();
            let mut faulted: Option<String> = None;
            let sent_at = current_unix_seconds();
            // The shared ACK fixture's mixed-incidence seam: both real native
            // entity bodies belong to ONE file's checkpoint, so one ACK cannot
            // publish that file's revision.
            if fault == "mixed_file" {
                let mut wire = serde_json::to_value(&current.index).unwrap();
                wire["file_snapshot_fingerprints"][root.to_str().unwrap()] = json!(all);
                let altered: ScanIndex = serde_json::from_value(wire).unwrap();
                current.index.file_snapshot_fingerprints = altered.file_snapshot_fingerprints;
                let item = &current.scan.snapshots[0];
                assert_eq!(
                    upload(std::slice::from_ref(item), &mut sender, ack)
                        .0
                        .unwrap(),
                    ResumableUploadResult::Completed
                );
                assert!(sender.contains_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item)
                ));
                destination.insert(item.source_session_id.clone(), item.clone());
            } else {
                let (status, _) = send(SOURCE, &current, &mut sender, |items| {
                    let mut response = ack(items)?;
                    match fault {
                        "malformed_ack" => {
                            // One ref echoes another body witness, once; the
                            // re-sent siblings get their own exact ACK.
                            if faulted.is_none() {
                                let entity = &mut response.accepted_entities[0];
                                faulted = Some(entity.snapshot_fingerprint.clone());
                                entity.body_witness_digest = Some("0".repeat(64));
                            }
                            for item in items {
                                if faulted.as_ref() != Some(&item.snapshot_fingerprint) {
                                    destination
                                        .insert(item.source_session_id.clone(), item.clone());
                                }
                            }
                        }
                        "partial_ack" => {
                            response.accepted_entities.pop();
                            response.accepted -= 1;
                        }
                        "not_stored" => {
                            response.unchanged_entities =
                                std::mem::take(&mut response.accepted_entities);
                            for entity in &mut response.unchanged_entities {
                                entity.unchanged_basis = Some("usage_identical".into());
                            }
                        }
                        _ => {
                            for item in items {
                                destination.insert(item.source_session_id.clone(), item.clone());
                            }
                        }
                    }
                    Ok(response)
                });
                if fault == "partial_ack" {
                    assert!(status.is_err());
                } else {
                    assert!(status.is_ok());
                }
            }
            let current_credit = all.intersection(&sender.accepted_fingerprints).count();
            assert_eq!(
                current_credit,
                match fault {
                    "durable_ack" => 2,
                    "mixed_file" | "malformed_ack" => 1,
                    _ => 0,
                }
            );
            if fault == "malformed_ack" {
                // A named body-witness refusal (neither shed nor a validation
                // reject): the ref is held RetryPending on the bounded refusal
                // clock and gets zero credit; siblings settle on their own ACK.
                let faulted = faulted.as_deref().expect("one ref refused");
                let item = current
                    .scan
                    .snapshots
                    .iter()
                    .find(|item| item.snapshot_fingerprint == faulted)
                    .unwrap();
                let record = &sender.quarantined_fingerprints[faulted];
                assert_eq!(
                    record.disposition,
                    SnapshotQuarantineDisposition::RetryPending
                );
                assert_eq!(
                    record.upload_body_witness.as_deref(),
                    Some(snapshot_upload_body_witness(item).as_str())
                );
                let base = SNAPSHOT_QUARANTINE_RETRY_SECONDS;
                assert!(
                    (jittered_retry_after(faulted, sent_at, base)
                        ..=jittered_retry_after(faulted, current_unix_seconds(), base))
                        .contains(&record.retry_after_unix_seconds),
                    "body_witness_refused retry clock, not an identity deferral"
                );
                assert!(!sender.accepted_fingerprints.contains(faulted));
                assert!(!sender.accepted_body_witnesses.contains_key(faulted));
                for sibling in current
                    .scan
                    .snapshots
                    .iter()
                    .filter(|item| item.snapshot_fingerprint != faulted)
                {
                    assert!(sender.contains_body(
                        &sibling.snapshot_fingerprint,
                        &snapshot_upload_body_witness(sibling)
                    ));
                }
            }
            let owed = checkpoint(
                &current,
                &mut sender,
                session.path(),
                Some(crate::snapshots::UnsettledUploadCause::UploadError),
            );
            let mut loaded = ScanIndex::load(session.path()).unwrap();
            assert_eq!(loaded.generation, owed.generation);
            if fault == "mixed_file" {
                assert_ne!(
                    loaded.files[root.to_str().unwrap()].source_file_fingerprint,
                    current.index.files[root.to_str().unwrap()].source_file_fingerprint,
                    "one unaccepted sibling prevents file settlement"
                );
            }
            let mut reoffer = None;
            if let Some(faulted) = faulted.as_deref() {
                // The refused ref's debt is its exact-body quarantine custody,
                // not the file fingerprint: the RetryPending record and its
                // witness survive the checkpoint and a durable reload.
                let item = current
                    .scan
                    .snapshots
                    .iter()
                    .find(|item| item.snapshot_fingerprint == faulted)
                    .unwrap();
                let body = snapshot_upload_body_witness(item);
                let held = &sender.quarantined_fingerprints[faulted];
                for index in [&owed, &loaded] {
                    let record = &index.quarantined_snapshot_fingerprints[faulted];
                    assert_eq!(
                        record.disposition,
                        SnapshotQuarantineDisposition::RetryPending
                    );
                    assert_eq!(record.upload_body_witness.as_deref(), Some(body.as_str()));
                    assert!(record.witness == held.witness, "same quarantine witness");
                }
                // Release the custody: the due retry re-reads the file and
                // re-sends this entity's current body.
                for record in [
                    loaded
                        .quarantined_snapshot_fingerprints
                        .get_mut(faulted)
                        .unwrap(),
                    sender.quarantined_fingerprints.get_mut(faulted).unwrap(),
                ] {
                    record.retry_after_unix_seconds = 0;
                }
                // That retry comes hours later, so the walk's metadata
                // re-listing is due again: move only the listing clocks.
                crate::snapshots::e2_pipeline_scan_fixture::age_listing_for_test(&mut loaded);
                assert!(
                    sender.prepare_quarantine_retries(&loaded.quarantined_snapshot_fingerprints)
                );
                // Released custody is not credit: no settlement before its ACK.
                assert!(!sender.accepted_fingerprints.contains(faulted));
                assert!(!sender.accepted_body_witnesses.contains_key(faulted));
                reoffer = Some((faulted.to_string(), body, item.source_session_id.clone()));
            }
            if fault == "not_stored" {
                // Receiver head dominance is custody, never stored-body credit.
                // Existing refusal retry owns its next offer; this helper adds no release.
                let mut held = RouteResult::emitted(Mode::Restart, SOURCE, vec![], &[]);
                held.accepted = prior_body.accepted.clone();
                for entity in current
                    .scan
                    .snapshots
                    .iter()
                    .map(|item| &item.source_session_id)
                {
                    let mut cold = prior_body.clone();
                    cold.snapshots.retain(|id, _| id == entity);
                    let mut prior = prior_body.clone();
                    prior.snapshots.retain(|id, _| id == entity);
                    for route in [&mut cold, &mut prior] {
                        for envelope in route.normalized.as_array_mut().unwrap() {
                            envelope["snapshots"]
                                .as_array_mut()
                                .unwrap()
                                .retain(|item| item["source_session_id"] == *entity);
                        }
                        route.normalized.as_array_mut().unwrap().retain(|envelope| {
                            !envelope["snapshots"].as_array().unwrap().is_empty()
                        });
                    }
                    // The held comparison preserves the exact accepted body/witness.
                    money_oracle::assert_held(entity, &prior, &held, &cold);
                }
                continue;
            }
            crate::snapshots::state_v2::release_collection_page_limit_for_test(&loaded);
            let mut retry = if reoffer.is_some() {
                // Re-read with accepted-share hints, as the sync loop does.
                // The sibling's ACK changed them, so the entity's current body
                // (and fingerprint) can differ from the refused bytes.
                let mut retry = c.raw(
                    &E2ScanFixture::capturing_identity(),
                    loaded,
                    100,
                    true,
                    &[root.clone(), agent.clone()],
                );
                retry.enrich_with(&c, Some(&mut sender.accepted_identity_buckets));
                retry
            } else {
                page(&c, loaded, 100, true)
            };
            assert!(retry.finish().held_fingerprints.is_empty());
            let already_acked = sender.accepted_fingerprints.clone();
            let mut physical_posts = 0;
            let mut offered = Vec::new();
            let (status, _) = send(SOURCE, &retry, &mut sender, |items| {
                physical_posts += items.len();
                offered.extend(items.iter().map(|item| {
                    (
                        item.source_session_id.clone(),
                        item.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(item),
                    )
                }));
                if fault == "mixed_file" {
                    for item in items {
                        assert!(
                            !already_acked.contains(&item.snapshot_fingerprint),
                            "stored sibling filtered before POST"
                        );
                    }
                }
                for item in items {
                    destination.insert(item.source_session_id.clone(), item.clone());
                }
                ack(items)
            });
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let mut retried = None;
            if let Some((faulted, body, entity)) = &reoffer {
                let short = |hash: &str| hash.chars().take(8).collect::<String>();
                let triples = offered
                    .iter()
                    .map(|(id, fp, witness)| {
                        (SessionHash::of(id).to_string(), short(fp), short(witness))
                    })
                    .collect::<Vec<_>>();
                eprintln!(
                    "retry offered (session, fp, witness): {triples:?}; refused ({}, {}, {})",
                    SessionHash::of(entity),
                    short(faulted),
                    short(body)
                );
                // (i) The due retry's POST carries an item for the SAME entity.
                let same = offered
                    .iter()
                    .filter(|(id, _, _)| id == entity)
                    .collect::<Vec<_>>();
                assert!(
                    !same.is_empty(),
                    "the due retry's POST carries the refused entity"
                );
                assert!(same.iter().all(|offer| *offer == same[0]));
                let (_, fp, witness) = (*same[0]).clone();
                // (iii) It settles only on its own exact ACK ...
                assert_eq!(
                    sender.accepted_body_witnesses.get(&fp),
                    Some(&witness),
                    "the refused entity settles on its own exact ACK"
                );
                assert!(!sender.quarantined_fingerprints.contains_key(&fp));
                // (iv) ... and the refused fingerprint never gets credit,
                // unless these same bytes were re-sent and exactly ACKed.
                if fp != *faulted {
                    assert!(!sender.accepted_fingerprints.contains(faulted));
                    assert!(!sender.accepted_body_witnesses.contains_key(faulted));
                } else {
                    assert_eq!(&witness, body, "same fingerprint, same body");
                }
                // (iii) The refused record is cleared or superseded in the
                // next durable checkpoint: no RetryPending for this entity.
                let mut after = sender.clone();
                checkpoint(&retry, &mut after, session.path(), None);
                let settled = ScanIndex::load(session.path()).unwrap();
                for key in [faulted, &fp] {
                    assert!(
                        !matches!(
                            settled.quarantined_snapshot_fingerprints.get(key),
                            Some(record) if record.disposition
                                == SnapshotQuarantineDisposition::RetryPending
                        ),
                        "no RetryPending left for the refused entity"
                    );
                }
                retried = Some((entity.clone(), fp, witness));
            }
            if fault == "durable_ack" {
                assert_eq!(
                    physical_posts, 0,
                    "durable ACK before index save is not sent twice"
                );
            }
            let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
            // Replacements applied at the receiver, assembled from the actual
            // accepted POSTs above, rather than re-scanning an expected body.
            if let Some((entity, fp, witness)) = &retried {
                // (ii) The cold-Full comparison below covers the retried item
                // itself: it is this entity's receiver body, in money and
                // placement.
                let item = &destination[entity];
                assert_eq!(&item.snapshot_fingerprint, fp);
                assert_eq!(&snapshot_upload_body_witness(item), witness);
            }
            let mut final_page = retry;
            final_page.scan.snapshots = destination.into_values().collect();
            for item in &final_page.scan.snapshots {
                assert!(sender.contains_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item)
                ));
            }
            let final_route = result(&final_page, Mode::Restart);
            if fault == "malformed_ack" {
                money_oracle::assert_placement_equivalent(&cold, &final_route);
                let mut differences = Vec::new();
                money_oracle::entity_differences(&cold, &final_route, &mut differences);
                assert!(differences.is_empty(), "{}", differences.join("\n"));

                // The due refused-body retry currently omits these opening
                // and context fields. Pin that separate gap to this entity:
                // every other field and every sibling must still match.
                let (entity, _, _) = retried.as_ref().expect("refused entity retried");
                assert_eq!(entity, ROOT);
                let mut expected = cold.snapshots.clone();
                let body = expected.get_mut(entity).unwrap();
                let actual = &final_route.snapshots[entity];
                assert!(body.get("context_posture_withheld").is_none());
                assert_eq!(actual["context_posture_withheld"], "unknown_birth");
                body.as_object_mut().unwrap().insert(
                    "context_posture_withheld".into(),
                    serde_json::json!("unknown_birth"),
                );
                for field in [
                    "cache_observations",
                    "compaction_count",
                    "first_own_request_at",
                    "first_turn_context_tokens",
                    "last_turn_context_tokens",
                    "peak_context_fill_tokens",
                ] {
                    assert!(body.as_object_mut().unwrap().remove(field).is_some());
                    assert!(actual.get(field).is_none(), "retry omits {field}");
                }
                for field in [
                    "first_request_cache_read_tokens",
                    "first_request_cache_write_1h_tokens",
                    "first_request_cache_write_5m_tokens",
                    "first_request_uncached_input_tokens",
                    "opening_file_overflow",
                    "opening_output_tokens",
                    "opening_request_count",
                    "opening_tool_calls",
                    "opening_truncated_outputs",
                    "request_2_context_tokens",
                    "request_3_context_tokens",
                ] {
                    assert!(body["session_start"]
                        .as_object_mut()
                        .unwrap()
                        .remove(field)
                        .is_some());
                    assert!(actual["session_start"].get(field).is_none());
                }
                // Only the fingerprints derived from the omitted context
                // differ; emitted() already validates the semantic envelope.
                for path in [
                    "/snapshot_fingerprint",
                    "/semantic_envelope/component_hashes/context_posture",
                    "/semantic_envelope/content_hash",
                    "/semantic_envelope/revision_hash",
                    "/semantic_envelope/revision_v2_hash",
                ] {
                    let expected = body.pointer_mut(path).unwrap();
                    let actual = actual.pointer(path).unwrap();
                    assert_ne!(&*expected, actual, "omitted context changes {path}");
                    *expected = actual.clone();
                }
                assert_eq!(expected, final_route.snapshots, "only the pinned omissions");
            } else {
                money_oracle::assert_equivalent(&cold, &final_route);
            }
        }
    });
}
