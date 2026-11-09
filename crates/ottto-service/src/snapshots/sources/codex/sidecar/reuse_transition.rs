// Extends the existing native archive/transition fixture and stored-body ACK driver.
pub(super) fn seed_sidecars(c: &Corpus) -> rusqlite::Connection {
    let home = c.sessions.parent().unwrap();
    let source = c.scratch.join("sidecar-writer.sqlite");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE threads (id TEXT, title TEXT, tokens_used INTEGER, archived INTEGER, created_at INTEGER, updated_at INTEGER, model TEXT, rollout_path TEXT, thread_source TEXT, first_user_message TEXT); CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT)").unwrap();
    for id in [MAIN, OTHER, SIDE, GAP] {
        db.execute("INSERT INTO threads VALUES (?1, 'Fixture title', 1, 0, 1791363600, 1791363600, 'gpt-5.2', ?2, 'user', NULL)", rusqlite::params![id, c.path(id).to_str().unwrap()]).unwrap();
    }
    crate::snapshots::codex_sqlite_read::tests::copy_database(
        &source,
        &home.join("state_5.sqlite"),
        true,
    );
    db
}

/// [money] Cached sidecars feed the native Tail, restore, restart-between-pages,
/// binary-witness upgrade, real post-ACK placement and quiet-restart routes.
#[test]
fn codex_sidecar_reuse_transition() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    for (id, account) in [
        (MAIN, Some("a")),
        (OTHER, Some("b")),
        (SIDE, Some("b")),
        (GAP, None),
    ] {
        c.write(id, account);
    }
    let _db = seed_sidecars(&c);
    let log_source = c.scratch.join("logs-writer.sqlite");
    let logs = rusqlite::Connection::open(&log_source).unwrap();
    logs.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, feedback_log_body TEXT)").unwrap();
    let now = unix_seconds(SystemTime::now()).unwrap() as i64;
    logs.execute("INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)", rusqlite::params![now, "turn{turn.id=priority-control}: websocket request: {\"type\":\"response.create\",\"service_tier\":\"priority\"}"]).unwrap();
    crate::snapshots::codex_sqlite_read::tests::copy_database(
        &log_source,
        &c.sessions.parent().unwrap().join("logs_2.sqlite"),
        true,
    );
    assert!(
        CodexTurnTraceMap::load_from_roots(&c.roots(), BACKFILL_WINDOW_DAYS)
            .is_priority_turn("priority-control")
    );
    let hash = |kind: &str, account: &str| {
        ottto_core::billing_identity_hash(
            "openai",
            kind,
            &format!(
                "synthetic-{}-{account}",
                if kind == "account" {
                    "user"
                } else {
                    "workspace"
                }
            ),
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
    let run =
        |index, cache| page_observed_with_limit(&c.roots(), index, cache, 100, &slots, |_| {});
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (working, first, ..) = run(prior.clone(), cache.clone());
    let (mut prior, _) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
    // Two independent account streams, native spawned side work, an evidence
    // gap, and a mid-session contradicting creator all pass this loader.
    for id in [MAIN, OTHER, SIDE, GAP] {
        append(&c.path(id), &turn(3));
    }
    append(&c.path(MAIN), &header(MAIN, Some("switched")));
    e2_pipeline_scan_fixture::age_listing_for_test(&mut prior);
    let (cold_index, cold_scan, ..) = run(ScanIndex::default(), Arc::default());
    let cold =
        crate::snapshot_sync::codex_transition_acked_route(&cold_index, &cold_scan, Mode::ColdFull);
    assert_ne!(
        cold.snapshots[MAIN]["session_account_evidence"],
        cold.snapshots[OTHER]["session_account_evidence"]
    );
    assert!(cold.snapshots[GAP]["session_account_evidence"].is_null());
    assert!(
        cold_scan
            .snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .any(|row| row.account_identifier_hash.is_some()),
        "tagged positive control"
    );
    assert!(
        cold.accepted_identity_buckets
            .as_ref()
            .unwrap()
            .get(OTHER)
            .is_some_and(|ledger| !ledger.is_null()),
        "actual stored-body ACK ledger"
    );
    let mut committed = None;
    for (label, owner) in [
        ("tail", cache.clone()),
        ("restore", Arc::default()),
        ("restart", Arc::default()),
        ("upgrade", Arc::default()),
    ] {
        let mut restored = ScanIndex::load(session.path()).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut restored);
        if label == "upgrade" {
            restored
                .active_quarantine_witness
                .as_mut()
                .unwrap()
                .collector_version = "0.1.239".into();
        }
        let (working, scan, ..) = run(restored, owner.clone());
        let d = scan.local_codex_diagnostics.as_ref().unwrap();
        assert_eq!(
            d.state_titles.reused_roots,
            u32::from(label == "tail"),
            "{label}"
        );
        let actual = crate::snapshot_sync::codex_transition_acked_route(
            &working,
            &scan,
            if label == "tail" {
                Mode::Ram
            } else {
                Mode::DiskRestore
            },
        );
        money_oracle::assert_equivalent(&cold, &actual);
        money_oracle::assert_placement_equivalent(&cold, &actual);
        money_oracle::assert_no_smaller_reemit(MAIN, &cold, &actual, &cold, false);
        assert_eq!(cold.batches, actual.batches, "{label}: byte-identical rows");
        // A newly started process fully loads first, then reuses on its next
        // pass while replaying exactly the same owed revision.
        let (_, second, ..) = run(prior.clone(), owner);
        assert_eq!(
            second
                .local_codex_diagnostics
                .as_ref()
                .unwrap()
                .state_titles
                .reused_roots,
            1
        );
        let second =
            crate::snapshot_sync::codex_transition_acked_route(&working, &second, Mode::Ram);
        money_oracle::assert_equivalent(&cold, &second);
        if label == "tail" {
            committed = Some((working, scan));
        }
        println!("CODEX_SIDECAR_REUSE_ORACLE {label} ok");
    }
    let (working, scan) = committed.unwrap();
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &prior, "accept");
    let accepted = route(&index, &scan, posts);
    let (index, _) = assert_quiet(&c, index, &accepted);
    assert_quiet_on(&c, index, &accepted, cache);
    println!("CODEX_SIDECAR_REUSE_ORACLE quiet_restart ok");
}
