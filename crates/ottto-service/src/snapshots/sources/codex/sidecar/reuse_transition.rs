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
/// compatible binary upgrade, real post-ACK placement and quiet-restart routes.
/// A turn an older build priced priority from Codex logs keeps that tier on
/// every route through its tier receipt.
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
    // An older build priced MAIN's opening turn priority from Codex logs. The
    // cold Full below is that build's output; every later route runs after the
    // logs evidence is gone and must equal it through the tier receipt.
    let turn_context = |turn: &str| {
        json!({"type":"turn_context", "timestamp":"2026-10-07T09:30:00Z",
            "payload":{"turn_id": turn, "model":"gpt-5.2"}})
        .to_string()
            + "\n"
    };
    fs::write(
        c.path(MAIN),
        header(MAIN, Some("a")) + &turn_context("priority-control") + &turn(1) + &turn(2),
    )
    .unwrap();
    crate::snapshots::older_build_logs_priority("priority-control");
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
    append(&c.path(MAIN), &turn_context("later-turn"));
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
    assert!(
        cold_scan
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == MAIN)
            .flat_map(|item| &item.model_usage)
            .any(|row| {
                row.selector_sources.get("service_tier").map(String::as_str)
                    == Some("derived_from_logs_2")
            }),
        "priority positive control"
    );
    crate::snapshots::older_build_logs_expired();
    let mut committed = None;
    for (label, owner) in [
        ("tail", cache.clone()),
        ("restore", Arc::default()),
        ("restart", Arc::default()),
        ("upgrade", Arc::default()),
    ] {
        let mut restored = ScanIndex::load(session.path()).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut restored);
        // This unit keeps the persisted format unchanged. The compatible
        // binary-upgrade arm starts a new process owner from the saved index;
        // no native sidecar facts can cross that process boundary.
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

/// [money] Cached sidecars preserve held/no-smaller and independent-owner progress.
#[test]
fn sidecar_reuse_inventory_refusal_isolates_only_proven_dependants() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    let _sidecars = seed_sidecars(&c);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let (working, first, _, _, _) = page(&c, prior.clone(), cache.clone());
    let (mut index, posts) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
    let accepted = route(&index, &first, posts);
    append(&c.path(OTHER), &turn(3));
    let sibling = c.sessions.join(format!("rollout-copy-{MAIN}.jsonl.zst"));
    // A complete first frame proves owner MAIN; corrupt body bytes in a
    // later frame fail only when acquisition advances past that header.
    let good_header = zstd::stream::encode_all(header(MAIN, Some("a")).as_bytes(), 1).unwrap();
    let mut damaged = good_header;
    damaged.extend_from_slice(b"not another zstd frame");
    fs::write(&sibling, damaged).unwrap();
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let before = index.clone();
    let (working, held_scan, _, _, _) = page(&c, index, cache.clone());
    assert_eq!(
        held_scan
            .local_codex_diagnostics
            .as_ref()
            .unwrap()
            .state_titles
            .reused_roots,
        1
    );
    assert!(held_scan
        .snapshots
        .iter()
        .all(|s| s.source_session_id != MAIN));
    assert!(held_scan
        .snapshots
        .iter()
        .any(|s| s.source_session_id == OTHER));
    let (mut index, posts) = working.checkpoint_with_captured_posts(&held_scan, &before, "accept");
    assert_eq!(posts.len(), 1);
    assert_eq!(
        index.files[&local_index_key(&c.path(MAIN))].last_upload_body_witness,
        before.files[&local_index_key(&c.path(MAIN))].last_upload_body_witness
    );
    assert!(!index
        .confirmed_empty_files
        .contains(&local_index_key(&sibling)));
    // The transient failed companion disappears; the original object's
    // ordinary append supplies the next usage. Compressed grouped replay is
    // deliberately unsupported, so recovery uses the existing singleton path.
    fs::remove_file(&sibling).unwrap();
    append(&c.path(MAIN), &turn(3));
    let (_, cold, _, _, _) = page(
        &c,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    assert!(
        cold.snapshots
            .iter()
            .any(|item| item.source_session_id == MAIN),
        "the repaired cold owner must be admitted before testing its recovery"
    );
    let mut cold_b = cold.clone();
    cold_b.snapshots.retain(|s| {
        held_scan
            .snapshots
            .iter()
            .any(|actual| actual.source_session_id == s.source_session_id)
    });
    let captured_b = route(&index, &held_scan, posts);
    money_oracle::assert_equivalent(&emitted(&index, &cold_b), &captured_b);
    // Compare the held owner alone: Codex's extra tier/token evidence is
    // collected per offered set, so test healthy B independently above.
    let mut cold_a = cold.clone();
    cold_a.snapshots.retain(|s| s.source_session_id == MAIN);
    let mut held_a = held_scan.clone();
    held_a.snapshots.clear();
    let mut held = emitted(&index, &held_a);
    held.accepted = accepted.accepted.clone();
    money_oracle::assert_held(MAIN, &accepted, &held, &emitted(&index, &cold_a));
    money_oracle::assert_no_smaller_reemit(MAIN, &accepted, &held, &emitted(&index, &cold_a), true);
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let before = index.clone();
    let (working, recovered, _, _, _) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert_eq!(
        recovered
            .snapshots
            .iter()
            .filter(|s| s.source_session_id == MAIN)
            .count(),
        1
    );
    let (index, posts) = working.checkpoint_with_captured_posts(&recovered, &before, "accept");
    assert_eq!(posts.len(), 1);
    let mut cold_a = cold;
    cold_a.snapshots.retain(|s| {
        recovered
            .snapshots
            .iter()
            .any(|a| a.source_session_id == s.source_session_id)
    });
    money_oracle::assert_equivalent(&emitted(&index, &cold_a), &route(&index, &recovered, posts));
    let (mut index, _) = assert_quiet(&c, index, &accepted);
    // Unknown headers remain a wildcard, including a misleading owner name.
    fs::write(&sibling, b"unknown header").unwrap();
    append(&c.path(OTHER), &turn(4));
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let (_, unknown, _, _, _) = page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert!(
        unknown.snapshots.is_empty(),
        "unknown owner cannot prove another owner unique"
    );
    drop(session);
    println!("CODEX_SIDECAR_REUSE_ORACLE held_no_smaller ok");
}
