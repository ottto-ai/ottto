use crate::snapshots::claude_request_money as money;

fn p2a_scan(root: &Path, support: &Path, index: &mut ScanIndex) -> SourceScanResult {
    index.activate_upload_context("already-admitted-context".into());
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.load_claude_reemission_exclusions(support);
    scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root.to_owned()],
        index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        true,
    )
    .unwrap()
}
fn p2a_support(home: &Path) -> PathBuf {
    let support = home.join("support");
    fs::create_dir_all(support.join("snapshots")).unwrap();
    fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        b"",
    )
    .unwrap();
    money::store::reload_for_test(&support).unwrap();
    support
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_adoption_strict_bytes_floor_and_covering_ack_partial_rollback() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-adoption", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let previous = index.clone();
    // Unlike legacy admission, revision 3 has no first-file byte exception.
    let denied =
        with_body_witness_adoption_byte_budget(1, || p2a_scan(&root, &support, &mut index));
    assert_eq!(denied.scanned_file_count, 0);
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 1));
    index = previous.clone();
    let mut scan = p2a_scan(&root, &support, &mut index);
    assert_eq!(scan.snapshots.len(), 2);
    // Parsing/finalization is not adoption, including a shed, skew or held page.
    let mut unstamped = scan.clone();
    let mut unstamped_index = index.clone();
    finalize_scan_after_policy(
        SnapshotSource::ClaudeCode,
        &mut unstamped,
        &mut unstamped_index,
    );
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 1));
    for item in &mut scan.snapshots {
        assert!(money::emit_for_test(
            item,
            &money::body::ClaudeEntityBody::default()
        ));
    }
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    let first = &scan.snapshots[0];
    let accepted = BTreeSet::from([first.snapshot_fingerprint.clone()]);
    let wrong = BTreeMap::from([(first.snapshot_fingerprint.clone(), "unrelated-body".into())]);
    index.stamp_request_money_acks(&scan.snapshots, &accepted, &wrong);
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 1));
    let covering = BTreeMap::from([(
        first.snapshot_fingerprint.clone(),
        snapshot_upload_body_witness(first),
    )]);
    index.stamp_request_money_acks(&scan.snapshots, &accepted, &covering);
    let mut partial = index.committable_subset(&previous, &accepted, &BTreeMap::new());
    let path = home.join("partial.json");
    partial.save(&path).unwrap();
    let partial = ScanIndex::load(&path).unwrap();
    assert_eq!(
        partial
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision == 3)
            .count(),
        1
    );
    assert_eq!(
        partial
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision == 1)
            .count(),
        1
    );

    // A known activity floor is settled-refused durably without parsing/building.
    let mut floor = previous;
    for activity in floor.snapshot_activity_at.values_mut() {
        *activity = Some("2026-04-30T23:59:59Z".into());
    }
    let skipped = p2a_scan(&root, &support, &mut floor);
    assert_eq!(skipped.scanned_file_count, 0);
    assert!(floor
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 3));
    money::store::reload_for_test(&support).unwrap();
    let floor_count = money::store::with_ledger_for_test(&support, |ledger| {
        ledger
            .census()
            .records_with_prefix(&money::adoption_prefix(&floor))
            .filter(|(_, record)| record.window() == 5)
            .count()
    })
    .unwrap();
    assert_eq!(floor_count, 2);
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_adoption_pause_resume_and_consumed_evidence_stays_local() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-pause", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let scan = p2a_scan(&root, &support, &mut index);
    for state in [1, 2, 3, 6] {
        money::note_adoption_outcomes(&support, &index, &scan.snapshots, |_| state);
        money::store::reload_for_test(&support).unwrap();
        assert!(money::adoption_paused(&support, &index), "state {state}");
        money::note_adoption_outcomes(&support, &index, &scan.snapshots, |_| 4);
        money::store::reload_for_test(&support).unwrap();
        assert!(
            !money::adoption_paused(&support, &index),
            "resolved state {state}"
        );
    }
    money::note_route_pause(&support, &index, true);
    money::store::reload_for_test(&support).unwrap();
    assert!(money::adoption_paused(&support, &index));
    money::note_route_pause(&support, &index, false);
    assert!(!money::adoption_paused(&support, &index));

    let mut literal = scan.snapshots.clone();
    for item in &mut literal {
        assert!(money::emit_for_test(
            item,
            &money::body::ClaudeEntityBody::default()
        ));
    }
    let wire = serde_json::to_vec(&literal).unwrap();
    assert!(money::stage_selection_fingerprints(
        &support, &mut index, &literal
    ));
    let before = serde_json::to_value(&index).unwrap()["claude_money_files"].clone();
    // Equal-count ownership evidence, deliberately absent from every wire field.
    money::store::with_ledger_for_test(&support, |ledger| {
        ledger.insert(
            "watch:trace:synthetic:0000000000000001".into(),
            claude_request_census::ClaudeRequestCensusRecord::money_debt([9; 32], 0),
        );
    })
    .unwrap();
    assert!(money::stage_selection_fingerprints(
        &support, &mut index, &literal
    ));
    assert_ne!(
        before,
        serde_json::to_value(&index).unwrap()["claude_money_files"]
    );
    assert!(!index.claude_money_selection_changed.is_empty());
    assert_eq!(wire, serde_json::to_vec(&literal).unwrap());
    let reoffers = money::scheduled_reoffers(&index, &literal);
    assert!(
        literal
            .iter()
            .all(|item| reoffers.contains(&item.snapshot_fingerprint)),
        "a changed local consumed-evidence witness always withdraws an older equal-wire ACK"
    );

    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_real_scan_union_partial_files_primary_promotion_and_project_refusal() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-union-promotion", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let original = root.join("aaaaaaaa-bbbb-4ccc-8ddd-000000000000.jsonl");
    let copy = root.join("99999999-bbbb-4ccc-8ddd-000000000000.jsonl");
    fs::copy(&original, &copy).unwrap();
    use std::io::Write as _;
    std::fs::OpenOptions::new().append(true).open(&copy).unwrap().write_all(
        b"{\"type\":\"assistant\",\"timestamp\":\"2026-08-23T18:02:00Z\",\"sessionId\":\"aaaaaaaa-bbbb-4ccc-8ddd-000000000000\",\"requestId\":\"union-extra\",\"message\":{\"id\":\"union-extra-m\",\"model\":\"claude-haiku-4-5\",\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\n").unwrap();
    let mut scan = p2a_scan(&root, &support, &mut index);
    assert_eq!(scan.snapshots.len(), 3, "actual physical parsers");
    let held = money::live_page(
        &support,
        &mut scan.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    assert!(held.is_empty(), "complete union must build: {held:?}");
    assert_eq!(scan.snapshots.len(), 2, "one body per logical member");
    let logical = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == "aaaaaaaa-bbbb-4ccc-8ddd-000000000000")
        .unwrap();
    assert_eq!(
        logical.request_count, 2,
        "union includes the secondary's unique response"
    );
    assert_eq!(
        logical.removed_request_count,
        Some(0),
        "same identity copies are never removed units"
    );
    let primary = index
        .files
        .iter()
        .find(|(_, entry)| {
            Some(entry.source_file_fingerprint.as_str())
                == logical.source_file_fingerprint.as_deref()
        })
        .unwrap()
        .0
        .clone();
    let retained_posture = serde_json::to_value(&logical.context_curve).unwrap();
    assert!(money::stage_selection_fingerprints(
        &support,
        &mut index,
        &scan.snapshots
    ));
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    assert_eq!(
        serde_json::to_value(
            &scan
                .snapshots
                .iter()
                .find(|item| item.source_session_id == "aaaaaaaa-bbbb-4ccc-8ddd-000000000000")
                .unwrap()
                .context_curve
        )
        .unwrap(),
        retained_posture
    );
    let accepted = scan
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let witnesses = scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect();
    index.stamp_request_money_acks(&scan.snapshots, &accepted, &witnesses);
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 3));
    assert_eq!(
        index.confirmed_empty_files.len(),
        0,
        "secondary checkpoint never declares authoritative empty"
    );
    let path = home.join("union.json");
    index.save(&path).unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    fs::remove_file(&primary).unwrap();
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 1;
    }
    let mut promoted = p2a_scan(&root, &support, &mut index);
    let held = money::live_page(
        &support,
        &mut promoted.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    assert!(
        held.is_empty(),
        "surviving physical file promotes after a real census: {held:?}"
    );
    assert_eq!(promoted.snapshots.len(), 2);
    assert!(!index.files.contains_key(&primary));
    let survivor = if original.exists() { original } else { copy };
    let foreign = home.join("foreign-project");
    fs::create_dir_all(&foreign).unwrap();
    fs::copy(
        survivor,
        foreign.join("88888888-bbbb-4ccc-8ddd-000000000000.jsonl"),
    )
    .unwrap();
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 1;
    }
    index.activate_effective_upload_body_witness_revision(3);
    index.load_claude_reemission_exclusions(&support);
    let mut foreign_scan = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root, foreign],
        &mut index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        true,
    )
    .unwrap();
    let held = money::live_page(
        &support,
        &mut foreign_scan.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    assert!(
        held.contains("aaaaaaaa-bbbb-4ccc-8ddd-000000000000"),
        "foreign project custody never merges"
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_gate_off_reconciliation_prunes_local_selection_metadata() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-metadata-prune", 1);
    assert_eq!(index.claude_money_files.len(), 2);
    for key in index.files.keys() {
        fs::remove_file(key).unwrap();
    }
    index.activate_effective_upload_body_witness_revision(0);
    scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root],
        &mut index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        true,
    )
    .unwrap();
    assert!(index.files.is_empty());
    assert!(
        index.claude_money_files.is_empty(),
        "gate-off custody must remain a subset of indexed files"
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_known_union_selects_complete_group_before_small_page_boundary() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-union-page", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let original = root.join("aaaaaaaa-bbbb-4ccc-8ddd-000000000000.jsonl");
    fs::copy(
        original,
        root.join("99999999-bbbb-4ccc-8ddd-000000000000.jsonl"),
    )
    .unwrap();
    let mut discovered = p2a_scan(&root, &support, &mut index);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut discovered, &mut index);
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 1;
    }
    index.activate_effective_upload_body_witness_revision(3);
    index.load_claude_reemission_exclusions(&support);
    let mut page = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root],
        &mut index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        2,
        true,
    )
    .unwrap();
    assert_eq!(page.scanned_file_count, 2);
    assert!(
        page.snapshots
            .iter()
            .all(|item| item.source_session_id == "aaaaaaaa-bbbb-4ccc-8ddd-000000000000"),
        "an unrelated member must not split this known union's physical files"
    );
    let held = money::live_page(
        &support,
        &mut page.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        page.census_complete,
        None,
        &mut BTreeMap::new(),
    );
    assert!(held.is_empty(), "bounded group is buildable: {held:?}");
    assert_eq!(page.snapshots.len(), 1);
    assert_eq!(page.snapshots[0].request_count, 1);
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_held_new_alias_discovery_survives_partial_index_rollback() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-union-discovery", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let previous = index.clone();
    let original = root.join("aaaaaaaa-bbbb-4ccc-8ddd-000000000000.jsonl");
    let alias = root.join("00000000-bbbb-4ccc-8ddd-000000000000.jsonl");
    fs::copy(original, &alias).unwrap();
    index.activate_effective_upload_body_witness_revision(3);
    index.load_claude_reemission_exclusions(&support);
    let mut page = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root.clone()],
        &mut index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        1,
        true,
    )
    .unwrap();
    let alias_key = local_index_key(&alias);
    assert_eq!(page.snapshots.len(), 1);
    assert_eq!(
        page.snapshots[0].source_file_fingerprint.as_deref(),
        Some(index.files[&alias_key].source_file_fingerprint.as_str())
    );
    let held = money::live_page(
        &support,
        &mut page.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        false,
        None,
        &mut BTreeMap::new(),
    );
    assert!(held.contains("aaaaaaaa-bbbb-4ccc-8ddd-000000000000"));
    assert!(money::prepare_money_offers(
        &support,
        &index,
        &page.snapshots,
        &held
    ));
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut page, &mut index);
    let mut partial = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(
        !partial.files.contains_key(&alias_key),
        "no committed predecessor or membership placeholder"
    );
    assert!(!partial.claude_money_files.contains_key(&alias_key));
    let path = home.join("held-alias.json");
    partial.save(&path).unwrap();
    let mut restarted = ScanIndex::load(&path).unwrap();
    money::store::reload_for_test(&support).unwrap();
    // Next complete source traversal, using only persisted index and ledger.
    restarted.traversal = None;
    restarted.resume_after_path = None;
    restarted.resume_upper_bound_path = None;
    restarted.resume_census_window_end = None;
    restarted.activate_effective_upload_body_witness_revision(3);
    restarted.load_claude_reemission_exclusions(&support);
    let mut recovered = scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root],
        &mut restarted,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        2,
        true,
    )
    .unwrap();
    assert_eq!(recovered.scanned_file_count, 2);
    assert!(recovered
        .snapshots
        .iter()
        .all(|item| item.source_session_id == "aaaaaaaa-bbbb-4ccc-8ddd-000000000000"));
    let held = money::live_page(
        &support,
        &mut recovered.snapshots,
        &restarted,
        &Default::default(),
        &Default::default(),
        false,
        None,
        &mut BTreeMap::new(),
    );
    assert!(
        held.is_empty(),
        "persisted discovery must recover the complete union: {held:?}"
    );
    assert_eq!(recovered.snapshots.len(), 1);
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_union_resolves_pair_copies_before_request_conflicts_and_keeps_idless_lines() {
    for (name, different_message, idless, expected_requests, expected_removed) in [
        ("progressive", false, false, 1, 0),
        ("conflicting", true, false, 1, 1),
        ("idless", false, true, 4, 0),
    ] {
        let (home, root, mut index) =
            claude_context_backfill_fixture(&format!("p2a-pair-{name}"), 1);
        let support = p2a_support(&home);
        let _live = money::LiveForTest::new(&support);
        let session = "aaaaaaaa-bbbb-4ccc-8ddd-000000000000";
        let original = root.join(format!("{session}.jsonl"));
        let alias = root.join("99999999-bbbb-4ccc-8ddd-000000000000.jsonl");
        if idless {
            let line = serde_json::json!({"type":"assistant", "sessionId":session,
                "timestamp":"2026-08-23T18:20:00Z", "message":{"model":"claude-haiku-4-5",
                "usage":{"input_tokens":3,"output_tokens":1}}})
            .to_string()
                + "\n";
            fs::write(&original, format!("{line}{line}")).unwrap();
            fs::copy(&original, &alias).unwrap();
        } else {
            let mut line: serde_json::Value =
                serde_json::from_slice(&fs::read(&original).unwrap()).unwrap();
            line["message"]["usage"]["input_tokens"] = 30.into();
            if different_message {
                line["message"]["id"] = "different-message".into();
            }
            fs::write(&alias, line.to_string() + "\n").unwrap();
        }
        let mut scan = p2a_scan(&root, &support, &mut index);
        // Creation clocks are per-file provenance, not a cross-account refusal.
        for (position, item) in scan.snapshots.iter_mut().enumerate() {
            item.session_account_evidence = Some(SessionAccountEvidence {
                provider: "claude_code",
                account_identifier_hash: Some("a".repeat(64)),
                provider_workspace_hash: None,
                identity_hash_scheme: "synthetic:v1",
                evidence_source: "synthetic",
                identity_disposition: None,
                source_created_at: Some(format!("2026-08-23T18:00:{position:02}Z")),
            });
        }
        let held = money::live_page(
            &support,
            &mut scan.snapshots,
            &index,
            &Default::default(),
            &Default::default(),
            true,
            None,
            &mut BTreeMap::new(),
        );
        assert!(held.is_empty(), "{name}: {held:?}");
        let body = scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == session)
            .unwrap();
        assert_eq!(body.request_count, expected_requests, "{name}");
        assert_eq!(body.removed_request_count, Some(expected_removed), "{name}");
        if !idless {
            assert_eq!(body.input_tokens, 30, "largest resolved contribution wins");
        }
        assert!(
            body.usage_buckets
                .iter()
                .all(
                    |bucket| bucket.first_activity_at.as_deref() == Some("2026-08-23T18:20:00Z")
                        && bucket.last_activity_at.as_deref() == Some("2026-08-23T18:20:00Z")
                ),
            "bucket activity uses counted events, not its hour boundary"
        );
        let _ = fs::remove_dir_all(home);
    }
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_alias_representative_is_global_and_retained_telemetry_uses_logical_root() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-global-holder", 2);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let a = "aaaaaaaa-bbbb-4ccc-8ddd-000000000000";
    let b = "aaaaaaaa-bbbb-4ccc-8ddd-000000000001";
    let a_path = root.join(format!("{a}.jsonl"));
    let b_path = root.join(format!("{b}.jsonl"));
    let alias = root.join("00000000-bbbb-4ccc-8ddd-000000000000.jsonl");
    let mut shared: serde_json::Value =
        serde_json::from_slice(&fs::read(&b_path).unwrap()).unwrap();
    shared["requestId"] = "shared-union-request".into();
    fs::write(&b_path, shared.to_string() + "\n").unwrap();
    shared["sessionId"] = a.into();
    fs::write(&alias, shared.to_string() + "\n").unwrap();
    let mut scan = p2a_scan(&root, &support, &mut index);
    let a_key = local_index_key(&a_path);
    let b_key = local_index_key(&b_path);
    let alias_key = local_index_key(&alias);
    let keys = index.files.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let rank = if key == a_key {
            1
        } else if key == b_key {
            2
        } else {
            3
        };
        let record = index
            .claude_request_census
            .get(&key)
            .unwrap()
            .clone()
            .with_birth_for_test(Some(claude_request_census::ClaudeRequestBirth {
                unix_seconds: 1_750_000_000 + rank,
                device: 0,
                inode: 0,
            }));
        index.claude_request_census.insert(key, record);
    }
    let held = money::live_page(
        &support,
        &mut scan.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    assert!(held.is_empty(), "{held:?}");
    let a_body = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == a)
        .unwrap();
    let b_body = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == b)
        .unwrap();
    assert_eq!(
        a_body.request_count, 2,
        "A's old primary represents the shared request found only in its new alias"
    );
    assert_eq!(
        b_body.request_count, 0,
        "B must see the same A representative and lose once"
    );
    assert_eq!(b_body.removed_request_count, Some(1));

    index.files.retain(|key, _| key == &alias_key);
    let mut ledger = money::store::ClaudeLedger::new_for_test();
    let header = money::facts::ClaudeFactsHeader {
        session: a.into(),
        ..Default::default()
    };
    let facts = money::facts::encode(&header, std::iter::empty::<&money::facts::ClaudeFact>(), 0)
        .into_boxed_slice();
    let telemetry = claude_request_census::telemetry_key(a);
    ledger.insert(
        telemetry.clone(),
        claude_request_census::ClaudeRequestCensusRecord::telemetry(
            Vec::new(),
            facts,
            claude_request_census::ClaudeTelemetryTailState {
                last_append_unix: 1,
                ..Default::default()
            },
            1,
        ),
    );
    assert_eq!(
        claude_request_ledger::retire_idle_telemetry(&mut ledger, &index, 35 * 86400 + 2),
        0
    );
    assert!(ledger.get(&telemetry).unwrap().retired().is_none());
    let _ = fs::remove_dir_all(home);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn p2a_protected_alias_keeps_ordinary_body_without_new_custody_hold() {
    let (home, root, mut index) = claude_context_backfill_fixture("p2a-protected-alias", 1);
    let support = p2a_support(&home);
    let _live = money::LiveForTest::new(&support);
    let session = "aaaaaaaa-bbbb-4ccc-8ddd-000000000000";
    fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(session.as_bytes())),
    )
    .unwrap();
    fs::copy(
        root.join(format!("{session}.jsonl")),
        root.join("00000000-bbbb-4ccc-8ddd-000000000000.jsonl"),
    )
    .unwrap();
    let mut page = p2a_scan(&root, &support, &mut index);
    assert_eq!(
        page.snapshots.len(),
        1,
        "only the newly changed alias needs its ordinary parse"
    );
    let before = serde_json::to_vec(&page.snapshots).unwrap();
    let held = money::live_page(
        &support,
        &mut page.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    assert!(
        held.is_empty(),
        "protected members never acquire money custody holds"
    );
    assert_eq!(before, serde_json::to_vec(&page.snapshots).unwrap());
    let _ = fs::remove_dir_all(home);
}
