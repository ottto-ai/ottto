use super::*;
use crate::snapshots::codex_file_join::tests::usage;
fn temp_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ottto-{name}-{unique}"));
    fs::create_dir_all(&path).unwrap();
    path
}

struct Fixture {
    home: PathBuf,
    roots: Vec<PathBuf>,
    ids: Vec<String>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        Self::build(count, false)
    }
    fn build(count: usize, physical_copies: bool) -> Self {
        let home = temp_dir("codex-cross-root-copies");
        let roots = (0..5)
            .map(|i| home.join(format!("home-{i}/sessions")))
            .collect::<Vec<_>>();
        let ids = (0..count)
            .map(|i| format!("aaaaaaaa-bbbb-4ccc-8ddd-{i:012x}"))
            .collect::<Vec<_>>();
        for (i, root) in roots.iter().enumerate() {
            fs::create_dir_all(root).unwrap();
            let db = Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
            db.execute_batch(concat!(
                "CREATE TABLE threads (id TEXT, title TEXT, tokens_used INTEGER, archived INTEGER, ",
                "created_at_ms INTEGER, updated_at_ms INTEGER, model TEXT, rollout_path TEXT, ",
                "thread_source TEXT, first_user_message TEXT);"
            )).unwrap();
            let history =
                Connection::open(root.parent().unwrap().join("thread_history_1.sqlite")).unwrap();
            history.execute_batch("CREATE TABLE thread_history_projection_state (thread_id TEXT, next_rollout_byte_offset INTEGER, next_rollout_ordinal INTEGER);").unwrap();
            // Default home is empty; four slot homes retain copied metadata.
            // The highest-progress home sorts FIRST, exercising older-last load.
            if i == 0 {
                continue;
            }
            let turns = [0, 4, 2, 3, 1][i];
            for (j, id) in ids.iter().enumerate() {
                let path = root.join(format!("rollout-2026-10-01T10-00-00-{id}.jsonl"));
                let mut rows = vec![
                    json!({"type":"session_meta","timestamp":"2026-10-01T10:00:00Z","payload":{"id":id}}),
                ];
                for turn in 1..=turns {
                    rows.push(json!({"type":"token_usage_record","timestamp":format!("2026-10-01T10:{turn:02}:00Z"),"payload":{
                        "thread_id":id,"response_id":format!("r-{turn}"),"usage":usage(100),"thread_token_usage":usage(turn*100)}}));
                    rows.push(json!({"type":"event_msg","timestamp":format!("2026-10-01T10:{turn:02}:01Z"),"payload":{
                        "type":"token_count","info":{"model":"gpt-5.2","last_token_usage":usage(100),"total_token_usage":usage(turn*100)}}}));
                }
                let bytes = rows
                    .iter()
                    .map(|row| row.to_string() + "\n")
                    .collect::<String>();
                if i == 1 || physical_copies {
                    fs::write(&path, &bytes).unwrap();
                }
                let created = 1_790_848_800_000_i64 + if j < 26 { (i as i64) * 75 } else { 0 };
                db.execute("INSERT INTO threads VALUES (?1, 'same', ?2, 0, ?3, ?4, 'gpt-5.2', ?5, 'user', NULL)",
                    rusqlite::params![id, turns*100, created, 1_790_848_800_000_i64+turns as i64*60_000, path.to_str().unwrap()]).unwrap();
                history
                    .execute(
                        "INSERT INTO thread_history_projection_state VALUES (?1, ?2, ?3)",
                        rusqlite::params![id, bytes.len(), rows.len()],
                    )
                    .unwrap();
            }
        }
        Self { home, roots, ids }
    }
    fn update(&self, root: usize, sql: &str) {
        Connection::open(self.roots[root].parent().unwrap().join("state_5.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn metadata(&self) -> CodexTitleMetadata {
        CodexTitleMetadata::load_from_roots(&self.roots)
    }
    fn scan(&self, index: ScanIndex) -> (ScanIndex, SourceScanResult) {
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &self.roots,
            index,
            "2026-10-25T08:00:00Z",
            BACKFILL_WINDOW_DAYS,
            10_000,
            false,
            None,
            &[],
            false,
        );
        for _ in 0..20_000 {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("fixture did not finish");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.home).unwrap();
    }
}

#[test]
fn five_roots_46_copied_threads_recover_census_and_count_each_once() {
    let fixture = Fixture::new(46);
    let metadata = fixture.metadata();
    assert_eq!(metadata.local_diagnostics.state_threads.completed_roots, 5);
    assert_eq!(metadata.local_diagnostics.state_threads.failed_roots, 0);
    assert!(metadata.identity_conflicts.is_empty());
    assert!(!metadata.state_census_incomplete && !metadata.sidecar_census_incomplete);
    assert_eq!(metadata.state_threads.len(), 46);
    for id in &fixture.ids {
        assert_eq!(metadata.state_threads[id].tokens_used, 400);
        for root in &fixture.roots[1..] {
            let row = &metadata.root_sidecars[root.parent().unwrap()].threads[id];
            let path = Path::new(row.rollout_path.as_deref().unwrap());
            let (bound, extent) = metadata.thread_extent_for_path(id, path);
            assert_eq!(bound.unwrap(), row);
            assert!(extent.unwrap().next_byte_offset > 0);
            assert!(path.starts_with(root));
            if root == &fixture.roots[1] {
                assert_eq!(
                    extent.unwrap().next_byte_offset,
                    fs::metadata(path).unwrap().len()
                );
            } else {
                assert!(!path.exists(), "older homes retain metadata only");
            }
        }
    }
    let (mut index, mut scan) = fixture.scan(ScanIndex::default());
    assert!(scan.census_complete, "{scan:?}");
    assert_eq!(scan.dropped_usage_record_count, 0);
    assert_eq!(scan.ownership_incomplete_file_count, 0);
    assert_eq!(scan.unreadable_path_count, 0);
    assert!(!scan.snapshots.is_empty());
    assert_eq!(
        scan.snapshots.len(),
        46,
        "one physical file per logical thread"
    );
    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    let by_id = scan.snapshots.iter().fold(
        BTreeMap::<String, BTreeSet<String>>::new(),
        |mut map, item| {
            assert_eq!(item.input_tokens, 400);
            assert_eq!(item.provenance.state_total_tokens, Some(400));
            map.entry(item.source_session_id.clone())
                .or_default()
                .insert(item.snapshot_fingerprint.clone());
            map
        },
    );
    assert_eq!(by_id.len(), 46);
    assert!(
        by_id.values().all(|bodies| bodies.len() == 1),
        "one upload body per logical thread"
    );
    let accepted = scan
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let unacknowledged =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert!(
        unacknowledged.files.is_empty(),
        "lost upload ACK cannot checkpoint any file"
    );
    let settled = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let (_, again) = fixture.scan(settled);
    assert!(again.census_complete, "{again:?}");
    assert!(
        again.snapshots.is_empty(),
        "acknowledged sessions do not upload again"
    );
}

#[test]
fn incompatible_copies_stay_scoped_and_cannot_be_resurrected_by_a_third_root() {
    for sql in [
        "UPDATE threads SET created_at_ms = created_at_ms+1000",
        "UPDATE threads SET model = 'different-model'",
        "UPDATE threads SET rollout_path = replace(rollout_path, '/sessions/', '/sessions/other/')",
        "UPDATE threads SET tokens_used = 9999", // An older copy claiming more usage.
        "UPDATE threads SET updated_at_ms = 1790849040000", // Equal update, unequal tokens.
        "UPDATE threads SET created_at_ms = NULL",
        "UPDATE threads SET title = 'different-title'",
        "UPDATE threads SET archived = 1",
    ] {
        let fixture = Fixture::new(1);
        fixture.update(2, sql);
        let metadata = fixture.metadata();
        assert_eq!(
            metadata.identity_conflicts,
            BTreeSet::from([fixture.ids[0].clone()])
        );
        assert!(!metadata.state_threads.contains_key(&fixture.ids[0]));
        assert!(metadata.state_census_incomplete && metadata.sidecar_census_incomplete);
        let (_, scan) = fixture.scan(ScanIndex::default());
        assert!(!scan.census_complete);
        assert!(
            scan.snapshots.is_empty(),
            "no conflicting state-only fallback"
        );
    }
}

#[test]
fn creation_precision_tolerance_does_not_chain_across_roots() {
    let fixture = Fixture::new(1);
    for (i, millis) in [(1, 0), (2, 750), (3, 1500), (4, 1501)] {
        fixture.update(
            i,
            &format!("UPDATE threads SET created_at_ms = 1790848800000+{millis}"),
        );
    }
    let metadata = fixture.metadata();
    assert!(metadata.identity_conflicts.contains(&fixture.ids[0]));
    assert!(metadata.state_threads.is_empty());
}

#[test]
fn incomparable_projection_progress_stays_conflicted() {
    let fixture = Fixture::new(1);
    Connection::open(
        fixture.roots[2]
            .parent()
            .unwrap()
            .join("thread_history_1.sqlite"),
    )
    .unwrap()
    .execute_batch("UPDATE thread_history_projection_state SET next_rollout_ordinal=99999")
    .unwrap();
    let metadata = fixture.metadata();
    assert!(metadata.identity_conflicts.contains(&fixture.ids[0]));
    assert!(!metadata.rollout_extents.contains_key(&fixture.ids[0]));
    assert!(metadata.sidecar_census_incomplete);
}

#[test]
fn synthetic_reduction_and_alias_failures_are_retryable_not_hidden_by_copy_recovery() {
    let fixture = Fixture::new(1);
    let metadata = fixture.metadata();
    assert!(!metadata.state_census_incomplete && !metadata.sidecar_census_incomplete);
    let mut counts = ScanTraversalCounts::default();
    counts.record_unreadable(UnreadableCause::Reduction, 1);
    counts.record_unreadable(UnreadableCause::AliasParser, 1);
    assert_eq!(counts.unreadable_path_count, 2);
    assert!(counts.has_retryable_problems());
    assert!(!counts.settle_non_progressing_residue());
    let projection = serde_json::to_value(counts.unreadable_causes.projection(2)).unwrap();
    assert_eq!(projection["counts"], json!([0, 0, 0, 0, 1, 1, 0, 0]));
    // Only a genuinely clean subsequent traversal may complete the census.
    let (_, clean) = fixture.scan(ScanIndex::default());
    assert!(clean.census_complete, "{clean:?}");
}

#[test]
fn stale_metadata_in_four_homes_with_one_physical_rollout_completes() {
    let fixture = Fixture::new(1);
    let metadata = fixture.metadata();
    assert!(metadata.identity_conflicts.is_empty());
    assert_eq!(metadata.state_threads[&fixture.ids[0]].tokens_used, 400);
    let (_, scan) = fixture.scan(ScanIndex::default());
    assert!(scan.census_complete, "{scan:?}");
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].input_tokens, 400);
}

#[test]
fn multiple_physical_homes_remain_strict_without_independent_alias_proof() {
    let fixture = Fixture::build(1, true);
    let metadata = fixture.metadata();
    assert!(metadata.identity_conflicts.is_empty());
    let (index, scan) = fixture.scan(ScanIndex::default());
    assert!(!scan.census_complete);
    assert!(scan.snapshots.is_empty());
    assert!(index.files.is_empty());
    assert_eq!(scan.ownership_incomplete_file_count, 4);
    let diagnostic = scan.local_codex_diagnostics.unwrap();
    let causes = serde_json::to_value(
        diagnostic
            .unreadable_causes
            .projection(scan.unreadable_path_count as u64),
    )
    .unwrap();
    assert_eq!(
        causes["counts"][5], 4,
        "unchanged guard refuses each cross-home file group"
    );
}

#[test]
fn another_homes_collision_invalidates_unchanged_local_reduction_dependencies() {
    let fixture = Fixture::new(1);
    let before = fixture.metadata();
    let root = fixture.roots[1].parent().unwrap();
    let local = &before.root_sidecars[root].threads[&fixture.ids[0]];
    let path = Path::new(local.rollout_path.as_deref().unwrap());
    let fingerprint = before.path_reduction_fingerprint(path);
    fixture.update(2, "UPDATE threads SET model='conflicting-model'");
    let after = fixture.metadata();
    assert!(after.identity_conflicts.contains(&fixture.ids[0]));
    assert_eq!(&after.root_sidecars[root].threads[&fixture.ids[0]], local);
    assert_ne!(
        after.path_reduction_fingerprint(path),
        fingerprint,
        "paused parser must not reuse ownership after another home conflicts"
    );
    fixture.update(2, "UPDATE threads SET model='gpt-5.2'");
    assert_eq!(
        fixture.metadata().path_reduction_fingerprint(path),
        fingerprint
    );
}

#[test]
fn dominant_projection_does_not_hide_incompatible_older_copies_in_any_order() {
    let projections = [(1000, 100), (500, 80), (600, 70)];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut metadata = CodexTitleMetadata::default();
        for (n, i) in order.into_iter().enumerate() {
            let (next_byte_offset, next_ordinal) = projections[i];
            let extents = BTreeMap::from([(
                "thread".to_string(),
                CodexRolloutExtent {
                    next_byte_offset,
                    next_ordinal,
                },
            )]);
            merge_extents(&mut metadata, &extents);
            metadata.root_sidecars.insert(
                PathBuf::from(format!("home-{n}")),
                RootSidecar {
                    threads: BTreeMap::new(),
                    extents,
                },
            );
        }
        assert!(
            metadata.identity_conflicts.contains("thread"),
            "order={order:?}"
        );
        assert!(!metadata.rollout_extents.contains_key("thread"));
    }
}

#[test]
fn equal_token_state_ties_follow_parsed_time_not_timestamp_text() {
    let fixture = Fixture::new(1);
    let loaded = fixture.metadata();
    let mut metadata = CodexTitleMetadata::default();
    for (root_index, updated) in [
        (1, "2026-10-01T11:04:00+01:00"),
        (2, "2026-10-01T10:04:00.900Z"),
        (3, "2026-10-01T10:04:00.100Z"),
        (4, "2026-10-01T10:04:00.200Z"),
    ] {
        let root = fixture.roots[root_index].parent().unwrap();
        let mut row = loaded.root_sidecars[root].threads[&fixture.ids[0]].clone();
        row.tokens_used = 400;
        row.updated_at = Some(updated.to_string());
        let threads = BTreeMap::from([(fixture.ids[0].clone(), row)]);
        merge_threads(&mut metadata, root, &threads);
        metadata.root_sidecars.insert(
            root.to_path_buf(),
            RootSidecar {
                threads,
                extents: BTreeMap::new(),
            },
        );
    }
    assert!(metadata.identity_conflicts.is_empty());
    let selected = &metadata.state_threads[&fixture.ids[0]];
    let latest =
        &metadata.root_sidecars[fixture.roots[2].parent().unwrap()].threads[&fixture.ids[0]];
    assert_eq!(
        selected, latest,
        "900 ms is later despite the first row's text sorting last"
    );
}

#[test]
fn parsed_state_evidence_comes_from_the_physical_home_even_if_a_stale_home_claims_more() {
    let fixture = Fixture::new(1);
    let (_, before) = fixture.scan(ScanIndex::default());
    assert_eq!(before.snapshots[0].provenance.state_total_tokens, Some(400));
    // A later watermark survives in a home whose rollout is missing. It stays
    // available to state-only fallback, not the parsed physical file's evidence.
    fixture.update(
        2,
        "UPDATE threads SET tokens_used=500, updated_at_ms=1790849100000",
    );
    let metadata = fixture.metadata();
    assert!(metadata.identity_conflicts.is_empty());
    assert_eq!(metadata.state_threads[&fixture.ids[0]].tokens_used, 500);
    let (_, scan) = fixture.scan(ScanIndex::default());
    assert!(scan.census_complete, "{scan:?}");
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].input_tokens, 400);
    assert_eq!(scan.snapshots[0].provenance.state_total_tokens, Some(400));
    assert_eq!(
        scan.snapshots[0].snapshot_fingerprint,
        before.snapshots[0].snapshot_fingerprint
    );
}
