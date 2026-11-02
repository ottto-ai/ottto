use super::*;

const ACTIVE: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const ALIAS: &str = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const DUPLICATE: &str = "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const TITLE_CONFLICT: &str = "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const NULL_TITLE: &str = "eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const COLLECTED: &str = "2026-10-25T08:00:00Z";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ottto-thread-rows-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn root(&self, name: &str) -> PathBuf {
        let root = self.0.join(name).join("sessions");
        fs::create_dir_all(&root).unwrap();
        let db = Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
        db.execute_batch(
            "CREATE TABLE threads(id TEXT, title TEXT, tokens_used INTEGER,
            archived INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER, model TEXT,
            rollout_path TEXT, thread_source TEXT, first_user_message TEXT);
            CREATE INDEX thread_id ON threads(id);",
        )
        .unwrap();
        root
    }
    fn insert(&self, root: &Path, id: &str, title: Option<&str>, tokens: u64) {
        let db = Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
        db.execute("INSERT INTO threads VALUES(?1,?2,?3,0,1790848800000,1790848860000,'gpt-5.2',?4,'user',NULL)",
            rusqlite::params![id,title,tokens,root.join(format!("rollout-{id}.jsonl")).to_str().unwrap()]).unwrap();
    }
    fn load(&self, roots: &[PathBuf]) -> CodexTitleMetadata {
        CodexTitleMetadata::load_from_roots(roots)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// Feed identical eager fields into the existing consumers; no second parser,
// fingerprint algorithm or persisted format is implemented by this fixture.
fn eager_fields(metadata: &CodexTitleMetadata) -> CodexTitleMetadata {
    let mut eager = metadata.clone();
    for candidate in eager.titles.values_mut() {
        candidate.title = candidate.display_title().unwrap();
        candidate.lookup = None;
    }
    for thread in eager.state_threads.values_mut().chain(
        eager
            .root_sidecars
            .values_mut()
            .flat_map(|sidecar| sidecar.threads.values_mut()),
    ) {
        let thread = Arc::make_mut(thread);
        thread.title = thread.raw_title(&mut Default::default()).unwrap();
        thread.title_lookup = None;
    }
    eager
}

/// [behaviour] Compact rows preserve eager fingerprints, home proof, title
/// precedence, conflicts, page inputs, selectors and state-only wire items.
#[test]
fn streamed_thread_rows_match_eager_consumers() {
    let fixture = Fixture::new();
    let roots = [fixture.root("a"), fixture.root("b")];
    let large_title = format!("Synthetic title{}", " ".repeat(1_000_000));
    for root in &roots {
        fixture.insert(root, ACTIVE, Some(&large_title), 200);
        fixture.insert(
            root,
            TITLE_CONFLICT,
            Some(if root == &roots[0] { "Left" } else { "Right" }),
            40,
        );
        fixture.insert(
            root,
            NULL_TITLE,
            if root == &roots[0] { None } else { Some("") },
            30,
        );
    }
    fixture.insert(&roots[0], ALIAS, Some("Alias"), 10);
    fixture.insert(&roots[0], &ALIAS.to_ascii_uppercase(), Some("Alias"), 10);
    fixture.insert(&roots[0], DUPLICATE, Some("First"), 20);
    fixture.insert(&roots[0], DUPLICATE, Some("Second"), 20);
    fs::write(
        roots[0].parent().unwrap().join("session_index.jsonl"),
        format!("{{\"id\":\"{ACTIVE}\",\"thread_name\":\"Index override\"}}\n"),
    )
    .unwrap();
    let compact = fixture.load(&roots);
    assert_eq!(
        compact.identity_conflicts,
        BTreeSet::from([
            ALIAS.to_string(),
            DUPLICATE.to_string(),
            TITLE_CONFLICT.to_string(),
            NULL_TITLE.to_string()
        ])
    );
    let taxonomy = compact.local_diagnostics.identity_conflict_taxonomy;
    assert_eq!(taxonomy.state_intra_root_row_keys, 1);
    assert_eq!(
        compact.titles[ACTIVE].display_title().unwrap(),
        "Index override"
    );
    assert_eq!(compact.state_threads[ACTIVE].tokens_used, 200);
    for root in &roots {
        let row = &compact.root_sidecars[root.parent().unwrap()].threads[ACTIVE];
        let path = Path::new(row.rollout_path.as_deref().unwrap());
        assert!(std::ptr::eq(
            compact.thread_extent_for_path(ACTIVE, path).0.unwrap(),
            row.as_ref()
        ));
    }
    let eager = eager_fields(&compact);
    for id in [ACTIVE, ALIAS, DUPLICATE, TITLE_CONFLICT, NULL_TITLE] {
        for root in &roots {
            let path = root.join(format!("rollout-{id}.jsonl"));
            assert_eq!(
                compact.path_sidecar_fingerprint(&path).unwrap(),
                eager.path_sidecar_fingerprint(&path).unwrap()
            );
            assert_eq!(
                compact.path_reduction_fingerprint(&path),
                eager.path_reduction_fingerprint(&path)
            );
            assert_eq!(
                compact.identity_from_path_evidence(&path),
                eager.identity_from_path_evidence(&path)
            );
        }
    }
    for metadata in [&compact, &eager] {
        let mut output = Vec::new();
        let (count, _) = append_codex_state_only_snapshots(
            &mut output,
            metadata,
            COLLECTED,
            &mut ScanIndex::default(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(output[0].unattributed_total_tokens, 200);
        assert_eq!(
            output[0].session_display_name.as_deref(),
            Some("Synthetic title")
        );
        assert_eq!(
            serde_json::to_value(&output[0]).unwrap(),
            serde_json::to_value(
                codex_state_only_snapshot(
                    ACTIVE,
                    &eager.state_threads[ACTIVE],
                    COLLECTED,
                    &mut Default::default()
                )
                .unwrap()
            )
            .unwrap()
        );
    }
    let path = roots[0].join(format!("rollout-{ACTIVE}.jsonl"));
    let body = [
        json!({"type":"session_meta","timestamp":"2026-10-01T10:00:00Z","payload":{"id":ACTIVE}}),
        json!({"type":"turn_context","payload":{"model":"gpt-5.2","service_tier":"priority"}}),
        json!({"type":"event_msg","timestamp":"2026-10-01T10:01:00Z","payload":{"type":"token_count","info":{"model":"gpt-5.2","total_token_usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}}),
    ];
    fs::write(
        &path,
        body.iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let parse = |metadata: &CodexTitleMetadata| {
        parse_codex_jsonl_file_with_title_metadata(
            &path,
            COLLECTED,
            metadata.path_sidecar_fingerprint(&path).unwrap(),
            metadata,
            None,
        )
        .unwrap()
    };
    let actual = parse(&compact);
    assert!(!actual.is_empty());
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        serde_json::to_value(parse(&eager)).unwrap()
    );
    assert_eq!(
        actual[0].session_display_name.as_deref(),
        Some("Index override")
    );

    let scan_page = |materialize: bool| {
        let mut state = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &roots,
            ScanIndex::default(),
            COLLECTED,
            BACKFILL_WINDOW_DAYS,
            1,
            false,
            None,
            &[],
            false,
        );
        if materialize {
            state.codex_title_metadata = eager_fields(&state.codex_title_metadata);
        }
        let selected = state
            .identified_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.path.clone(),
                    candidate.source_file_fingerprint.clone(),
                )
            })
            .collect::<Vec<_>>();
        for _ in 0..20_000 {
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete { scan, .. } => return (selected, scan),
            }
        }
        panic!("synthetic page did not finish");
    };
    let (selected, actual_page) = scan_page(false);
    let (expected_selected, expected_page) = scan_page(true);
    assert_eq!(selected, expected_selected);
    assert_eq!(selected.len(), 1);
    assert_eq!(
        actual_page.scanned_file_count,
        expected_page.scanned_file_count
    );
    assert_eq!(actual_page.census_complete, expected_page.census_complete);
    assert_eq!(
        actual_page.state_census_complete,
        expected_page.state_census_complete
    );
    assert_eq!(
        actual_page.sidecar_census_complete,
        expected_page.sidecar_census_complete
    );
    assert_eq!(
        serde_json::to_value(actual_page.snapshots).unwrap(),
        serde_json::to_value(expected_page.snapshots).unwrap()
    );

    let before = compact.path_sidecar_fingerprint(&path).unwrap();
    let reduction = compact.path_reduction_fingerprint(&path);
    Connection::open(roots[0].parent().unwrap().join("state_5.sqlite"))
        .unwrap()
        .execute("UPDATE threads SET title='Changed' WHERE id=?1", [ACTIVE])
        .unwrap();
    assert!(
        compact.path_sidecar_fingerprint(&path).is_err(),
        "changed census title stays Unknown"
    );
    // A fresh single-home census still reselects a title-only change, without a
    // reduction revision or upload-policy binding change.
    let fresh = fixture.load(&roots[..1]);
    assert_ne!(fresh.path_sidecar_fingerprint(&path).unwrap(), before);
    assert_eq!(fresh.path_reduction_fingerprint(&path), reduction);
}

/// [behaviour] Failed folds publish no rows, aliases or taxonomy; schema
/// fallbacks and NULL/empty title distinctions retain their existing verdicts.
#[test]
fn thread_rows_publish_only_after_complete_reads() {
    let fixture = Fixture::new();
    let root = fixture.root("home");
    fixture.insert(&root, ACTIVE, Some("Good"), 100);
    fixture.insert(&root, ALIAS, Some("Alias"), 10);
    fixture.insert(&root, &ALIAS.to_ascii_uppercase(), Some("Alias"), 10);
    let path = root.parent().unwrap().join("state_5.sqlite");
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO threads(id,title,tokens_used,archived) VALUES('bad',?1,5,0)",
            [b"not text".as_slice()],
        )
        .unwrap();
    let mut metadata = CodexTitleMetadata::default();
    let mut open = SidecarOpenCounts::default();
    assert!(load_codex_sqlite_titles(
        &path,
        &mut open,
        &mut metadata.titles,
        &mut metadata.identity_conflicts
    )
    .is_err());
    assert!(metadata.titles.is_empty());
    assert!(metadata.identity_conflicts.is_empty());
    assert!(load_codex_sqlite_state_threads(
        &path,
        &mut open,
        &mut metadata.state_threads,
        &mut metadata.identity_conflicts,
        &mut metadata.local_diagnostics.identity_conflict_taxonomy
    )
    .is_err());
    assert!(metadata.state_threads.is_empty());
    assert!(metadata.identity_conflicts.is_empty());
    assert_eq!(
        metadata
            .local_diagnostics
            .identity_conflict_taxonomy
            .state_alias_keys,
        0
    );
    let loaded = fixture.load(std::slice::from_ref(&root));
    assert!(loaded.state_census_incomplete);
    assert!(loaded.sidecar_census_incomplete);
    assert_eq!(
        loaded.local_diagnostics.state_titles.reason,
        codex_scan_diagnostics::LoaderReason::SqliteRowDecode
    );
    assert_eq!(
        loaded.local_diagnostics.state_threads.reason,
        codex_scan_diagnostics::LoaderReason::SqliteRowDecode
    );
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM threads WHERE id='bad'", [])
        .unwrap();
    let later = "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    fixture.insert(&root, later, Some("Later known row"), 7);
    let complete = fixture.load(std::slice::from_ref(&root));
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE threads SET title='Moved' WHERE id=?1", [ACTIVE])
        .unwrap();
    let mut output = Vec::new();
    assert!(append_codex_state_only_snapshots(
        &mut output,
        &complete,
        COLLECTED,
        &mut ScanIndex::default(),
        &BTreeSet::new()
    )
    .is_err());
    assert_eq!(
        output.len(),
        1,
        "a failed title does not delay later known money"
    );
    assert_eq!(output[0].source_session_id, later);
    assert_eq!(output[0].unattributed_total_tokens, 7);
}

/// [behaviour] Raw title history is absent from retained census payloads.
/// Compact id-directory growth remains expected; active page stays fixed.
#[test]
fn retained_thread_payload_does_not_follow_title_history() {
    use crate::heap_layout_bound::completed_bound;
    let fixture = Fixture::new();
    let root = fixture.root("home");
    for row in 0..16 {
        let id = format!("{row:08x}-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        fixture.insert(&root, &id, Some("Title"), 10);
    }
    let small = fixture.load(std::slice::from_ref(&root));
    let db = Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
    let huge_title = format!("Title{}", " ".repeat(1_000_000));
    db.execute("UPDATE threads SET title=?1", [&huge_title])
        .unwrap();
    drop(db);
    let large = fixture.load(std::slice::from_ref(&root));
    assert_eq!(small.state_threads.len(), large.state_threads.len());
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(
            completed_bound(&small, usize::MAX),
            completed_bound(&large, usize::MAX)
        );
    }
    assert!(large.state_threads.values().all(|row| row.title.is_none()));
    assert!(large.titles.values().all(|row| row.title.is_empty()));
    let active = "00000000-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    assert_eq!(
        large
            .narrowed_to(&root.join(format!("rollout-{active}.jsonl")))
            .state_threads
            .len(),
        1
    );
}
