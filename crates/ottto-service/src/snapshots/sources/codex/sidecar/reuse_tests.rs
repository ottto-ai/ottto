//! Synthetic sidecar reuse and fresh-load parity, through the scan constructor.
use super::*;

thread_local! {
    static STAGED: std::cell::RefCell<BTreeMap<PathBuf, SourceStamp>> = const { std::cell::RefCell::new(BTreeMap::new()) };
}
fn sync_input(home: &Path, input: &str) {
    let source = home.join("writer").join(input);
    let now = SourceStamp::capture_sqlite(&source).expect("synthetic writer witness");
    STAGED.with(|staged| {
        let mut staged = staged.borrow_mut();
        if staged.get(&source).is_some_and(|old| old.same(&now)) { return; }
        let replace = !matches!((staged.get(&source), &now),
            (Some(SourceStamp::Sqlite { main: old, .. }), SourceStamp::Sqlite { main: now, .. }) if old.same_object(now));
        codex_sqlite_read::tests::copy_database(&source, &home.join(input), replace);
        staged.insert(source, now);
    });
}
fn sync_home(home: &Path) {
    for input in ["state_5.sqlite", "thread_history_1.sqlite"] {
        sync_input(home, input);
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "ottto-sidecar-reuse-{}",
            ottto_core::generate_control_token().unwrap()
        ));
        fs::create_dir_all(home.join("sessions")).unwrap();
        fs::create_dir_all(home.join("writer")).unwrap();
        let db = Connection::open(home.join("writer/state_5.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE threads (id TEXT, title TEXT, tokens_used INTEGER, archived INTEGER, created_at INTEGER, updated_at INTEGER, model TEXT, rollout_path TEXT, thread_source TEXT, first_user_message TEXT); CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT);").unwrap();
        drop(db);
        sync_home(&home);
        Self(home)
    }
    fn roots(&self) -> Vec<PathBuf> {
        vec![self.0.join("sessions")]
    }
    fn selecting(&self, cache: &sampled_scan::SharedCache) -> OwnedSourceScan {
        OwnedSourceScan::new_selecting(
            SnapshotSource::Codex,
            &self.roots(),
            ScanIndex::default(),
            "2026-11-09T12:00:00Z",
            30,
            100,
            None,
            &[],
            false,
            &mut ListingRequest::default(),
            false,
            &[],
            Some((
                cache,
                &crate::transcript_acquisition::Scope("sidecar-reuse".into()),
            )),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        STAGED.with(|staged| {
            staged
                .borrow_mut()
                .retain(|path, _| !path.starts_with(&self.0))
        });
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// [regress] An unchanged second pass does not reopen the sidecar databases.
#[test]
fn reuse_skips_sidecar_read() {
    let fixture = Fixture::new();
    let cache = sampled_scan::SharedCache::default();
    let first = fixture.selecting(&cache);
    assert!(!first.codex_title_metadata.state_census_incomplete);
    let second = fixture.selecting(&cache);
    let d = second.codex_title_metadata.local_diagnostics;
    assert_eq!(
        d.state_titles.snapshot_fallbacks
            + d.state_threads.snapshot_fallbacks
            + d.spawn_edges.snapshot_fallbacks,
        0
    );
}

const ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-000000000001";
fn assert_metadata(a: &CodexTitleMetadata, b: &CodexTitleMetadata, paths: &[PathBuf]) {
    macro_rules! equal { ($($field:ident),* $(,)?) => { $(assert_eq!(a.$field, b.$field, stringify!($field));)* }; }
    equal!(
        state_threads,
        rollout_extents,
        state_created_threads,
        spawn_parents,
        spawn_parent_conflicts,
        identity_conflicts,
        state_census_incomplete,
        sidecar_census_incomplete,
        state_census_unscoped_incomplete,
        sidecar_census_unscoped_incomplete,
        created_thread_census_failed_homes,
        created_thread_scoped,
        legacy_sidecar_fingerprint,
        legacy_config_file_present
    );
    let titles = |m: &CodexTitleMetadata| {
        m.titles
            .iter()
            .map(|(id, title)| (id.clone(), (title.title.clone(), title.source.clone())))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(titles(a), titles(b));
    assert_eq!(
        serde_json::to_value(a.local_diagnostics.identity_conflict_taxonomy).unwrap(),
        serde_json::to_value(b.local_diagnostics.identity_conflict_taxonomy).unwrap()
    );
    assert_eq!(
        a.root_sidecars.keys().collect::<Vec<_>>(),
        b.root_sidecars.keys().collect::<Vec<_>>()
    );
    for (home, rows) in &a.root_sidecars {
        assert_eq!(rows.threads, b.root_sidecars[home].threads);
        assert_eq!(rows.extents, b.root_sidecars[home].extents);
    }
    for path in paths {
        assert_eq!(
            a.path_sidecar_fingerprint(path),
            b.path_sidecar_fingerprint(path)
        );
        assert_eq!(
            a.path_reduction_fingerprint(path),
            b.path_reduction_fingerprint(path)
        );
        let (a, b) = (a.narrowed_to(path), b.narrowed_to(path));
        assert_metadata(&a, &b, &[]);
        assert_eq!(
            a.path_sidecar_fingerprint(path),
            b.path_sidecar_fingerprint(path)
        );
        assert_eq!(
            a.path_reduction_fingerprint(path),
            b.path_reduction_fingerprint(path)
        );
    }
}
fn parity(facts: &mut SidecarFacts, roots: &[PathBuf], paths: &[PathBuf]) -> CodexTitleMetadata {
    for home in roots
        .iter()
        .filter_map(|root| root.parent())
        .collect::<BTreeSet<_>>()
    {
        sync_home(home);
    }
    let mut reused = CodexTitleMetadata::load_reused(roots, facts);
    let mut fresh = CodexTitleMetadata::load_from_roots(roots);
    // The emitted gauge is the kept facts' charge, and 0 with nothing kept.
    let gauge = reused.local_diagnostics.sidecar_facts_heap_bytes;
    assert_eq!(gauge, facts.heap_bytes() as u64);
    assert_eq!(gauge == 0, facts.homes.kept.is_empty());
    assert!(gauge < u64::MAX, "a kept charge is a completed bound");
    assert_eq!(fresh.local_diagnostics.sidecar_facts_heap_bytes, 0);
    let index = ScanIndex::default();
    reused.scope_created_thread_census(&index, roots);
    fresh.scope_created_thread_census(&index, roots);
    assert_metadata(&reused, &fresh, paths);
    reused
}
fn seed(fixture: &Fixture) -> (Connection, PathBuf) {
    let db = Connection::open(fixture.0.join("writer/state_5.sqlite")).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let path = fixture
        .0
        .join("sessions")
        .join(format!("rollout-{ID}.jsonl"));
    db.execute("INSERT INTO threads VALUES (?1, 'Base title', 10, 0, 1790000000, 1790000001, 'gpt-5.2', ?2, 'user', NULL)", rusqlite::params![ID, path.to_str().unwrap()]).unwrap();
    (db, path)
}

/// [money] Raw row, roster, WAL, partial-census and merged-prefix changes
/// preserve every map, completeness/scope flag and both v4 fingerprints.
#[test]
fn sidecar_state_transitions_match_fresh() {
    let a = Fixture::new();
    let b = Fixture::new();
    let (db, path) = seed(&b);
    let mut facts = SidecarFacts::default();
    let mut roots = a.roots();
    roots.extend(b.roots());
    fs::write(
        a.0.join("session_index.jsonl"),
        json!({"id":ID,"thread_name":"Winning title"}).to_string() + "\n",
    )
    .unwrap();
    for _ in 0..2 {
        parity(&mut facts, &roots, std::slice::from_ref(&path));
    }
    let cached = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(cached.local_diagnostics.state_titles.reused_roots, 2);
    // Removed winning home: the surviving Q2 row needs a new exact prefix.
    roots = b.roots();
    let removed = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(removed.local_diagnostics.state_titles.reloaded_roots, 1);
    assert_eq!(removed.titles[ID].title, "Base title");
    roots.extend(a.roots());
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    for title in [
        None,
        Some(String::new()),
        Some("é".repeat(32)),
        Some("x".repeat(63)),
        Some("x".repeat(64)),
        Some("x".repeat(65)),
        Some(" raw  title \n".into()),
    ] {
        db.execute(
            "UPDATE threads SET title=?1, tokens_used=tokens_used+1",
            [title],
        )
        .unwrap();
        parity(&mut facts, &roots, std::slice::from_ref(&path));
        parity(&mut facts, &roots, std::slice::from_ref(&path));
    }
    for sql in ["UPDATE threads SET rollout_path='moved', updated_at=updated_at+1", "UPDATE threads SET thread_source='agent_created_thread', first_user_message=''", "INSERT INTO thread_spawn_edges VALUES ('parent', 'child')", "DELETE FROM thread_spawn_edges", "INSERT INTO threads SELECT upper(id), title, tokens_used, archived, created_at, updated_at, model, rollout_path, thread_source, first_user_message FROM threads", "DELETE FROM threads WHERE id != lower(id)"] {
        db.execute_batch(sql).unwrap(); parity(&mut facts, &roots, std::slice::from_ref(&path));
    }
    let history = Connection::open(a.0.join("writer/thread_history_1.sqlite")).unwrap();
    history.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE thread_history_projection_state (thread_id TEXT, next_rollout_byte_offset INTEGER, next_rollout_ordinal INTEGER)").unwrap();
    for sql in [
        format!(
            "INSERT INTO thread_history_projection_state VALUES ('{ID}', 20, 2), ('{}', 21, 3)",
            ID.to_uppercase()
        ),
        "DELETE FROM thread_history_projection_state".into(),
    ] {
        history.execute_batch(&sql).unwrap();
        parity(&mut facts, &roots, std::slice::from_ref(&path));
    }
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    db.execute_batch("UPDATE threads SET tokens_used=tokens_used+1; PRAGMA wal_checkpoint(RESTART); UPDATE threads SET tokens_used=tokens_used+1").unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    drop(db);
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    let parked = b.0.join("state-old.sqlite");
    fs::rename(b.0.join("state_5.sqlite"), &parked).unwrap();
    let missing = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(missing.local_diagnostics.state_titles.absent_roots, 1);
    fs::rename(parked, b.0.join("state_5.sqlite")).unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    let db = Connection::open(b.0.join("writer/state_5.sqlite")).unwrap();
    db.execute_batch("PRAGMA journal_mode=DELETE; ALTER TABLE thread_spawn_edges RENAME TO old_edges; CREATE TABLE thread_spawn_edges (parent_thread_id BLOB, child_thread_id TEXT); INSERT INTO thread_spawn_edges VALUES (x'ff', 'child')").unwrap();
    let q4_failed = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert!(
        q4_failed.state_created_threads.contains(ID),
        "Q3 survives Q4 failure"
    );
    assert!(!q4_failed.created_thread_census_failed_homes.is_empty());
    assert!(!facts.homes.kept.contains_key(&b.0));
    db.execute_batch(
        "DROP TABLE thread_spawn_edges; ALTER TABLE old_edges RENAME TO thread_spawn_edges",
    )
    .unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    fs::write(a.0.join("session_index.jsonl"), "{bad json\n").unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    fs::remove_file(a.0.join("session_index.jsonl")).unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    // Unsupported cache witness retains a successful ordinary plain read.
    fs::hard_link(b.0.join("state_5.sqlite"), b.0.join("hardlink")).unwrap();
    assert!(SourceStamp::capture_sqlite(&b.0.join("state_5.sqlite")).is_none());
    assert!(!parity(&mut facts, &roots, std::slice::from_ref(&path)).state_census_incomplete);
    assert!(facts.homes.kept.is_empty(), "a partial group holds no RAM");
    let repeated = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(repeated.local_diagnostics.state_titles.reloaded_roots, 2);
    assert!(facts.homes.kept.is_empty());
    fs::remove_file(b.0.join("hardlink")).unwrap();
    parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(facts.homes.kept.len(), 2);
    let repaired = parity(&mut facts, &roots, std::slice::from_ref(&path));
    assert_eq!(repaired.local_diagnostics.state_titles.reused_roots, 2);
}

/// [regress] A refused reuse records its content-free cause and the changed
/// sorted-roster positions per input; a declined keep records why.
#[test]
fn sidecar_reload_cause_is_recorded() {
    let (a, b) = (Fixture::new(), Fixture::new());
    let mut roots = a.roots();
    roots.extend(b.roots());
    let mut facts = SidecarFacts::default();
    let cause = |facts: &mut SidecarFacts, roots: &[PathBuf]| {
        let d = CodexTitleMetadata::load_reused(roots, facts).local_diagnostics;
        (
            d.sidecar_reload_cause,
            d.sidecar_changed_homes,
            d.sidecar_keep_declined,
        )
    };
    assert_eq!(cause(&mut facts, &roots), ("not_kept", [0; 3], ""));
    assert_eq!(cause(&mut facts, &roots), ("", [0; 3], ""));
    let line = json!({"id": ID, "thread_name": "Touched"}).to_string() + "\n";
    fs::write(b.0.join("session_index.jsonl"), line).unwrap();
    let position = usize::from(a.0 < b.0);
    let touched = cause(&mut facts, &roots);
    assert_eq!(touched, ("stamp_changed", [0, 0, 1 << position], ""));
    assert_eq!(
        cause(&mut facts, &b.roots()),
        ("roster_changed", [0; 3], "")
    );
    // A hard link leaves the state stamp unavailable: read, but not kept.
    fs::hard_link(b.0.join("state_5.sqlite"), b.0.join("hardlink")).unwrap();
    let unstamped = cause(&mut facts, &b.roots());
    assert_eq!(unstamped, ("stamp_changed", [1, 0, 0], "unstamped"));
    assert!(facts.homes.kept.is_empty());
    let next = cause(&mut facts, &b.roots());
    assert_eq!(next, ("not_kept", [0; 3], "unstamped"));
}

/// [money] Compact digest and clone/continue keep the legacy byte stream;
/// None and Some("") have distinct copy equality, including SHA block edges.
#[test]
fn compact_title_keeps_legacy_fingerprints_and_raw_equality() {
    for title in [
        None,
        Some(String::new()),
        Some("é".repeat(32)),
        Some("x".repeat(63)),
        Some("x".repeat(64)),
        Some("x".repeat(65)),
    ] {
        let row = Shared::from(CodexStateThread {
            title,
            tokens_used: 7,
            ..Default::default()
        });
        let mut m = CodexTitleMetadata::default();
        m.titles.insert(
            ID.into(),
            CodexTitleCandidate {
                title: "Merged title".into(),
                source: "session_index".into(),
            },
        );
        m.state_created_threads.insert(ID.into());
        m.state_threads.insert(ID.into(), row.clone());
        m.root_sidecars.insert(
            PathBuf::from("/synthetic"),
            Arc::new(codex_root_copies::RootSidecar {
                threads: BTreeMap::from([(ID.into(), row.clone())]),
                raw: facts::RawRows {
                    threads: vec![(ID.into(), row.clone())],
                    ..Default::default()
                },
                ..Default::default()
            }),
        );
        let before = m.session_sidecar_fingerprint(ID);
        let path = Path::new("/synthetic").join(format!("rollout-{ID}.jsonl"));
        let reduction = m.path_reduction_fingerprint(&path);
        m.compact_titles();
        assert_eq!(before, m.session_sidecar_fingerprint(ID));
        assert_eq!(reduction, m.path_reduction_fingerprint(&path));
        assert_eq!(row, m.state_threads[ID]);
        assert!(m.state_threads[ID].title.is_none());
    }
    assert_ne!(
        CodexStateThread::default(),
        CodexStateThread {
            title: Some(String::new()),
            ..Default::default()
        }
    );
}

/// [behaviour] Missing columns/row decode failures retain unrelated census
/// successes; incomplete state is not kept and a repaired pass loads again.
#[test]
fn subcensus_failures_are_isolated() {
    for sql in [
        "ALTER TABLE threads RENAME COLUMN title TO old_title",
        "UPDATE threads SET tokens_used=x'ff'",
        "ALTER TABLE threads RENAME COLUMN first_user_message TO old_message",
    ] {
        let f = Fixture::new();
        let (db, path) = seed(&f);
        let mut facts = SidecarFacts::default();
        parity(&mut facts, &f.roots(), std::slice::from_ref(&path));
        db.execute_batch(sql).unwrap();
        let failed = parity(&mut facts, &f.roots(), std::slice::from_ref(&path));
        assert!(failed.state_census_incomplete);
        assert!(facts.homes.kept.is_empty());
        assert!(
            failed.local_diagnostics.state_titles.completed_roots > 0
                || failed.local_diagnostics.state_threads.completed_roots > 0
        );
    }
}

/// [money] Per-pass conflict suppression keeps the old physical-home view,
/// while the resident home still owns its raw row for the next pass.
#[test]
fn alias_conflict_keeps_legacy_physical_fingerprint() {
    let f = Fixture::new();
    let (db, path) = seed(&f);
    db.execute("INSERT INTO threads VALUES (?1, 'Alias title', 0, 0, NULL, NULL, NULL, NULL, 'user', NULL)", [ID.to_uppercase()]).unwrap();
    sync_home(&f.0);
    let metadata = CodexTitleMetadata::load_from_roots(&f.roots());
    assert!(metadata.identity_conflicts.contains(ID));
    assert_eq!(metadata.thread_extent_for_path(ID, &path), (None, None));
    let mut legacy = CodexTitleMetadata::default();
    legacy.identity_conflicts.insert(ID.into());
    assert_eq!(
        metadata.path_sidecar_fingerprint(&path),
        legacy.path_sidecar_fingerprint(&path)
    );
    assert_eq!(
        metadata.path_reduction_fingerprint(&path),
        legacy.path_reduction_fingerprint(&path)
    );
}

/// [behaviour] WAL routing keeps absence distinct from empty, while facts
/// treat both empty-frame states equally; moving snapshots cannot be kept.
#[test]
fn sqlite_witness_routes_and_refuses_moved_snapshot() {
    let f = Fixture::new();
    let path = f.0.join("state_5.sqlite");
    let before = SourceStamp::capture_sqlite(&path).unwrap();
    let read = codex_sqlite_read::CodexSqliteRead::open_stamped(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        CODEX_SIDECAR_BUSY_TIMEOUT,
        Some(&before),
    )
    .unwrap();
    assert!(read.is_snapshot());
    fs::write(f.0.join("state_5.sqlite-wal"), []).unwrap();
    let empty = SourceStamp::capture_sqlite(&path).unwrap();
    assert!(before.same(&empty));
    assert!(matches!(
        empty,
        SourceStamp::Sqlite {
            wal: crate::transcript_acquisition::SqliteWal::Empty,
            ..
        }
    ));
    assert!(read.read(|_| Ok(())).is_err());
    assert!(read.after_stamp().is_none());
    fs::remove_file(f.0.join("state_5.sqlite-wal")).unwrap();
    let mut kept = StampedFacts::default();
    let value: Result<_> = kept.reuse_or_load(
        0,
        || SourceStamp::capture_sqlite(&path).ok_or_else(|| std::io::Error::other("noncacheable")),
        || {
            let db = Connection::open(&path)?;
            db.execute_batch("CREATE TABLE changed (n INTEGER)")?;
            Ok(7)
        },
    );
    assert_eq!(value.unwrap(), 7);
    assert!(kept.kept.is_empty());
}

/// [money] A kept home keeps only its views: a reused pass derives the same
/// facts as the raw rows did (`parity`), including an id that differs from
/// its resolved key, and the raw thread/history copies leave the heap.
#[test]
fn kept_home_drops_raw_rows() {
    let f = Fixture::new();
    let (db, path) = seed(&f);
    let upper = "AAAAAAAA-BBBB-4CCC-8DDD-000000000002";
    let other =
        f.0.join("sessions")
            .join(format!("rollout-{}.jsonl", upper.to_lowercase()));
    db.execute("INSERT INTO threads VALUES (?1, 'Upper title', 5, 0, 1790000000, 1790000001, 'gpt-5.2', ?2, 'user', NULL)", rusqlite::params![upper, other.to_str().unwrap()]).unwrap();
    let history = Connection::open(f.0.join("writer/thread_history_1.sqlite")).unwrap();
    history.execute_batch(&format!("CREATE TABLE thread_history_projection_state (thread_id TEXT, next_rollout_byte_offset INTEGER, next_rollout_ordinal INTEGER); INSERT INTO thread_history_projection_state VALUES ('{ID}', 20, 2), ('{upper}', 7, 1)")).unwrap();
    let paths = [path, other];
    let mut facts = SidecarFacts::default();
    let first = parity(&mut facts, &f.roots(), &paths);
    assert!(first.identity_conflicts.is_empty());
    let second = parity(&mut facts, &f.roots(), &paths);
    assert_eq!(second.local_diagnostics.state_titles.reused_roots, 1);
    assert_eq!(second.root_sidecars[&f.0].extents.len(), 2);
    let slim = facts.homes.kept[&f.0].1.clone();
    assert!(slim.raw.threads.is_empty() && slim.raw.history.is_empty());
    assert_eq!(slim.threads.len(), 2);
    // The previous representation: the same home plus its raw rows. A clone
    // drops spare capacity, so both sides start from one cloned baseline.
    let base = (*slim).clone();
    let mut old = base.clone();
    old.raw.threads = slim
        .threads
        .iter()
        .map(|(id, row)| (id.clone(), row.clone()))
        .collect();
    old.raw.history = slim
        .extents
        .iter()
        .map(|(id, e)| (id.clone(), e.next_byte_offset as i64, e.next_ordinal as i64))
        .collect();
    let merged = CodexTitleMetadata::merge_roots(
        BTreeMap::from([(f.0.clone(), Arc::new(old.clone()))]),
        false,
    );
    assert_metadata(&merged, &second, &paths);
    let size = |home: &codex_root_copies::RootSidecar| {
        crate::heap_layout_bound::completed_bound(home, usize::MAX).unwrap()
    };
    let raw = crate::heap_layout_bound::completed_bound(&old.raw.threads, usize::MAX).unwrap()
        + crate::heap_layout_bound::completed_bound(&old.raw.history, usize::MAX).unwrap()
        - 2 * std::mem::size_of::<Vec<u8>>();
    assert!(size(&slim) < size(&old));
    assert_eq!(size(&old) - size(&base), raw);
}
