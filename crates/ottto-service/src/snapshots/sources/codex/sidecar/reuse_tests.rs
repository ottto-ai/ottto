//! Synthetic fresh sidecar census, compaction and read-guard checks.
use super::*;
use crate::transcript_acquisition::StampedFacts;

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

const ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-000000000001";
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
/// successes on each fresh load.
#[test]
fn subcensus_failures_are_isolated() {
    for sql in [
        "ALTER TABLE threads RENAME COLUMN title TO old_title",
        "UPDATE threads SET tokens_used=x'ff'",
        "ALTER TABLE threads RENAME COLUMN first_user_message TO old_message",
    ] {
        let f = Fixture::new();
        let (db, _path) = seed(&f);
        sync_home(&f.0);
        CodexTitleMetadata::load_from_roots(&f.roots());
        db.execute_batch(sql).unwrap();
        sync_home(&f.0);
        let failed = CodexTitleMetadata::load_from_roots(&f.roots());
        assert!(failed.state_census_incomplete);
        assert!(
            failed.local_diagnostics.state_titles.completed_roots > 0
                || failed.local_diagnostics.state_threads.completed_roots > 0
        );
    }
    let f = Fixture::new();
    let (db, _path) = seed(&f);
    db.execute_batch("UPDATE threads SET thread_source='agent_created_thread', first_user_message=''; INSERT INTO thread_spawn_edges VALUES (x'ff', 'child')").unwrap();
    sync_home(&f.0);
    let q4_failed = CodexTitleMetadata::load_from_roots(&f.roots());
    assert!(
        q4_failed.state_created_threads.contains(ID),
        "Q3 survives Q4 failure"
    );
    assert!(!q4_failed.created_thread_census_failed_homes.is_empty());
}

/// [money] Per-pass conflict suppression keeps the old physical-home view,
/// while the pass owns the raw row used to build it.
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
