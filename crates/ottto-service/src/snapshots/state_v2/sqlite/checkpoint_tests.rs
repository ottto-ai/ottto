//! State-store checkpoint cadence regressions. Synthetic values only.
use super::*;

const SAVE_BYTES: usize = 3_460_301; // 3.3 MiB, one whole-value rewrite
const PASSES: u64 = 12;

/// A published synthetic store: its scratch directory, path and identity.
fn live_store(prefix: &str) -> (crate::test_scratch::ScratchDir, PathBuf, Identity) {
    let scratch = crate::test_scratch::ScratchDir::canonical(prefix);
    let path = scratch.join("index.v2.sqlite.import");
    let mut db = Sqlite::create_import(&path).unwrap();
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-checkpoint".into(),
        fence_generation: 0,
        binding: super::super::super::scan_index_persistence::Binding {
            source: super::super::super::scan_index_persistence::Source::Claude,
            namespace_hash: "b".repeat(64),
        },
    };
    db.control("identity", &identity).unwrap();
    db.control("generation", &0_u64).unwrap();
    db.finish_import().unwrap();
    (scratch, path, identity)
}
fn open(path: &Path, identity: &Identity) -> Sqlite {
    let mut db = Sqlite::open(path, identity).unwrap();
    db.path_extractor(key_only);
    db
}
/// Reads the old value like the real extractor and emits only the key.
fn key_only(h: &Header, v: &dyn Value, paths: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
    v.write(&mut io::sink())?;
    if let RowKey::Record { key_bytes, .. } = &h.key {
        paths(std::str::from_utf8(key_bytes)?)?;
    }
    Ok(())
}
fn key(name: &str) -> RowKey {
    RowKey::record("scan_state.traversal", name.as_bytes().to_vec(), 0).unwrap()
}
fn save(db: &mut Sqlite, generation: u64, name: &str, bytes: &[u8]) {
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        value_version: 1,
        key: &key(name),
        fixed: &Fixed::None,
        value: bytes,
    })
    .unwrap();
    assert_eq!(
        tx.commit(generation, generation + 1),
        DurableCommitOutcome::Committed(generation + 1)
    );
}
fn read(db: &mut Sqlite, name: &str) -> Vec<u8> {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let header = tx.get(&key(name)).unwrap().unwrap();
    let mut out = Vec::new();
    tx.read_value(&header, &mut out).unwrap();
    out
}

/// [behaviour] Idle releases cached pages without changing the next pass's budget.
#[test]
fn idle_releases_page_cache_and_next_pass_refills_it() {
    let (_scratch, path, identity) = live_store("v2-idle-cache");
    let mut db = open(&path, &identity);
    // Exercise the page cache even when the database fits in the mmap ceiling.
    db.conn()
        .unwrap()
        .execute_batch("PRAGMA mmap_size=0")
        .unwrap();
    let mmap_size: i64 = db
        .conn()
        .unwrap()
        .query_row("PRAGMA mmap_size", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mmap_size, 0);
    let value = vec![b'x'; SAVE_BYTES];
    for (generation, quiet) in [false, true].into_iter().enumerate() {
        save(&mut db, generation as u64, "cached", &value);
        assert_eq!(read(&mut db, "cached"), value);
        db.maintenance(false).unwrap();
        let warm = serde_json::to_value(db.maintenance_stats()).unwrap();
        let warm_bytes = warm["cache_used_bytes"].as_u64().unwrap();
        // Cache retention depends on SQLite's process-wide soft heap pressure,
        // not the payload size. Require a measurable release on either OS.
        assert!(warm_bytes > 16 * 1024, "warm cache: {warm_bytes}");
        let sqlite_heap = unsafe { rusqlite::ffi::sqlite3_memory_used() };
        db.between_cycles(quiet).unwrap();
        let idle = serde_json::to_value(db.maintenance_stats()).unwrap();
        let idle_bytes = idle["cache_used_bytes"].as_u64().unwrap();
        eprintln!("idle cache quiet={quiet}: warm={warm_bytes} idle={idle_bytes} sqlite_heap={sqlite_heap}");
        assert!(
            idle_bytes < 64 * 1024 && idle_bytes < warm_bytes / 2,
            "warm cache: {warm_bytes}, idle cache: {idle_bytes}"
        );
        let cache_size: i64 = db
            .conn()
            .unwrap()
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cache_size, -8192);
        db.clean_checkpoint().unwrap();
        db.stamp().unwrap();
        let accesses = db.cache_accesses_for_test();
        assert_eq!(read(&mut db, "cached"), value);
        assert!(db.cache_accesses_for_test() > accesses);
    }
}

/// Checkpoint counts by mode: (PASSIVE, IdleReclaim), complete or not.
fn checkpoints(db: &Sqlite) -> (u64, u64) {
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    let count = |slot: usize| {
        stats["checkpoint_complete"][slot].as_u64().unwrap()
            + stats["checkpoint_incomplete"][slot].as_u64().unwrap()
    };
    (count(0), count(2))
}
/// The disk state a SIGTERM leaves: the database and its WAL, never closed.
/// Copies after the last use of `db`; the copy's -shm is rebuilt at open.
fn exit_without_close(db: Sqlite, path: &Path, to: &crate::test_scratch::ScratchDir) -> PathBuf {
    let copy = to.join("index.v2.sqlite.import");
    fs::copy(path, &copy).unwrap();
    fs::copy(sidecar(path, "-wal"), sidecar(&copy, "-wal")).unwrap();
    drop(db);
    copy
}

/// [regress] the shipped cadence checkpoints by WAL size, never by pass.
#[test]
fn shipped_cadence_checkpoints_at_the_wal_threshold_without_idle_truncate() {
    let (_scratch, path, identity) = live_store("v2-checkpoint-cadence");
    let mut db = open(&path, &identity);
    assert_eq!(db.purge_policy.checkpoint_bytes, 32 * 1024 * 1024);
    let value = |pass: u64| -> Vec<u8> {
        let mut state = (pass + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (0..SAVE_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    };
    let threshold = db.purge_policy.checkpoint_bytes;
    let mut checkpointed_passes = 0;
    for pass in 0..PASSES {
        let (passive, _) = checkpoints(&db);
        save(&mut db, pass, "traversal", &value(pass));
        // The save's own commit runs maintenance, so this is the pass's peak.
        let peak = db.wal_bytes().unwrap();
        db.between_cycles(false).unwrap();
        db.clean_checkpoint().unwrap();
        assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(0));
        let fired = checkpoints(&db).0 > passive;
        assert_eq!(fired, peak >= threshold, "WAL {peak} B");
        assert!(peak < WAL_ALARM_BYTES);
        if fired {
            // The clean marker's commit restarts the WAL at the size limit.
            let after = db.wal_bytes().unwrap();
            assert!(after < threshold, "WAL {after} B");
        }
        checkpointed_passes += u64::from(fired);
    }
    let (_, idle) = checkpoints(&db);
    assert_eq!(idle, 0, "no idle TRUNCATE without debt");
    assert!(
        (1..PASSES).contains(&checkpointed_passes),
        "PASSIVE on {checkpointed_passes} passes"
    );
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["wal_alarm"], false);
    assert!(read(&mut db, "traversal") == value(PASSES - 1));
    db.validate_parts().unwrap();
}

/// [regress] frames left behind the clean marker by an exit without close
/// replay at open without a check; a dirty marker is checked.
#[test]
fn clean_marker_skips_open_check_after_an_exit_without_close() {
    for clean in [true, false] {
        let (_scratch, path, identity) = live_store("v2-clean-marker");
        let mut db = open(&path, &identity);
        save(&mut db, 0, "traversal", b"committed");
        if clean {
            db.between_cycles(false).unwrap();
            db.clean_checkpoint().unwrap();
        }
        assert_eq!(
            db.read_control::<u8>("phase").unwrap(),
            Some(u8::from(!clean))
        );
        assert!(db.wal_bytes().unwrap() > 0, "no TRUNCATE between passes");
        let after_exit = crate::test_scratch::ScratchDir::canonical("v2-clean-marker-exit");
        let copy = exit_without_close(db, &path, &after_exit);
        super::super::telemetry::take_thread_event_for_test("quick_check");
        let mut db = open(&copy, &identity);
        assert_eq!(
            super::super::telemetry::take_thread_event_for_test("quick_check"),
            (!clean).then(|| serde_json::json!(1)),
            "clean marker {clean}"
        );
        assert_eq!(read(&mut db, "traversal"), b"committed");
    }
}

/// [regress] an idle pass truncates the WAL only to clear checkpoint debt or
/// while erasure is overdue.
#[test]
fn idle_truncate_runs_only_for_checkpoint_debt() {
    let (_scratch, path, identity) = live_store("v2-idle-debt");
    let mut db = open(&path, &identity);
    let idle = |db: &Sqlite| {
        let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
        (
            stats["checkpoint_complete"][2].as_u64().unwrap(),
            stats["checkpoint_incomplete"][2].as_u64().unwrap(),
        )
    };
    save(&mut db, 0, "traversal", b"first");
    db.between_cycles(false).unwrap();
    assert_eq!(idle(&db), (0, 0));
    assert!(db.wal_bytes().unwrap() > 0);
    // A reader pins its snapshot, so PASSIVE stops short and leaves debt.
    db.purge_policy.checkpoint_bytes = 0;
    let reader = reader_for_test(&db);
    save(&mut db, 1, "traversal", b"second");
    db.between_cycles(false).unwrap();
    assert!(db.debt);
    assert_eq!(idle(&db), (0, 1));
    db.clean_checkpoint().unwrap();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(1));
    drop(reader);
    db.between_cycles(false).unwrap();
    assert!(!db.debt);
    assert_eq!(idle(&db), (0, 1));
    db.clean_checkpoint().unwrap();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(0));
    // An overdue erasure that cannot run (no space) still truncates.
    db.control("erasure_pending", &1_u64).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    db.control("erasure_since", &(now.as_secs() - 25 * 3600))
        .unwrap();
    db.purge_policy.space = |_| Some(0);
    db.between_cycles(false).unwrap();
    assert_eq!(idle(&db), (1, 1));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(1));
}
