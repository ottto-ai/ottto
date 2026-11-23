//! State-store checkpoint cadence regressions. Synthetic values only.
use super::*;

const SAVE_BYTES: usize = 3_460_301; // 3.3 MiB, one whole-value rewrite
const PASSES: u64 = 12;

/// A published synthetic store: its scratch directory, path and identity.
fn live_store(prefix: &str) -> (crate::test_scratch::ScratchDir, PathBuf, Identity) {
    live_store_for_source(
        prefix,
        super::super::super::scan_index_persistence::Source::Claude,
    )
}
fn live_store_for_source(
    prefix: &str,
    source: super::super::super::scan_index_persistence::Source,
) -> (crate::test_scratch::ScratchDir, PathBuf, Identity) {
    let scratch = crate::test_scratch::ScratchDir::canonical(prefix);
    let path = scratch.join("index.v2.sqlite.import");
    let mut db = Sqlite::create_import(&path).unwrap();
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-checkpoint".into(),
        fence_generation: 0,
        binding: super::super::super::scan_index_persistence::Binding {
            source,
            namespace_hash: "b".repeat(64),
        },
    };
    db.control("identity", &identity).unwrap();
    db.control("generation", &0_u64).unwrap();
    db.finish_import().unwrap();
    (scratch, path, identity)
}

/// [regress] Verified sources accumulate pager writes across sampling, VACUUM and reopen.
#[test]
fn pager_bytes_follow_verified_store_identity_and_survive_replacement() {
    use super::super::super::scan_index_persistence::Source;
    use crate::local_resource_diagnostics::{cache_lifecycle, cache_lifecycle_totals, capture};
    let fields = [
        (
            Source::Claude,
            "claude_sqlite_pager_wal_page_bytes_cumulative",
        ),
        (
            Source::Codex,
            "codex_sqlite_pager_wal_page_bytes_cumulative",
        ),
        (Source::Pi, "pi_sqlite_pager_wal_page_bytes_cumulative"),
    ];
    for (source, field) in fields {
        let (_scratch, path, identity) = live_store_for_source("pager-source", source);
        let (_, counts) = cache_lifecycle::observe(|| {
            let mut db = open(&path, &identity);
            let row = || capture(cache_lifecycle_totals).1.remove(0);
            let before = row()["counts"][field].as_u64().unwrap();
            db.control("phase", &0_u8).unwrap();
            db.between_cycles(false).unwrap();
            let after = row()["counts"][field].as_u64().unwrap();
            assert!(after > before, "{field}");
            let (_, repeated) = cache_lifecycle::observe(|| {
                db.sample_pager_writes();
                db.sample_pager_writes();
            });
            assert_eq!(serde_json::to_value(repeated).unwrap()[field], 0);
            db.control("phase", &1_u8).unwrap();
            let (_, replaced) = cache_lifecycle::observe(|| {
                assert_eq!(db.vacuum().unwrap().state, CheckpointState::Complete);
            });
            assert!(
                serde_json::to_value(replaced).unwrap()[field]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(row()["counts"][field].as_u64().unwrap() >= after);
            db.control("phase", &0_u8).unwrap();
            let (_, closed) = cache_lifecycle::observe(|| drop(db));
            assert!(
                serde_json::to_value(closed).unwrap()[field]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            let before_reopen = row()["counts"][field].as_u64().unwrap();
            let _db = open(&path, &identity);
            assert!(row()["counts"][field].as_u64().unwrap() >= before_reopen);
        });
        let counts = serde_json::to_value(counts).unwrap();
        assert!(counts[field].as_u64().unwrap() > 0);
        for (_, other) in fields {
            if other != field {
                assert_eq!(counts[other], 0, "{other}");
            }
        }
    }
}

/// [regress] History WAL pages are sampled once and carried across connection closes.
#[test]
fn upload_history_pager_bytes_are_cumulative() {
    use crate::local_resource_diagnostics::cache_lifecycle;
    let scratch = crate::test_scratch::ScratchDir::canonical("history-pager");
    let path = history::Store::path(&scratch);
    let (_, counts) = cache_lifecycle::observe(|| {
        let store = history::Store::open(&path).unwrap();
        store.sample_pager_writes();
        let (_, repeated) = cache_lifecycle::observe(|| store.sample_pager_writes());
        assert_eq!(
            repeated.upload_history_sqlite_pager_wal_page_bytes_cumulative,
            0
        );
        store
            .conn_for_test()
            .execute_batch("PRAGMA application_id=1")
            .unwrap();
        let (_, closed) = cache_lifecycle::observe(|| drop(store));
        assert!(closed.upload_history_sqlite_pager_wal_page_bytes_cumulative >= 4096);
        let _store = history::Store::open(&path).unwrap();
    });
    assert!(counts.upload_history_sqlite_pager_wal_page_bytes_cumulative >= 4096);
    assert_eq!(counts.claude_sqlite_pager_wal_page_bytes_cumulative, 0);
    assert_eq!(counts.codex_sqlite_pager_wal_page_bytes_cumulative, 0);
    assert_eq!(counts.pi_sqlite_pager_wal_page_bytes_cumulative, 0);
}
/// [regress] External sorts on state and history connections add spill bytes once.
#[test]
fn tempbuf_spill_bytes_are_sampled_once_for_state_and_history() {
    use crate::local_resource_diagnostics::{cache_lifecycle, cache_lifecycle_totals, capture};
    let (_scratch, path, identity) = live_store("tempbuf-spill");
    let db = open(&path, &identity);
    let scratch = crate::test_scratch::ScratchDir::canonical("history-tempbuf-spill");
    let history = history::Store::open(&history::Store::path(&scratch)).unwrap();
    for (conn, event) in [
        (db.conn().unwrap(), Event::ClaudePagerBytes),
        (history.conn_for_test(), Event::HistoryPagerBytes),
    ] {
        sample_pager_writes(conn, event);
        let row = || capture(cache_lifecycle_totals).1.remove(0);
        let field = "sqlite_tempbuf_spill_bytes_cumulative";
        let before = row()["counts"][field].as_u64().unwrap();
        conn.execute_batch("PRAGMA temp_store=FILE; PRAGMA cache_size=1")
            .unwrap();
        // Four MiB of sort keys exceed SQLite's minimum sorter buffer too.
        let bytes: i64 = conn
            .query_row(
                "SELECT sum(length(v)) FROM (
                   WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096)
                   SELECT printf('%01024d', x) AS v FROM n ORDER BY v DESC
                 )",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bytes, 4096 * 1024);
        let (_, counts) = cache_lifecycle::observe(|| sample_pager_writes(conn, event));
        assert!(counts.sqlite_tempbuf_spill_bytes_cumulative > 0);
        assert!(
            row()["counts"][field].as_u64().unwrap()
                >= before + counts.sqlite_tempbuf_spill_bytes_cumulative
        );
        let (_, repeated) = cache_lifecycle::observe(|| {
            sample_pager_writes(conn, event);
            sample_pager_writes(conn, event);
        });
        assert_eq!(repeated.sqlite_tempbuf_spill_bytes_cumulative, 0);
    }
}

/// [regress] Resetting pager writes first excludes overlapping TEMP-table bytes.
#[test]
fn temp_table_spill_is_counted_as_pager_bytes_only() {
    use crate::local_resource_diagnostics::cache_lifecycle;
    let (_scratch, path, identity) = live_store("tempbuf-overlap");
    let db = open(&path, &identity);
    db.sample_pager_writes();
    db.conn()
        .unwrap()
        .execute_batch(
            "PRAGMA temp_store=FILE;
             PRAGMA temp.page_size=4096;
             PRAGMA temp.cache_size=1;
             CREATE TEMP TABLE spill(v BLOB);
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<512)
             INSERT INTO spill SELECT zeroblob(1024) FROM n;",
        )
        .unwrap();
    let (_, counts) = cache_lifecycle::observe(|| db.sample_pager_writes());
    assert!(counts.claude_sqlite_pager_wal_page_bytes_cumulative > 0);
    assert_eq!(counts.sqlite_tempbuf_spill_bytes_cumulative, 0);
    let (_, repeated) = cache_lifecycle::observe(|| db.sample_pager_writes());
    assert_eq!(repeated.claude_sqlite_pager_wal_page_bytes_cumulative, 0);
    assert_eq!(repeated.sqlite_tempbuf_spill_bytes_cumulative, 0);
}

/// [regress] Count each checkpoint's reported pages, including repeated backfill.
#[test]
fn checkpoint_reported_pages_follow_results_without_resampling() {
    use crate::local_resource_diagnostics::{cache_lifecycle, cache_lifecycle_totals, capture};
    let (_scratch, path, identity) = live_store("checkpoint-reported-pages");
    let mut db = open(&path, &identity);
    db.control("phase", &1_u8).unwrap();
    let field = "sqlite_checkpoint_reported_pages_cumulative";
    let row = || capture(cache_lifecycle_totals).1.remove(0);
    let before = row()["counts"][field].as_u64().unwrap();
    let (result, counts) = cache_lifecycle::observe(|| db.checkpoint(CheckpointMode::Passive));
    let done = result.checkpointed_frames.unwrap();
    assert!(done > 0);
    assert_eq!(counts.sqlite_checkpoint_reported_pages_cumulative, done);
    assert!(row()["counts"][field].as_u64().unwrap() >= before + done);
    let (_, sampled) = cache_lifecycle::observe(|| {
        db.sample_pager_writes();
        db.sample_pager_writes();
    });
    assert_eq!(sampled.sqlite_checkpoint_reported_pages_cumulative, 0);
    let (result, repeated) = cache_lifecycle::observe(|| db.checkpoint(CheckpointMode::Passive));
    assert_eq!(result.checkpointed_frames, Some(done));
    assert_eq!(repeated.sqlite_checkpoint_reported_pages_cumulative, done);
    let (result, truncated) =
        cache_lifecycle::observe(|| db.checkpoint(CheckpointMode::IdleReclaim));
    assert_eq!(result.state, CheckpointState::Complete);
    assert_eq!(result.checkpointed_frames, Some(0));
    assert_eq!(truncated.sqlite_checkpoint_reported_pages_cumulative, 0);
}

/// [regress] A WAL checkpoint and an erasure VACUUM each add the process
/// logical-write delta to their own field (macOS only; zero elsewhere).
#[test]
fn checkpoint_and_erasure_vacuum_count_logical_write_deltas() {
    use crate::local_resource_diagnostics::cache_lifecycle;
    let (_scratch, path, identity) = live_store("checkpoint-logical-writes");
    let mut db = open(&path, &identity);
    db.control("phase", &1_u8).unwrap();
    let (result, checkpoint) = cache_lifecycle::observe(|| db.checkpoint(CheckpointMode::Passive));
    assert!(result.checkpointed_frames.unwrap() > 0);
    db.control("phase", &2_u8).unwrap();
    let (result, vacuum) = cache_lifecycle::observe(|| db.checkpoint(CheckpointMode::Purge));
    assert_eq!(result.state, CheckpointState::Complete);
    let measured = cfg!(target_os = "macos");
    assert_eq!(
        checkpoint.sqlite_checkpoint_logical_write_bytes_cumulative > 0,
        measured
    );
    assert_eq!(checkpoint.erasure_vacuum_logical_write_bytes_cumulative, 0);
    // The VACUUM's own TRUNCATE checkpoint counts under the VACUUM only.
    assert_eq!(
        vacuum.erasure_vacuum_logical_write_bytes_cumulative > 0,
        measured
    );
    assert_eq!(vacuum.sqlite_checkpoint_logical_write_bytes_cumulative, 0);
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
        // Prime daily idle work without releasing, so the comparison isolates
        // release from maintenance's own cache activity.
        db.maintenance(true).unwrap();
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

/// [regress] within a day of the last truncation, an idle pass truncates the
/// WAL only to clear checkpoint debt or while erasure is overdue.
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

/// [regress] Once a day an idle window truncates the WAL even without
/// debt; a later window the same day does not.
#[test]
fn idle_window_truncates_once_a_day_without_debt() {
    let (_scratch, path, identity) = live_store("v2-daily-truncate");
    let mut db = open(&path, &identity);
    save(&mut db, 0, "traversal", b"first");
    db.between_cycles(false).unwrap();
    assert_eq!(checkpoints(&db).1, 0, "not due within a day of open");
    assert!(db.wal_bytes().unwrap() > 0);
    db.next_truncate = None; // a day has passed
    db.between_cycles(false).unwrap();
    assert_eq!(checkpoints(&db).1, 1);
    assert_eq!(db.wal_bytes(), Some(0));
    save(&mut db, 1, "traversal", b"second");
    db.between_cycles(false).unwrap();
    assert_eq!(checkpoints(&db).1, 1, "once a day");
    assert!(db.wal_bytes().unwrap() > 0);
}

/// [regress] The shipped erasure deadline is 7 days. A quiet window
/// waits half of it, a busy source pauses at five sixths, and a recent
/// success holds a quiet window until that pause is due.
#[test]
fn erasure_gates_follow_the_weekly_deadline() {
    const DAY: u64 = 86400;
    assert_eq!(maintenance::ERASURE_DEADLINE, Duration::from_secs(7 * DAY));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let attempted = |case: &str, success_ago: Option<u64>, age: u64, quiet: bool| {
        let (_scratch, path, identity) = live_store(&format!("v2-weekly-{case}"));
        let mut db = open(&path, &identity);
        db.set_purge_policy(maintenance::ERASURE_DEADLINE, Duration::from_secs(5))
            .unwrap();
        db.control("erasure_pending", &1_u64).unwrap();
        db.control("erasure_since", &(now - age)).unwrap();
        if let Some(ago) = success_ago {
            db.control("erasure_success", &(now - ago)).unwrap();
        }
        // Only whether an attempt started matters here, not its outcome.
        let _ = db.between_cycles(quiet);
        db.read_control::<u64>("erasure_attempt").unwrap().is_some()
    };
    assert!(!attempted("quiet-3d", None, 3 * DAY, true));
    assert!(attempted("quiet-4d", None, 4 * DAY, true));
    assert!(!attempted("busy-5d", None, 5 * DAY, false));
    assert!(attempted("busy-6d", None, 6 * DAY, false));
    assert!(!attempted("recent-4d", Some(DAY), 4 * DAY, true));
    assert!(attempted("recent-6d", Some(DAY), 6 * DAY, true));
    // The success cooldown is the full deadline.
    assert!(!attempted(
        "cooldown-under",
        Some(7 * DAY - 60),
        4 * DAY,
        true
    ));
    assert!(attempted("cooldown-at", Some(7 * DAY), 4 * DAY, true));
    // Acquisition pauses for erasure at five sixths too.
    let pause = |case: &str, age: u64| {
        let (_scratch, path, identity) = live_store(&format!("v2-weekly-pause-{case}"));
        let mut db = open(&path, &identity);
        db.set_purge_policy(maintenance::ERASURE_DEADLINE, Duration::from_secs(5))
            .unwrap();
        db.control("erasure_pending", &1_u64).unwrap();
        db.control("erasure_since", &(now - age)).unwrap();
        db.collection_pause_due().unwrap()
    };
    assert!(!pause("5d", 5 * DAY));
    assert!(pause("6d", 6 * DAY));
}

/// [regress] The daemon exits without closing its stores. A WAL left that
/// way makes the daily truncate due at the first idle window after reopen.
#[test]
fn a_leftover_wal_is_truncated_at_the_first_idle_window_after_reopen() {
    let (_scratch, path, identity) = live_store("v2-leftover-wal");
    let mut db = open(&path, &identity);
    save(&mut db, 0, "traversal", b"committed");
    let after_exit = crate::test_scratch::ScratchDir::canonical("v2-leftover-wal-exit");
    let copy = exit_without_close(db, &path, &after_exit);
    let mut db = open(&copy, &identity);
    assert!(db.wal_bytes().unwrap() > 0);
    db.between_cycles(false).unwrap();
    assert_eq!(checkpoints(&db).1, 1);
    assert_eq!(db.wal_bytes(), Some(0));
    assert_eq!(read(&mut db, "traversal"), b"committed");
}
