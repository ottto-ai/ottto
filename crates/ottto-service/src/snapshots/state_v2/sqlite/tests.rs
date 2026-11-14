//! State-store checkpoint cadence: the write-amplification fixture and the
//! clean-marker and idle-debt regressions. Synthetic values only.
//!
//! Replays whole-value rewrites through the real store, save path and
//! checkpoint calls under each checkpoint/secure_delete configuration and
//! prints one `WRITE_AMP_FIXTURE {json}` line per configuration. Byte counts
//! are printed for review, never asserted: the test asserts only that every
//! value reads back and that the WAL stays under its alarm.
//!
//! A WAL hook reads each committed frame from the -wal file. A generation
//! (WAL salts) ends only after a complete checkpoint, so each finished
//! generation counts as one checkpoint whose database page writes are its
//! distinct page numbers. The -shm and database files are never opened here:
//! closing another descriptor on them would drop SQLite's POSIX locks.
use super::*;
use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
use std::io::{Read, Seek, SeekFrom};

const WARMUP_PASSES: usize = 2;
const PASSES: usize = 24;
const FIELD_BYTES: usize = 1_887_437; // 1.8 MiB
const TRAVERSAL_BYTES: usize = 1_572_864; // 1.5 MiB
const FRAME_BYTES: u64 = 24 + 4096;

#[derive(Clone, Copy, PartialEq)]
enum Between {
    /// Before this change: PASSIVE at 8 MiB, the idle TRUNCATE, then the
    /// clean checkpoint's TRUNCATE and its `phase` commit.
    TruncateEveryPass,
    /// PASSIVE only once the WAL reaches the threshold; the `phase` commit
    /// stays.
    Threshold,
    /// Whatever `between_cycles` and `clean_checkpoint` do in this build.
    Shipped,
}
struct Config {
    name: &'static str,
    /// None keeps the store's own setting.
    secure_delete: Option<&'static str>,
    between: Between,
    threshold: Option<u64>,
}

#[derive(Default, serde::Serialize)]
struct Counts {
    commits: u64,
    frames: u64,
    zero_frames: u64,
}
struct Generation {
    salts: [u8; 8],
    frames: u32,
    pages: BTreeSet<u32>,
}
#[derive(Default)]
struct Wal {
    path: PathBuf,
    generation: Option<Generation>,
    /// 0 = the save transaction, 1 = between passes.
    step: usize,
    measuring: bool,
    counts: [Counts; 2],
    checkpoints: u64,
    checkpointed_frames: u64,
    checkpointed_pages: u64,
    error: Option<String>,
}
impl Wal {
    fn read(&mut self, frames: u32) -> io::Result<()> {
        let mut file = File::open(&self.path)?;
        let mut header = [0_u8; 32];
        file.read_exact(&mut header)?;
        let salts: [u8; 8] = header[16..24].try_into().expect("eight bytes");
        if self.generation.as_ref().is_some_and(|g| g.salts != salts) {
            self.finish_generation();
        }
        let generation = self.generation.get_or_insert_with(|| Generation {
            salts,
            frames: 0,
            pages: BTreeSet::new(),
        });
        file.seek(SeekFrom::Start(
            32 + u64::from(generation.frames) * FRAME_BYTES,
        ))?;
        let mut frame = vec![0_u8; FRAME_BYTES as usize];
        while generation.frames < frames {
            file.read_exact(&mut frame)?;
            if frame[8..16] != salts {
                return Err(io::Error::other("frame salts differ from the WAL header"));
            }
            generation
                .pages
                .insert(u32::from_be_bytes(frame[0..4].try_into().expect("four")));
            generation.frames += 1;
            if self.measuring {
                let counts = &mut self.counts[self.step];
                counts.frames += 1;
                counts.commits += u64::from(frame[4..8] != [0; 4]);
                counts.zero_frames += u64::from(frame[24..].iter().all(|b| *b == 0));
            }
        }
        Ok(())
    }
    /// The generation was checkpointed completely: SQLite restarts or
    /// truncates the WAL only after every frame is in the database.
    fn finish_generation(&mut self) {
        if let Some(generation) = self.generation.take() {
            if self.measuring {
                self.checkpoints += 1;
                self.checkpointed_frames += u64::from(generation.frames);
                self.checkpointed_pages += generation.pages.len() as u64;
            }
        }
    }
}
unsafe extern "C" fn wal_hook(
    arg: *mut c_void,
    _: *mut rusqlite::ffi::sqlite3,
    _: *const c_char,
    frames: c_int,
) -> c_int {
    // SAFETY: `arg` is the RefCell registered by `measure`, which unregisters
    // the hook before that RefCell is dropped. The hook runs only inside a
    // store call, while the test holds no borrow of it.
    let wal = unsafe { &*(arg as *const RefCell<Wal>) };
    let mut wal = wal.borrow_mut();
    if wal.error.is_none() {
        let read = u32::try_from(frames)
            .map_err(io::Error::other)
            .and_then(|frames| wal.read(frames));
        if let Err(error) = read {
            wal.error = Some(error.to_string());
        }
    }
    rusqlite::ffi::SQLITE_OK
}

/// Linux per-thread I/O counters: syscall write bytes (`wchar`) and bytes
/// charged when this thread dirtied the page cache (`write_bytes`), which is
/// page-cache-level, not device-level. SQLite does its I/O on the calling
/// thread, so other tests in the process do not count.
fn thread_io() -> Option<[u64; 3]> {
    let text = fs::read_to_string("/proc/thread-self/io").ok()?;
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
    };
    Some([
        field("wchar:")?,
        field("write_bytes:")?,
        field("cancelled_write_bytes:")?,
    ])
}

fn value(pass: usize, salt: u64, len: usize) -> Vec<u8> {
    // Every pass rewrites every byte, as a re-encoded Field does.
    let mut state = (pass as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ salt;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}
/// Reads the old value like the real extractor and emits only the unchanged
/// key, so no erasure is armed.
fn key_only(h: &Header, v: &dyn Value, paths: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
    v.write(&mut io::sink())?;
    if let RowKey::Record { key_bytes, .. } = &h.key {
        paths(std::str::from_utf8(key_bytes)?)?;
    }
    Ok(())
}

fn between(db: &mut Sqlite, config: &Config) {
    match config.between {
        Between::TruncateEveryPass => {
            db.maintenance(false).unwrap();
            for _ in 0..2 {
                let result = db.checkpoint(CheckpointMode::IdleReclaim);
                assert_eq!(result.state, CheckpointState::Complete);
            }
            db.control("phase", &0_u8).unwrap();
            db.clean = true;
        }
        Between::Threshold => {
            db.maintenance(false).unwrap();
            db.control("phase", &0_u8).unwrap();
            db.clean = true;
        }
        Between::Shipped => {
            db.between_cycles(false).unwrap();
            db.clean_checkpoint().unwrap();
        }
    }
}

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
fn save(db: &mut Sqlite, generation: u64, bytes: &[u8]) {
    let key = RowKey::record("scan_state.traversal", b"traversal".to_vec(), 0).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        value_version: 1,
        key: &key,
        fixed: &Fixed::None,
        value: bytes,
    })
    .unwrap();
    assert_eq!(
        tx.commit(generation, generation + 1),
        DurableCommitOutcome::Committed(generation + 1)
    );
}

fn measure(config: &Config) -> serde_json::Value {
    let (_scratch, import, identity) = live_store("v2-write-amp");
    let mut db = Sqlite::open(&import, &identity).unwrap();
    db.path_extractor(key_only);
    if let Some(mode) = config.secure_delete {
        db.conn()
            .unwrap()
            .execute_batch(&format!("PRAGMA secure_delete={mode};"))
            .unwrap();
    }
    if let Some(bytes) = config.threshold {
        db.purge_policy.checkpoint_bytes = bytes;
    }
    let secure_delete: i64 = db
        .conn()
        .unwrap()
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .unwrap();
    let wal = RefCell::new(Wal {
        path: sidecar(&import, "-wal"),
        ..Wal::default()
    });
    // SAFETY: the handle belongs to the open connection; the hook is removed
    // below, before `wal` is dropped and before the connection closes.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(
            db.conn().unwrap().handle(),
            Some(wal_hook),
            &wal as *const RefCell<Wal> as *mut c_void,
        );
    }
    let field = RowKey::record("scan_state.traversal", b"field".to_vec(), 0).unwrap();
    let traversal = RowKey::record("scan_state.traversal", b"traversal".to_vec(), 0).unwrap();
    let (mut generation, mut wal_peak, mut io_start) = (0_u64, 0_u64, None);
    for pass in 0..WARMUP_PASSES + PASSES {
        if pass == WARMUP_PASSES {
            // Every configuration starts measuring from an empty WAL.
            let drained = db.checkpoint(CheckpointMode::IdleReclaim);
            assert_eq!(drained.state, CheckpointState::Complete);
            let mut wal = wal.borrow_mut();
            wal.finish_generation();
            wal.measuring = true;
            io_start = thread_io();
        }
        wal.borrow_mut().step = 0;
        let mut tx = db.begin(TxnMode::Write).unwrap();
        for (key, salt, len) in [(&field, 1, FIELD_BYTES), (&traversal, 2, TRAVERSAL_BYTES)] {
            tx.put(RowInput {
                value_version: 1,
                key,
                fixed: &Fixed::None,
                value: &value(pass, salt, len),
            })
            .unwrap();
        }
        assert_eq!(
            tx.commit(generation, generation + 1),
            DurableCommitOutcome::Committed(generation + 1)
        );
        generation += 1;
        wal_peak = wal_peak.max(db.wal_bytes().unwrap());
        wal.borrow_mut().step = 1;
        between(&mut db, config);
        let bytes = db.wal_bytes().unwrap();
        wal_peak = wal_peak.max(bytes);
        assert!(bytes < WAL_ALARM_BYTES, "{}: WAL {bytes} B", config.name);
    }
    // Drain what is left, so every configuration pays for every page once.
    let drained = db.checkpoint(CheckpointMode::IdleReclaim);
    assert_eq!(drained.state, CheckpointState::Complete);
    wal.borrow_mut().finish_generation();
    let io_end = thread_io();
    // SAFETY: as above; clears the hook registered by this function.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(db.conn().unwrap().handle(), None, std::ptr::null_mut());
    }
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (key, salt, len) in [(&field, 1, FIELD_BYTES), (&traversal, 2, TRAVERSAL_BYTES)] {
        let header = tx.get(key).unwrap().unwrap();
        let mut out = Vec::new();
        tx.read_value(&header, &mut out).unwrap();
        assert!(
            out == value(WARMUP_PASSES + PASSES - 1, salt, len),
            "{}: value differs",
            config.name
        );
    }
    drop(tx);
    db.validate_parts().unwrap();
    let wal = wal.into_inner();
    assert_eq!(wal.error, None, "{}", config.name);
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["wal_alarm"], false, "{}", config.name);
    let page_count: u64 = db
        .conn()
        .unwrap()
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let passes = PASSES as f64;
    let saved = (FIELD_BYTES + TRAVERSAL_BYTES) as f64 * passes;
    let frames = wal.counts[0].frames + wal.counts[1].frames;
    let commits = wal.counts[0].commits + wal.counts[1].commits;
    let store_bytes = frames * FRAME_BYTES + wal.checkpointed_pages * 4096;
    let io = io_start.zip(io_end).map(|(a, b)| {
        serde_json::json!({
            "level": "linux_thread_page_cache",
            "wchar_per_pass": (b[0] - a[0]) as f64 / passes,
            "write_bytes_per_pass": (b[1] - a[1]) as f64 / passes,
            "cancelled_write_bytes_per_pass": (b[2] - a[2]) as f64 / passes,
        })
    });
    serde_json::json!({
        "config": config.name,
        "secure_delete": secure_delete,
        "checkpoint_bytes": db.purge_policy.checkpoint_bytes,
        "passes": PASSES,
        "saved_bytes_per_pass": FIELD_BYTES + TRAVERSAL_BYTES,
        "commits": commits,
        "wal_frames": frames,
        "wal_frames_per_commit": frames as f64 / commits as f64,
        "wal_frames_per_pass": frames as f64 / passes,
        "save": wal.counts[0],
        "between": wal.counts[1],
        "checkpoints": wal.checkpoints,
        "passes_per_checkpoint": passes / wal.checkpoints as f64,
        "frames_checkpointed": wal.checkpointed_frames,
        "db_pages_written": wal.checkpointed_pages,
        "db_pages_per_checkpoint": wal.checkpointed_pages as f64 / wal.checkpoints as f64,
        "db_pages_per_pass": wal.checkpointed_pages as f64 / passes,
        "freed_pages_zeroed": wal.counts[0].zero_frames + wal.counts[1].zero_frames,
        "store_bytes_per_pass": store_bytes as f64 / passes,
        "store_bytes_per_saved_byte": store_bytes as f64 / saved,
        "wal_peak_bytes": wal_peak,
        "db_pages": page_count,
        "proc_io": io,
    })
}

/// [measure] state-store write amplification per checkpoint configuration.
#[test]
fn write_amplification_per_checkpoint_configuration() {
    let threshold = Some(32 * 1024 * 1024);
    let today = Some(8 * 1024 * 1024);
    for config in [
        Config {
            name: "a_today",
            secure_delete: Some("ON"),
            between: Between::TruncateEveryPass,
            threshold: today,
        },
        Config {
            name: "b_secure_delete_fast",
            secure_delete: Some("FAST"),
            between: Between::TruncateEveryPass,
            threshold: today,
        },
        Config {
            name: "c_passive_at_32_mib",
            secure_delete: Some("ON"),
            between: Between::Threshold,
            threshold,
        },
        Config {
            name: "d_fast_and_passive_at_32_mib",
            secure_delete: Some("FAST"),
            between: Between::Threshold,
            threshold,
        },
        Config {
            name: "shipped",
            secure_delete: None,
            between: Between::Shipped,
            threshold: None,
        },
    ] {
        let line = measure(&config);
        println!("WRITE_AMP_FIXTURE {line}");
    }
}

/// [regress] between passes the WAL is kept, and a crash that leaves committed
/// frames behind the clean marker is still checked at open.
#[test]
fn clean_marker_skips_open_check_only_with_an_empty_wal() {
    let (_scratch, path, identity) = live_store("v2-clean-marker");
    let mut db = Sqlite::open(&path, &identity).unwrap();
    db.path_extractor(key_only);
    save(&mut db, 0, b"first");
    db.between_cycles(false).unwrap();
    db.clean_checkpoint().unwrap();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(0));
    assert!(db.wal_bytes().unwrap() > 0, "no TRUNCATE between passes");
    // A clean close checkpoints and removes the WAL: no check.
    drop(db);
    super::super::telemetry::take_thread_event_for_test("quick_check");
    let mut db = Sqlite::open(&path, &identity).unwrap();
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("quick_check"),
        None
    );
    db.clean_checkpoint().unwrap();
    drop(db);
    // A crash between passes: committed frames stay behind phase=0.
    let other = Connection::open(&path).unwrap();
    other
        .execute_batch("UPDATE control SET name=name WHERE name='generation'")
        .unwrap();
    assert!(fs::metadata(sidecar(&path, "-wal")).unwrap().len() > 0);
    let db = Sqlite::open(&path, &identity).unwrap();
    assert_eq!(
        super::super::telemetry::take_thread_event_for_test("quick_check"),
        Some(serde_json::json!(1))
    );
    drop(db);
    drop(other);
}

/// [regress] an idle pass truncates the WAL only to clear checkpoint debt.
#[test]
fn idle_truncate_runs_only_for_checkpoint_debt() {
    let (_scratch, path, identity) = live_store("v2-idle-debt");
    let mut db = Sqlite::open(&path, &identity).unwrap();
    db.path_extractor(key_only);
    let idle = |db: &Sqlite| {
        let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
        (
            stats["checkpoint_complete"][2].as_u64().unwrap(),
            stats["checkpoint_incomplete"][2].as_u64().unwrap(),
        )
    };
    save(&mut db, 0, b"first");
    db.between_cycles(false).unwrap();
    assert_eq!(idle(&db), (0, 0));
    assert!(db.wal_bytes().unwrap() > 0);
    // A reader pins its snapshot, so PASSIVE stops short and leaves debt.
    db.purge_policy.checkpoint_bytes = 0;
    let reader = reader_for_test(&db);
    save(&mut db, 1, b"second");
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
}
