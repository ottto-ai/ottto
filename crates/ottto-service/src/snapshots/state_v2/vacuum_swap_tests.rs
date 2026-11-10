//! Erasure by VACUUM INTO and a validated swap: one table of source × fault
//! point. Synthetic stores only; CI runs these.
use super::tail::{Collection, CollectionMeta, Shape, StagedFile, TailStage};
use super::*;
use crate::snapshots::scan_index_persistence::Source;
use crate::test_scratch::ScratchDir;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REMNANTS: [&str; 4] = [".vacuum", ".vacuum-journal", ".vacuum-wal", ".vacuum-shm"];
const EPOCH: u64 = 7;
/// Rows the shared fixture must hold for the dump to cover them.
const SEEDED: [&str; 9] = [
    "tail.head",
    "tail.page.responses",
    "progress.cache_state",
    "progress.cache_head",
    "progress.ledger",
    "progress.identity",
    "progress_generation",
    "progress_import",
    "field_presence",
];

/// Maintenance and erasure controls an attempt legitimately writes. Every
/// other row compares, logical controls included.
fn bookkeeping(name: &str) -> bool {
    name == "phase"
        || ["erasure_", "reference_", "store_growth"]
            .iter()
            .any(|p| name.starts_with(p))
}

/// Tail pages, upload progress and its accepted (ACK) ledger and identity
/// rows, through the production Tail-only and progress-import writers.
fn seed_tail_and_progress(db: &mut sqlite::Sqlite, identity: &Identity) {
    type Json = serde_json::Value;
    let graph = db.read_control::<u64>("generation").unwrap().unwrap();
    let meta = CollectionMeta {
        shape: Shape::Slot,
        elements_per_page: 8,
        elements: 16,
    };
    let page = |n: u64| {
        (
            (Collection::Responses, n),
            format!("tail page {n}").into_bytes(),
        )
    };
    let mut stage = TailStage::default();
    stage.stage(
        "/synthetic/vacuum/tail.jsonl",
        StagedFile {
            revision: 1,
            head: b"synthetic tail head".to_vec(),
            collections: [(Collection::Responses, meta)].into(),
            pages: [page(0), page(1)].into(),
            ..Default::default()
        },
    );
    super::tail::commit_exit(db, identity, graph, &stage).unwrap();
    let one = |value: Json| BTreeMap::from([("request-1".to_owned(), value)]);
    let (states, heads) = (
        one(serde_json::json!("accepted")),
        one(serde_json::json!("h1")),
    );
    // Several chunk rows: the test chunk size is 256 bytes.
    let fingerprints: BTreeMap<String, String> = (0..16)
        .map(|n| (format!("fp-{n}"), "a".repeat(40)))
        .collect();
    let ledger = serde_json::json!({"schema_version": 3,
        "accepted_snapshot_fingerprints": fingerprints, "accepted_row_count": 16});
    let mut points = |tx: &mut dyn Transaction, progress_generation: u64| -> Result<bool> {
        let point = serde_json::json!({"progress_generation": progress_generation,
            "accepted": {"key_epoch": 1}});
        super::progress::put_point(tx, "bucket-1", &point)?;
        Ok(true)
    };
    let page = super::progress::Page {
        cache_state: &states,
        cache_head: &heads,
        ledger: &ledger,
    };
    let marker = super::progress::Marker {
        sha256: "b".repeat(64),
        generation: 1,
    };
    let imported =
        super::progress::import(db, identity, graph + 1, &page, &marker, Some(&mut points));
    assert!(matches!(
        imported.unwrap(),
        super::progress::Imported::Committed(_)
    ));
}

/// A published-name store for `source` with graph, Tail and progress rows
/// and erasure debt, and its identity.
fn store(source: Source, dir: &Path) -> (sqlite::Sqlite, PathBuf, Identity) {
    let build = super::codex_on_tests::fixtures()
        .into_iter()
        .find_map(|(s, build)| (s == source).then_some(build))
        .unwrap();
    let import = dir.join("state.v2.sqlite.import");
    let db = money_test_support::populate(source, &import, &build(), BTreeMap::new());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    drop(db);
    let path = dir.join("state.v2.sqlite");
    fs::rename(&import, &path).unwrap();
    let mut db = sqlite::Sqlite::open(&path, &identity).unwrap();
    seed_tail_and_progress(&mut db, &identity);
    let names: BTreeSet<String> = dump(&mut db)
        .into_iter()
        .filter_map(|(h, _)| match h.key {
            RowKey::Record { kind, .. } => Some(kind.name().to_owned()),
            RowKey::Meta(name) => Some(name),
            RowKey::RequestSet(_) => None,
        })
        .collect();
    for name in SEEDED {
        assert!(names.contains(name), "{source:?}: no {name} row");
    }
    db.control("erasure_pending", &EPOCH).unwrap();
    (db, path, identity)
}
/// Due now: aged past the early window, last attempt two hours ago.
fn attempt(db: &mut sqlite::Sqlite) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    db.control("erasure_since", &(now - 13 * 3600))?;
    db.control("erasure_attempt", &(now - 7200))?;
    db.maintenance(true)
}
/// Every row and value except maintenance and erasure bookkeeping, after the
/// part and header audits.
fn dump(db: &mut sqlite::Sqlite) -> Vec<(Header, Vec<u8>)> {
    db.validate_parts().unwrap();
    db.audit_headers().unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut rows = Vec::new();
    for table in Table::ALL {
        let mut after = None;
        loop {
            let page = tx.scan_prefix(RowPrefix { table }, after.as_ref(), 128);
            let page = page.unwrap();
            let Some(last) = page.last() else { break };
            after = Some(last.key.clone());
            for h in page {
                if matches!(&h.key, RowKey::Meta(n) if bookkeeping(n)) {
                    continue;
                }
                let mut value = Vec::new();
                tx.read_value(&h, &mut value).unwrap();
                rows.push((h, value));
            }
        }
    }
    rows
}
fn ino(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}
fn copy_dir(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}
fn pending(db: &sqlite::Sqlite) -> Option<u64> {
    db.read_control::<u64>("erasure_pending").unwrap()
}

/// A later load cold-opens `path` (the faulted store is already dropped): the
/// rows, identity and debt are as before the fault. The next attempt
/// completes, removes every remnant and publishes a new WAL-mode inode that a
/// cold open accepts with the same rows.
fn next_attempt(path: &Path, identity: &Identity, before: &[(Header, Vec<u8>)], row: &str) {
    let inode = ino(path);
    let mut db = sqlite::Sqlite::open(path, identity).unwrap();
    assert_eq!(dump(&mut db), before, "{row}: rows after the fault");
    let stored = db.read_control::<Identity>("identity").unwrap();
    assert_eq!(stored.as_ref(), Some(identity), "{row}: identity");
    assert_eq!(pending(&db), Some(EPOCH), "{row}: no false completion");
    attempt(&mut db).unwrap();
    assert_eq!(pending(&db), Some(0), "{row}: completed");
    for suffix in REMNANTS {
        assert!(
            !sqlite::sidecar(path, suffix).exists(),
            "{row}: {suffix} remains"
        );
    }
    assert_ne!(ino(path), inode, "{row}: a new file");
    let header = fs::read(path).unwrap();
    assert_eq!(header[18..20], [2, 2], "{row}: WAL header");
    drop(db);
    let mut db = sqlite::Sqlite::open(path, identity).unwrap();
    assert_eq!(dump(&mut db), before, "{row}: rows after the swap");
}

/// [behaviour] Each source × fault point keeps the rows (graph, Tail, upload
/// progress and its accepted ledger, logical controls), identity and debt;
/// grants no completion; and the next attempt removes the remnant, completes
/// and publishes a file a cold open accepts. The faulted store is dropped
/// first, so every retry runs on a freshly opened store. Every row except
/// `reopen` also retries on a directory copy taken at the fault.
#[test]
fn erasure_swap_faults_keep_custody_for_every_source() {
    // (row, seam, post-close: the store must reload)
    // `close` is W2: the seam fails just before `Connection::close` (not a
    // real close error), with the copy validated and the store still open.
    const ROWS: [(&str, Option<&str>, bool); 7] = [
        ("W1", None, false),
        ("W2b", Some("W2b"), false),
        ("close", Some("close"), true),
        ("W3", Some("W3"), true),
        ("W4", Some("W4"), true),
        ("reopen", Some("W4"), true),
        ("W5", None, false),
    ];
    for (source, _) in super::codex_on_tests::fixtures() {
        for (name, seam, reload) in ROWS {
            let row = format!("{source:?} {name}");
            let dir = ScratchDir::canonical("vacuum-swap");
            let image = ScratchDir::canonical("vacuum-swap-crash");
            let (mut db, path, identity) = store(source, &dir);
            let before = dump(&mut db);
            let crash = image.join("state.v2.sqlite");
            let to = image.to_path_buf();
            match (name, seam) {
                // A crash during the copy leaves a partial copy and journal.
                ("W1", _) => {
                    for suffix in [".vacuum", ".vacuum-journal"] {
                        fs::write(sqlite::sidecar(&path, suffix), b"partial copy").unwrap();
                    }
                    copy_dir(&dir, &to);
                }
                // Published, then a crash before the completion commit.
                ("W5", _) => {
                    let result = db.checkpoint(CheckpointMode::Purge);
                    assert_eq!(result.state, CheckpointState::Complete, "{row}");
                    copy_dir(&dir, &to);
                }
                (_, Some(seam)) => {
                    sqlite::on_swap(seam, move |tmp| {
                        match name {
                            // A stale copy WAL must never reach the store name.
                            "W2b" => fs::write(sqlite::sidecar(tmp, "-wal"), b"stale").unwrap(),
                            // The rename is done; the reopen is refused once.
                            // No crash image: it returns before the copy.
                            "reopen" => {
                                let path = tmp.with_extension("");
                                fs::set_permissions(path, fs::Permissions::from_mode(0o644))
                                    .unwrap();
                                return Ok(());
                            }
                            _ => {}
                        }
                        copy_dir(tmp.parent().unwrap(), &to);
                        anyhow::ensure!(name == "W2b", "test: fault at {name}");
                        Ok(())
                    });
                    assert_eq!(attempt(&mut db).is_err(), reload, "{row}: attempt");
                    assert_eq!(db.reload_required(), reload, "{row}: reload");
                    if !reload {
                        for suffix in REMNANTS {
                            assert!(!sqlite::sidecar(&path, suffix).exists(), "{row}: {suffix}");
                        }
                    }
                }
                _ => unreachable!(),
            }
            if !reload {
                assert_eq!(pending(&db), Some(EPOCH), "{row}: no false completion");
            }
            drop(db);
            if name == "reopen" {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            next_attempt(&path, &identity, &before, &row);
            if crash.exists() {
                next_attempt(&crash, &identity, &before, &format!("{row} crash image"));
            }
        }
    }
}

/// [behaviour] Space admission is one copy plus 1 GiB, not two copies.
#[test]
fn erasure_swap_admits_one_copy_plus_reserve() {
    const GIB: u64 = 1 << 30;
    let dir = ScratchDir::canonical("vacuum-swap-space");
    let (mut db, path, _) = store(Source::Claude, &dir);
    // After a complete idle TRUNCATE the logical size is the file size.
    let idle = db.checkpoint(CheckpointMode::IdleReclaim);
    assert_eq!(idle.state, CheckpointState::Complete);
    sqlite::set_space_reader(
        &mut db,
        Some(|p| Some(fs::metadata(p).ok()?.len() + GIB - 1)),
    );
    let refused = db.checkpoint(CheckpointMode::Purge);
    assert_eq!(refused.state, CheckpointState::Failed);
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["free_space_admitted"], false);
    let file = fs::metadata(&path).unwrap().len();
    assert_eq!(stats["free_space_required_bytes"], file + GIB);
    assert!(!sqlite::sidecar(&path, ".vacuum").exists());
    sqlite::set_space_reader(&mut db, Some(|p| Some(fs::metadata(p).ok()?.len() + GIB)));
    let admitted = db.checkpoint(CheckpointMode::Purge);
    assert_eq!(admitted.state, CheckpointState::Complete);
}

/// [behaviour] A busy TRUNCATE fails before any copy exists; the separate
/// upload history file is never touched.
#[test]
fn erasure_swap_busy_truncate_fails_before_the_copy() {
    let dir = ScratchDir::canonical("vacuum-swap-busy");
    let (mut db, path, _) = store(Source::Codex, &dir);
    let history = dir.join(sqlite::history::FILE_NAME);
    fs::write(&history, b"history rows").unwrap();
    let history_inode = ino(&history);
    assert_eq!(attempt(&mut db).map(|()| pending(&db)).unwrap(), Some(0));
    // Another writer keeps TRUNCATE from completing.
    db.control("erasure_pending", &EPOCH).unwrap();
    let writer = rusqlite::Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let busy = db.checkpoint(CheckpointMode::Purge);
    assert_eq!(busy.state, CheckpointState::Busy);
    assert!(!sqlite::sidecar(&path, ".vacuum").exists());
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_vacuum_failed"]["busy"], 1);
    assert_eq!(stats["vacuum_failures"], 0);
    drop(writer);
    assert_eq!(fs::read(&history).unwrap(), b"history rows");
    assert_eq!(ino(&history), history_inode);
}
