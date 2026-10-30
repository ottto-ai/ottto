//! Forward-only, append-only on-device steps. Identity.format is custody format,
//! never schema revision. Future fixed columns must be nullable and must not
//! enter canonical row digests until non-NULL. Never edit/reuse a shipped step.
use super::*;

pub(super) const REVISION: u32 = 1;
pub(super) const WRITER_CAPABILITY: u64 = 1;
struct Step {
    to: u32,
    destructive: bool,
    apply: fn(&Connection) -> Result<()>,
}
const STEPS: &[Step] = &[Step {
    to: 1,
    destructive: false,
    apply: revision_one,
}];

pub(super) fn revision(conn: &Connection) -> Result<u32> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}
pub(super) fn check_current(conn: &Connection) -> Result<()> {
    ensure!(
        supported(conn)? == REVISION,
        super::super::Hold::MigrationFailed
    );
    Ok(())
}
pub(super) fn supported(conn: &Connection) -> Result<u32> {
    let revision = revision(conn)?;
    if revision > REVISION {
        super::super::telemetry::event("newer_schema_refused", &1);
        bail!(super::super::Hold::NewerSchema);
    }
    Ok(revision)
}
/// Independent of DDL revision: value-only upgrades fence old readers/writers.
pub(super) fn writer_supported(conn: &Connection) -> Result<()> {
    let minimum =
        read_json::<u64>(conn, &RowKey::Meta("minimum_writer_capability".into()))?.unwrap_or(0);
    if minimum > WRITER_CAPABILITY {
        super::super::telemetry::event("newer_writer_refused", &1);
        bail!(super::super::Hold::NewerSchema);
    }
    ensure!(
        read_json::<u64>(conn, &RowKey::Meta("reference_drift".into()))?.unwrap_or(0) == 0,
        super::super::Hold::ReferenceDrift
    );
    Ok(())
}
/// Used for EVERY explicit write, including N-only maintenance markers.
pub(super) fn begin_write(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match supported(conn) {
        Ok(REVISION) => match writer_supported(conn) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(error)
            }
        },
        result => {
            let _ = conn.execute_batch("ROLLBACK");
            result?;
            bail!(super::super::Hold::MigrationFailed)
        }
    }
}
fn revision_one(conn: &Connection) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
        [],
        |r| r.get(0),
    )?;
    // The unpublished foundation used user_version=0. Adopt only its exact
    // known schema; never raze, fill, or rebuild an unexpected object set.
    if exists {
        validate_schema_revision(conn, 1)
    } else {
        schema(conn)
    }
}
/// Called only with store inode ownership, before a destructive step begins.
/// Keep failed backups for explicit recovery; never replace or wipe evidence.
fn verified_backup(conn: &Connection) -> Result<()> {
    ensure!(
        read_json::<u64>(conn, &RowKey::Meta("erasure_pending".into()))?.unwrap_or(0) == 0,
        "state_v2_backup_erasure_pending"
    );
    let path = Path::new(conn.path().context("state_v2_backup_path")?);
    let (busy, log, done): (u64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    ensure!(
        busy == 0
            && log == done
            && fs::metadata(sidecar(path, "-wal")).map_or(true, |m| m.len() == 0),
        "state_v2_backup_checkpoint"
    );
    private_file(path)?;
    let target = sidecar(path, ".migration-backup");
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut backup = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&target)?;
    let before = source.metadata()?;
    let bytes = io::copy(&mut source, &mut backup)?;
    backup.sync_all()?;
    fn digest(file: &mut File) -> Result<[u8; 32]> {
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut hash = sha2::Sha256::new();
        let mut block = [0_u8; 64 * 1024];
        loop {
            let n = file.read(&mut block)?;
            if n == 0 {
                break;
            }
            hash.update(&block[..n]);
        }
        Ok(hash.finalize().into())
    }
    ensure!(
        digest(&mut source)? == digest(&mut backup)?,
        "state_v2_backup_digest"
    );
    let after = source.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes == before.len()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && named.dev() == before.dev()
            && named.ino() == before.ino(),
        "state_v2_backup_changed"
    );
    private_file(&target)?;
    super::super::super::sync_checkpoint_parent(&target)?;
    super::super::telemetry::event("migration_backup_count", &1);
    super::super::telemetry::event("migration_backup_bytes", &bytes);
    Ok(())
}

pub(super) fn run(conn: &Connection) -> Result<()> {
    if supported(conn)? > 0 {
        writer_supported(conn)?;
    }
    for step in STEPS {
        if revision(conn)? >= step.to {
            continue;
        }
        if step.destructive {
            let path = Path::new(conn.path().context("state_v2_backup_path")?);
            super::super::recovery_backup::require_destructive_backup(path)?;
            verified_backup(conn).map_err(|_| super::super::Hold::MigrationFailed)?;
        }
        if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
            super::super::telemetry::event(
                "migration",
                &serde_json::json!({"from":revision(conn)?,"to":step.to,"outcome":"busy_or_io"}),
            );
            bail!(super::super::Hold::MigrationFailed);
        }
        let started = Instant::now();
        let from = match supported(conn) {
            Ok(from) => from,
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        if from >= step.to {
            conn.execute_batch("ROLLBACK")?;
            continue;
        }
        let result = (|| {
            ensure!(from + 1 == step.to, "state_v2_migration_gap");
            (step.apply)(conn)?;
            #[cfg(test)]
            if std::env::var_os("OTTTO_STATE_V2_MIGRATION_CRASH_FIXTURE").is_some_and(|path| {
                conn.path()
                    .is_some_and(|name| path == std::ffi::OsStr::new(name))
            }) {
                // Child fixture only: simulate loss after DDL and before the
                // revision bump/COMMIT, with no destructor rollback help.
                unsafe {
                    libc::_exit(88);
                }
            }
            validate_schema_revision(conn, step.to)?;
            conn.pragma_update(None, "user_version", step.to)?;
            conn.execute_batch("COMMIT")?;
            Ok::<_, anyhow::Error>(())
        })();
        super::super::telemetry::event(
            "migration",
            &serde_json::json!({"from":from,"to":step.to,"outcome":if result.is_ok() {"ok"} else {"failed"}, "migration_ms":started.elapsed().as_millis()}),
        );
        let wal_bytes = conn.path().and_then(|p| {
            fs::metadata(sidecar(Path::new(p), "-wal"))
                .ok()
                .map(|m| m.len())
        });
        super::super::telemetry::event("migration_wal_peak_bytes", &wal_bytes);
        if result.is_err() {
            let _ = conn.execute_batch("ROLLBACK");
            bail!(super::super::Hold::MigrationFailed);
        }
    }
    super::super::telemetry::event("schema_revision", &revision(conn)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_revision_fixtures_match_fresh_and_refuse_old_writers() {
        let fresh = Connection::open_in_memory().unwrap();
        run(&fresh).unwrap();
        let fixture = Connection::open_in_memory().unwrap();
        schema(&fixture).unwrap();
        // Revision zero is only the unshipped foundation adoption fixture.
        run(&fixture).unwrap();
        for rev in 1..=REVISION {
            fixture.pragma_update(None, "user_version", rev).unwrap();
            run(&fixture).unwrap();
            validate_schema_revision(&fixture, REVISION).unwrap();
        }
        let ddl = |c: &Connection| -> Vec<String> {
            c.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(ddl(&fresh), ddl(&fixture));
        fixture
            .pragma_update(None, "user_version", REVISION + 1)
            .unwrap();
        assert!(begin_write(&fixture)
            .unwrap_err()
            .downcast_ref::<super::super::super::Hold>()
            .is_some());
        assert!(fixture.is_autocommit());
        assert_eq!(revision(&fixture).unwrap(), REVISION + 1);
    }
    #[test]
    fn rollback_and_disk_full_preserve_schema_and_revision() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        schema(&c).unwrap();
        c.pragma_update(None, "user_version", 1).unwrap();
        c.execute_batch("ROLLBACK").unwrap();
        assert_eq!(revision(&c).unwrap(), 0);
        c.execute_batch("PRAGMA page_size=512; PRAGMA max_page_count=1")
            .unwrap();
        assert!(run(&c).is_err());
        assert_eq!(revision(&c).unwrap(), 0);
        assert!(c.is_autocommit());
    }
}

#[cfg(test)]
#[test]
fn busy_writer_preserves_revision_and_leaves_no_transaction() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "v2-migration-busy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let first = Connection::open(&path).unwrap();
    run(&first).unwrap();
    let other = Connection::open(&path).unwrap();
    first.busy_timeout(Duration::from_millis(1)).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        begin_write(&first)
            .unwrap_err()
            .downcast_ref::<rusqlite::Error>()
            .unwrap()
            .sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy)
    );
    assert!(first.is_autocommit());
    assert_eq!(revision(&first).unwrap(), 1);
    other.execute_batch("ROLLBACK").unwrap();
    drop(other);
    drop(first);
    fs::remove_file(path).unwrap();
}

#[cfg(test)]
#[test]
fn migration_crash_child() {
    if let Some(path) = std::env::var_os("OTTTO_STATE_V2_MIGRATION_CRASH_FIXTURE") {
        let conn = Connection::open(path).unwrap();
        run(&conn).unwrap();
        panic!("fixture did not crash");
    }
}
#[cfg(test)]
#[test]
fn crash_between_ddl_and_revision_bump_rolls_back_on_restart() {
    let dir = std::env::temp_dir().join(format!("v2-migration-crash-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("fixture.sqlite");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "snapshots::state_v2::sqlite::migrations::migration_crash_child",
            "--nocapture",
        ])
        .env("OTTTO_STATE_V2_MIGRATION_CRASH_FIXTURE", &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(88));
    let conn = Connection::open(&path).unwrap();
    assert_eq!(revision(&conn).unwrap(), 0);
    run(&conn).unwrap();
    assert_eq!(revision(&conn).unwrap(), 1);
    validate_schema_revision(&conn, 1).unwrap();
    drop(conn);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(test)]
#[test]
fn destructive_backup_is_private_verified_and_never_overwritten() {
    let dir = std::env::temp_dir().join(format!("v2-backup-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("synthetic.sqlite");
    let owned = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    lock_owner(&owned).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    settings(&conn, false).unwrap();
    run(&conn).unwrap();
    verified_backup(&conn).unwrap();
    let backup = sidecar(&path, ".migration-backup");
    let bytes = fs::read(&backup).unwrap();
    assert_eq!(bytes, fs::read(&path).unwrap());
    assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o600);
    assert!(verified_backup(&conn).is_err());
    assert_eq!(fs::read(&backup).unwrap(), bytes);
    drop(conn);
    drop(owned);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(test)]
#[test]
fn revision_one_four_table_ddl_golden() {
    assert_eq!(
        format!(
            "{:x}",
            sha2::Sha256::digest(include_bytes!("migrations/revision_1.sql"))
        ),
        "5ea34633109a7ef0319c619d1393c744a834e52a07f2bdd86ec422fa8afa3e01"
    );
}
#[cfg(test)]
#[test]
fn superseded_unshipped_layout_is_refused_intact() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE meta(name TEXT PRIMARY KEY,value BLOB); PRAGMA user_version=1;")
        .unwrap();
    assert!(run(&c).is_err());
    assert_eq!(revision(&c).unwrap(), 1);
    assert!(c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='meta')",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
}
