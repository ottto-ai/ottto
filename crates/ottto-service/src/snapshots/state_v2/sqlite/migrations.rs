//! Forward-only, append-only on-device steps. Identity.format is custody format,
//! never schema revision. Future fixed columns must be nullable and must not
//! enter canonical row digests until non-NULL. Never edit/reuse a shipped step.
use super::*;

pub(super) const REVISION: u32 = 1;
struct Step {
    to: u32,
    apply: fn(&Connection) -> Result<()>,
}
const STEPS: &[Step] = &[Step {
    to: 1,
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
fn supported(conn: &Connection) -> Result<u32> {
    let revision = revision(conn)?;
    if revision > REVISION {
        super::super::telemetry::event("newer_schema_refused", &1);
        bail!(super::super::Hold::NewerSchema);
    }
    Ok(revision)
}
/// Used for EVERY explicit write, including N-only maintenance markers.
pub(super) fn begin_write(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match supported(conn) {
        Ok(REVISION) => Ok(()),
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
pub(super) fn run(conn: &Connection) -> Result<()> {
    supported(conn)?;
    for step in STEPS {
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
fn busy_migration_is_named_and_preserves_revision() {
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
        run(&first)
            .unwrap_err()
            .downcast_ref::<super::super::Hold>(),
        Some(&super::super::Hold::MigrationFailed)
    );
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
