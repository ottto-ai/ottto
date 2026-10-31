//! Forward-only, append-only on-device steps. Identity.format is custody format,
//! never schema revision. Future fixed columns must be nullable and must not
//! enter canonical row digests until non-NULL. Never edit/reuse a shipped step.
use super::*;

pub(super) const REVISION: u32 = 1;
pub(super) const WRITER_CAPABILITY: u64 = 1;
struct Step {
    to: u32,
    apply: fn(&Connection) -> Result<()>,
}
const STEPS: &[Step] = &[Step {
    to: 1,
    apply: schema,
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
pub(super) fn run(conn: &Connection) -> Result<()> {
    if supported(conn)? > 0 {
        writer_supported(conn)?;
    }
    for step in STEPS {
        if revision(conn)? >= step.to {
            continue;
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
    /// [format] shipped revision fixtures match fresh and refuse old writers.
    #[test]
    fn shipped_revision_fixtures_match_fresh_and_refuse_old_writers() {
        let fresh = Connection::open_in_memory().unwrap();
        run(&fresh).unwrap();
        let fixture = Connection::open_in_memory().unwrap();
        schema(&fixture).unwrap();
        // A nonempty revision-zero database is never adopted, even when its
        // object set resembles revision one. Failed DDL leaves it intact.
        assert!(run(&fixture).is_err());
        assert_eq!(revision(&fixture).unwrap(), 0);
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
}

#[cfg(test)]
/// [format] migration crash child.
#[test]
fn migration_crash_child() {
    if let Some(path) = std::env::var_os("OTTTO_STATE_V2_MIGRATION_CRASH_FIXTURE") {
        let conn = Connection::open(path).unwrap();
        run(&conn).unwrap();
        panic!("fixture did not crash");
    }
}
#[cfg(test)]
/// [format] crash between ddl and revision bump rolls back on restart.
#[test]
fn crash_between_ddl_and_revision_bump_rolls_back_on_restart() {
    let dir = crate::test_scratch::canonical_private_dir("v2-migration-crash");
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
