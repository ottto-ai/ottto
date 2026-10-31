//! Read-only opens of Codex-owned SQLite databases that never write beside
//! them.
//!
//! An idle WAL-mode database has no `-wal`: its last connection checkpointed
//! every frame into the main file and removed the `-wal` and `-shm`. A plain
//! read-only open of it must create both files in the Codex home, or fails
//! where it cannot (CANTOPEN or READONLY_DIRECTORY at the first statement, on
//! every attempt). Such a database is instead read as an immutable snapshot of
//! the main file, without locks, `-wal` or `-shm`. The snapshot is current
//! only while the main file stays the same object, length and mtime and no
//! `-wal` appears; `read` checks that after the rows are read and before the
//! caller uses them. The check relies on the filesystem's mtime resolution.
//!
//! Every other database takes the plain open with `readonly_shm`, so SQLite
//! never creates, truncates or marks the `-shm`; a `-wal` without its `-shm`
//! fails CANTOPEN, which the caller retries. A plain open still creates an
//! empty `-wal` if Codex removes it after the idle check and before the first
//! statement's lock: the schema probe never waits on a lock, so a closing
//! Codex makes it fail busy and the caller re-checks instead.

use super::state_v2::{sidecar, sqlite_uri};
use crate::codex_scan_diagnostics::LoaderStage;
use crate::transcript_acquisition::FileStamp;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// rusqlite's busy timeout for a new connection, restored after the probe.
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct CodexSqliteRead {
    connection: Connection,
    snapshot: Option<(PathBuf, FileStamp)>,
}

impl std::ops::Deref for CodexSqliteRead {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.connection
    }
}

impl CodexSqliteRead {
    /// Open and read the schema. `flags` must be read-only; `SQLITE_OPEN_URI`
    /// is added. A lock held by Codex fails the probe as busy at once.
    pub(crate) fn open(path: &Path, flags: OpenFlags) -> Result<Self> {
        let stamp = idle_wal_stamp(path);
        let uri = sqlite_uri(path).context(LoaderStage::Open)?;
        let uri = if stamp.is_some() {
            uri
        } else {
            let live = uri
                .strip_suffix("&immutable=1")
                .context("codex_sqlite_live_uri")
                .context(LoaderStage::Open)?;
            format!("{live}&readonly_shm=1")
        };
        let connection = Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)
            .context(LoaderStage::Open)?;
        connection
            .busy_timeout(Duration::ZERO)
            .context(LoaderStage::Open)?;
        let read = Self {
            connection,
            snapshot: stamp.map(|stamp| (path.to_path_buf(), stamp)),
        };
        read.read(|connection| {
            connection
                .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
                .context(LoaderStage::Prepare)
        })?;
        read.connection
            .busy_timeout(DEFAULT_BUSY_TIMEOUT)
            .context(LoaderStage::Open)?;
        Ok(read)
    }

    pub(crate) fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    /// Run `read` and keep its result only while every row it read is
    /// current. A snapshot the database moved past fails as busy whatever
    /// `read` returned, since moved pages can also look corrupt or reshaped.
    pub(crate) fn read<T>(&self, read: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let result = read(&self.connection);
        self.verify().context(LoaderStage::Row)?;
        result
    }

    /// Ok when every row read so far is current: always for a plain open. A
    /// snapshot the database moved past fails as busy, so the caller keeps
    /// the read failed and retries it on a later pass.
    pub(crate) fn verify(&self) -> Result<()> {
        let Some((path, before)) = &self.snapshot else {
            return Ok(());
        };
        let unchanged = wal_absent(path)
            && fs::symlink_metadata(path)
                .ok()
                .and_then(|metadata| FileStamp::capture(metadata).ok())
                .is_some_and(|after| after.same_content(before));
        if unchanged {
            return Ok(());
        }
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database changed during a snapshot read".to_string()),
        )
        .into())
    }
}

/// The main file's stamp when it is a WAL-mode database with no `-wal`;
/// `None` sends every other database, or one that can't be inspected, to the
/// plain open.
fn idle_wal_stamp(path: &Path) -> Option<FileStamp> {
    if !wal_absent(path) {
        return None;
    }
    // Only a regular file with one name: SQLite keeps the `-wal` beside a
    // symlink's target, and another hard link's name has its own `-wal`, so
    // a live WAL could hide from the check beside `path`.
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.nlink() != 1 {
        return None;
    }
    let stamp = FileStamp::capture(metadata).ok()?;
    // Header bytes 18 and 19 are the file format write and read versions;
    // 2 means WAL. A rollback-journal database keeps the plain open, which
    // honours a hot journal.
    let mut header = [0_u8; 20];
    File::open(path).ok()?.read_exact(&mut header).ok()?;
    (header[18] == 2 && header[19] == 2).then_some(stamp)
}

fn wal_absent(path: &Path) -> bool {
    matches!(
        fs::symlink_metadata(sidecar(path, "-wal")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}
