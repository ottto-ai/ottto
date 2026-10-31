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
//! `-wal` appears; `verify` checks that after the rows are read and before the
//! caller uses them.

use super::state_v2::{sidecar, sqlite_uri};
use crate::transcript_acquisition::FileStamp;
use anyhow::Result;
use rusqlite::{Connection, OpenFlags};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

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
    /// `flags` must be read-only; a snapshot adds `SQLITE_OPEN_URI`.
    pub(crate) fn open(path: &Path, flags: OpenFlags) -> Result<Self> {
        let Some(stamp) = idle_wal_stamp(path) else {
            return Ok(Self {
                connection: Connection::open_with_flags(path, flags)?,
                snapshot: None,
            });
        };
        let connection =
            Connection::open_with_flags(sqlite_uri(path)?, flags | OpenFlags::SQLITE_OPEN_URI)?;
        Ok(Self {
            connection,
            snapshot: Some((path.to_path_buf(), stamp)),
        })
    }

    pub(crate) fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    /// Ok when every row read so far is current: always for a plain open. A
    /// snapshot the database moved past fails as busy, so the caller keeps
    /// the read failed and retries it on a later pass.
    pub(crate) fn verify(&self) -> Result<()> {
        let Some((path, before)) = &self.snapshot else {
            return Ok(());
        };
        let unchanged = wal_absent(path)
            && fs::metadata(path)
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
    let stamp = FileStamp::capture(fs::metadata(path).ok()?).ok()?;
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
