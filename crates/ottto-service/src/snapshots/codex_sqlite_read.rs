//! Read-only opens of Codex-owned SQLite databases that never write beside
//! them.
//!
//! The path is resolved once, so a symlinked database is read, checked and
//! verified through its target, beside which SQLite keeps the `-wal`.
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
//! An idle-looking WAL database with a second hard link is refused for good:
//! its live `-wal` may sit beside another name.
//!
//! Every other database takes the plain open, with `readonly_shm` so SQLite
//! never creates, truncates or marks the `-shm`, through a VFS that never
//! creates a `-wal`. A `-wal` that Codex removes after the idle check fails
//! the open CANTOPEN instead of coming back empty, and the caller's retry
//! reads the database as a snapshot. A `-wal` without its `-shm` also fails
//! CANTOPEN.

use super::state_v2::{sidecar, sqlite_uri};
use crate::codex_scan_diagnostics::{LinkedDatabase, LoaderStage};
use crate::transcript_acquisition::FileStamp;
use anyhow::{Context, Result};
use rusqlite::{ffi, Connection, OpenFlags};
use std::ffi::{c_char, c_int, CStr};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// rusqlite's busy timeout for a new connection, restored after the probe.
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The VFS every open here uses: the default "unix" VFS, except that it
/// never creates a `-wal`. URI-safe, so it goes into the query unencoded.
const NO_WAL_CREATE_VFS: &CStr = c"ottto-codex-read";

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
        // A path that can't be resolved is opened as given; SQLite reports it.
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let route = route(&path);
        Self::open_routed(&path, route, flags)
    }

    fn open_routed(path: &Path, route: Route, flags: OpenFlags) -> Result<Self> {
        let stamp = match route {
            Route::Snapshot(stamp) => Some(stamp),
            Route::Plain => None,
            Route::Unreadable => return Err(moved()).context(LoaderStage::Open),
            Route::Linked => {
                return Err(anyhow::Error::new(LinkedDatabase)).context(LoaderStage::Open)
            }
        };
        let vfs = no_wal_create_vfs().context(LoaderStage::Open)?;
        let query = if stamp.is_some() {
            format!("mode=ro&immutable=1&vfs={vfs}")
        } else {
            format!("mode=ro&readonly_shm=1&vfs={vfs}")
        };
        let uri = sqlite_uri(path, &query).context(LoaderStage::Open)?;
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
        Err(moved())
    }
}

fn moved() -> anyhow::Error {
    rusqlite::Error::SqliteFailure(
        ffi::Error::new(ffi::SQLITE_BUSY),
        Some("database not readable as a current snapshot".to_string()),
    )
    .into()
}

enum Route {
    Snapshot(FileStamp),
    Plain,
    /// The header could not be read: fail closed, retried as busy.
    Unreadable,
    /// An idle-looking WAL database with another hard link: refused for good.
    Linked,
}

/// `Snapshot` for a WAL-mode database with no `-wal` and one name; `Linked`
/// for one with another hard link, whose live `-wal` may sit beside a name
/// not checked here. Every other database takes the plain open, as does one
/// that can't be inspected: SQLite reports what it can't open, and the plain
/// open creates nothing.
fn route(path: &Path) -> Route {
    if !wal_absent(path) {
        return Route::Plain;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Route::Plain;
    };
    if !metadata.is_file() {
        return Route::Plain;
    }
    let Ok(mut file) = File::open(path) else {
        return Route::Plain;
    };
    // Header bytes 18 and 19 are the file format write and read versions;
    // 2 means WAL. A file shorter than the header is not a WAL database. A
    // rollback-journal database keeps the plain open, which honours a hot
    // journal.
    let mut header = [0_u8; 20];
    if let Err(error) = file.read_exact(&mut header) {
        if error.kind() == ErrorKind::UnexpectedEof {
            return Route::Plain;
        }
        return Route::Unreadable;
    }
    if header[18] != 2 || header[19] != 2 {
        return Route::Plain;
    }
    if metadata.nlink() != 1 {
        return Route::Linked;
    }
    FileStamp::capture(metadata).map_or(Route::Plain, Route::Snapshot)
}

fn wal_absent(path: &Path) -> bool {
    matches!(
        fs::symlink_metadata(sidecar(path, "-wal")),
        Err(error) if error.kind() == ErrorKind::NotFound
    )
}

/// The default "unix" VFS, which this process's SQLite opens every file
/// through, kept for the delegating `xOpen`.
static UNIX_VFS: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(std::ptr::null_mut());

/// Register the VFS once per process and return its name.
fn no_wal_create_vfs() -> Result<&'static str> {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let registered = *REGISTERED.get_or_init(|| {
        // SAFETY: `sqlite3_vfs_find` initialises SQLite if needed and returns
        // a registered VFS or null. Built-in VFS objects are static.
        let unix = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
        if unix.is_null() {
            return false;
        }
        UNIX_VFS.store(unix, Ordering::Release);
        // SAFETY: `unix` is a live VFS object. The copy keeps its file size,
        // methods and app data; only its name, list link and `xOpen` change.
        let mut vfs = unsafe { *unix };
        vfs.zName = NO_WAL_CREATE_VFS.as_ptr();
        vfs.pNext = std::ptr::null_mut();
        vfs.xOpen = Some(open_without_wal_create);
        let vfs: &'static mut ffi::sqlite3_vfs = Box::leak(Box::new(vfs));
        // SAFETY: `vfs` is a complete VFS object that lives for the process,
        // registered once (not as the default) after `UNIX_VFS` is set.
        unsafe { ffi::sqlite3_vfs_register(vfs, 0) == ffi::SQLITE_OK }
    });
    anyhow::ensure!(registered, "codex_sqlite_vfs_unavailable");
    NO_WAL_CREATE_VFS
        .to_str()
        .context("codex_sqlite_vfs_unavailable")
}

/// `xOpen` of the default VFS, without `SQLITE_OPEN_CREATE` for a `-wal`.
/// SQLite opens every `-wal` read-write with create, even on a read-only
/// connection. Without create, an existing `-wal` opens as before and a
/// missing one fails CANTOPEN (the read-only retry finds no file either).
/// Read-write is kept: the default VFS allows it without create. A read-only
/// connection opens no other file that it could create: a rollback journal
/// is created only by a write transaction, and the `-shm` open is skipped
/// under `readonly_shm`.
unsafe extern "C" fn open_without_wal_create(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let flags = if flags & ffi::SQLITE_OPEN_WAL != 0 {
        flags & !ffi::SQLITE_OPEN_CREATE
    } else {
        flags
    };
    let unix = UNIX_VFS.load(Ordering::Acquire);
    // SAFETY: this VFS is registered only after `UNIX_VFS` holds the live
    // default VFS, whose file size this VFS copied, so `file` fits its file
    // object. Every argument is SQLite's own, passed through unchanged but
    // for the cleared create flag.
    unsafe {
        match (*unix).xOpen {
            Some(open) => open(unix, name, file, flags, out_flags),
            None => ffi::SQLITE_CANTOPEN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wal_and_shm_exist(path: &Path) -> [bool; 2] {
        ["-wal", "-shm"].map(|suffix| sidecar(path, suffix).exists())
    }

    /// [regress] A database chosen for the plain open while its `-wal`
    /// existed, whose Codex connection then closed (checkpoint, `-wal` and
    /// `-shm` removed) before the first statement, got an empty `-wal`
    /// created beside it. The same plain open is the fallback when a path
    /// can't be inspected. It now fails CANTOPEN with nothing created, even
    /// in a writable directory, and the retry reads the snapshot.
    #[cfg(unix)]
    #[test]
    fn plain_open_of_a_database_gone_idle_creates_no_wal() {
        let dir = crate::test_scratch::unique_path("ottto-codex-plain-open-no-wal");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let path = fs::canonicalize(&dir)
            .expect("resolve fixture dir")
            .join("state.sqlite");
        let writer = Connection::open(&path).expect("open fixture writer");
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL;\
                 CREATE TABLE fixture (value INTEGER);\
                 INSERT INTO fixture VALUES (7);",
            )
            .expect("seed fixture");
        let route = route(&path);
        assert!(matches!(route, Route::Plain));
        drop(writer);
        assert_eq!(wal_and_shm_exist(&path), [false, false]);

        let Err(error) =
            CodexSqliteRead::open_routed(&path, route, OpenFlags::SQLITE_OPEN_READ_ONLY)
        else {
            panic!("plain open of an idle WAL database succeeded");
        };
        assert!(matches!(
            error.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(failure, _))
                if failure.code == rusqlite::ErrorCode::CannotOpen
        ));
        assert_eq!(wal_and_shm_exist(&path), [false, false]);

        let retry = CodexSqliteRead::open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("retry reads the snapshot");
        assert!(retry.is_snapshot());
        let value = retry
            .read(|connection| {
                Ok(connection
                    .query_row("SELECT value FROM fixture", [], |row| row.get::<_, i64>(0))?)
            })
            .expect("read snapshot row");
        assert_eq!(value, 7);
        drop(retry);
        assert_eq!(wal_and_shm_exist(&path), [false, false]);
        let _ = fs::remove_dir_all(dir);
    }
}
