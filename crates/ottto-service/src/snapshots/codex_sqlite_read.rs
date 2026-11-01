//! Read-only opens of Codex-owned SQLite databases that never write beside
//! them.
//!
//! Guard: every connection here goes through an allowlist VFS that denies
//! every mutating operation by mechanism. Opens are allowed only for the
//! read-only main file and an existing `-wal` (never created); every other
//! file type, create, delete-on-close and exclusive open is refused, as is an
//! open that SQLite would follow with a chmod or chown. Opened files are
//! wrapped: reads, shared locks, the read-only `-shm` mapping and read-only
//! file controls pass through; writes, truncates, syncs, write locks,
//! deletes, `-shm` growth, exclusive `-shm` locks and a writable `-shm`
//! mapping are refused, and anything else is refused by default. Temporary
//! storage stays in memory. Locking is always POSIX advisory locking, never
//! a lock file beside the database. A refused operation fails the read
//! closed; the caller's retry routes it again.
//!
//! The path is resolved once, so a symlinked database is read, checked and
//! verified through its target, beside which SQLite keeps the `-wal`. A
//! database with a second hard link is refused for good: its live `-wal` or
//! `-journal` may sit beside another name.
//!
//! An idle database has no `-wal` or `-journal`, so its main file is
//! complete: a WAL database's last connection checkpointed every frame and
//! removed the `-wal` and `-shm`. A plain read-only open of an idle WAL
//! database needs a `-wal` it may not create, so an idle database is read as
//! an immutable snapshot of the main file, without locks, `-wal` or `-shm`.
//! The snapshot is current only while the main file stays the same object
//! with one name, length and mtime and no `-wal` or `-journal` appears;
//! `read` checks that after the rows are read and before the caller uses
//! them. The check relies on the filesystem's mtime resolution.
//!
//! Every other database takes the plain open, with `readonly_shm`. A `-wal`
//! that Codex removes after the idle check fails the open CANTOPEN, and the
//! retry reads the database as a snapshot. A `-wal` without its `-shm` also
//! fails CANTOPEN.

use super::state_v2::{sidecar, sqlite_uri};
use crate::codex_scan_diagnostics::{LinkedDatabase, LoaderStage};
use crate::transcript_acquisition::FileStamp;
use anyhow::{Context, Result};
use rusqlite::{ffi, Connection, OpenFlags};
use std::ffi::{c_char, c_int, c_void, CStr, OsStr};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// rusqlite's busy timeout for a new connection, restored after the probe.
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The guard VFS. URI-safe, so it goes into the query unencoded.
const GUARD_VFS: &CStr = c"ottto-codex-read";

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
            Route::Linked => {
                return Err(anyhow::Error::new(LinkedDatabase)).context(LoaderStage::Open)
            }
        };
        let vfs = guard_vfs().context(LoaderStage::Open)?;
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
        connection
            .execute_batch("PRAGMA temp_store=MEMORY")
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
    /// snapshot is current while its file is still idle, has one name and
    /// has the same content stamp; otherwise it fails as busy, so the caller
    /// keeps the read failed and retries it on a later pass.
    pub(crate) fn verify(&self) -> Result<()> {
        let Some((path, before)) = &self.snapshot else {
            return Ok(());
        };
        if idle_stamp(path).is_some_and(|after| after.same_content(before)) {
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
    /// A database with another hard link: refused for good.
    Linked,
}

/// `Linked` for a regular file with another hard link; `Snapshot` for an
/// idle one with one name. Every other database takes the plain open, as
/// does one that can't be inspected: SQLite reports what it can't open.
fn route(path: &Path) -> Route {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Route::Plain;
    };
    if metadata.is_file() && metadata.nlink() != 1 {
        return Route::Linked;
    }
    idle_stamp(path).map_or(Route::Plain, Route::Snapshot)
}

/// The main file's stamp while it is a regular file with one name and no
/// `-wal` or `-journal` beside it.
fn idle_stamp(path: &Path) -> Option<FileStamp> {
    if !absent(&sidecar(path, "-wal")) || !absent(&sidecar(path, "-journal")) {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.nlink() != 1 {
        return None;
    }
    FileStamp::capture(metadata).ok()
}

fn absent(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(error) if error.kind() == ErrorKind::NotFound)
}

/// Bytes before the base VFS's own file object inside each guarded file.
const INNER_OFFSET: usize = 16;

/// A guarded file: its methods are `GUARD_IO`, and the base VFS's file
/// object follows at `INNER_OFFSET`.
#[repr(C)]
struct GuardFile {
    base: ffi::sqlite3_file,
    /// The main database's name for its `-shm` checks; null for a `-wal`.
    /// SQLite keeps the name valid until the file is closed.
    name: *const c_char,
}

const _: () = assert!(std::mem::size_of::<GuardFile>() <= INNER_OFFSET);

/// The base VFS the guard delegates allowed calls to: "unix-posix" where
/// SQLite registers it (macOS, whose default "unix" picks dot-file or proxy
/// locking, with lock files, on filesystems without POSIX locks), else
/// "unix", which always locks with POSIX locks. A filesystem without them
/// fails the lock, and so the read, closed.
static BASE_VFS: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(std::ptr::null_mut());

/// Register the guard VFS once per process and return its name.
fn guard_vfs() -> Result<&'static str> {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let registered = *REGISTERED.get_or_init(|| {
        // SAFETY: `sqlite3_vfs_find` initialises SQLite if needed and returns
        // a registered VFS or null. Built-in VFS objects are static.
        let base = [c"unix-posix", c"unix"]
            .into_iter()
            .map(|name| unsafe { ffi::sqlite3_vfs_find(name.as_ptr()) })
            .find(|base| !base.is_null())
            .unwrap_or(std::ptr::null_mut());
        if base.is_null() {
            return false;
        }
        BASE_VFS.store(base, Ordering::Release);
        // SAFETY: `base` is a live VFS object, only read here.
        let base = unsafe { &*base };
        let Some(size) = c_int::try_from(INNER_OFFSET)
            .ok()
            .and_then(|offset| base.szOsFile.checked_add(offset))
        else {
            return false;
        };
        // Every member is named, so a new one can't pass through unseen.
        // Version 2 leaves out the system-call overrides.
        let vfs = ffi::sqlite3_vfs {
            iVersion: 2,
            szOsFile: size,
            mxPathname: base.mxPathname,
            pNext: std::ptr::null_mut(),
            zName: GUARD_VFS.as_ptr(),
            pAppData: base.pAppData,
            xOpen: Some(guard_open),
            xDelete: Some(guard_delete),
            xAccess: base.xAccess,
            xFullPathname: base.xFullPathname,
            xDlOpen: base.xDlOpen,
            xDlError: base.xDlError,
            xDlSym: base.xDlSym,
            xDlClose: base.xDlClose,
            xRandomness: base.xRandomness,
            xSleep: base.xSleep,
            xCurrentTime: base.xCurrentTime,
            xGetLastError: base.xGetLastError,
            xCurrentTimeInt64: base.xCurrentTimeInt64,
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        };
        let vfs: &'static mut ffi::sqlite3_vfs = Box::leak(Box::new(vfs));
        // SAFETY: `vfs` is a complete VFS object that lives for the process,
        // registered once (not as the default) after `BASE_VFS` is set.
        unsafe { ffi::sqlite3_vfs_register(vfs, 0) == ffi::SQLITE_OK }
    });
    anyhow::ensure!(registered, "codex_sqlite_vfs_unavailable");
    GUARD_VFS.to_str().context("codex_sqlite_vfs_unavailable")
}

/// Bytes of a NUL-terminated name from SQLite, as a path.
///
/// # Safety
/// `name` must be null or point to a NUL-terminated string.
unsafe fn name_path<'a>(name: *const c_char) -> Option<&'a Path> {
    if name.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    Some(Path::new(OsStr::from_bytes(bytes)))
}

/// Whether SQLite can open this `-wal` or `-shm` without changing it. It
/// chmods an existing zero-length one whose mode differs from the main
/// file's, and chowns every one when running as root.
fn sidecar_open_changes_nothing(main: &Path, sidecar: &Path, missing_ok: bool) -> bool {
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    let Ok(main) = fs::metadata(main) else {
        return false;
    };
    match fs::symlink_metadata(sidecar) {
        Ok(file) => {
            file.is_file() && (file.len() != 0 || file.mode() & 0o777 == main.mode() & 0o777)
        }
        Err(error) => missing_ok && error.kind() == ErrorKind::NotFound,
    }
}

/// The flags to open with, or None to refuse: only the read-only main file
/// and an existing `-wal`. SQLite asks for every `-wal` read-write with
/// create; create is dropped, so a missing one fails CANTOPEN, and the
/// read-write descriptor can only be read through `GUARD_IO`.
///
/// # Safety
/// `name` must be null or point to a NUL-terminated string.
unsafe fn allowed_open(name: *const c_char, flags: c_int) -> Option<c_int> {
    // Auto-proxy would let the base pick proxy locking, with lock files.
    const REFUSED: c_int = ffi::SQLITE_OPEN_CREATE
        | ffi::SQLITE_OPEN_DELETEONCLOSE
        | ffi::SQLITE_OPEN_EXCLUSIVE
        | ffi::SQLITE_OPEN_AUTOPROXY;
    // SAFETY: the caller's guarantee.
    let path = unsafe { name_path(name) }?;
    match flags & 0x000F_FF00 {
        ffi::SQLITE_OPEN_MAIN_DB => (flags & ffi::SQLITE_OPEN_READONLY != 0
            && flags & (REFUSED | ffi::SQLITE_OPEN_READWRITE) == 0)
            .then_some(flags),
        ffi::SQLITE_OPEN_WAL => {
            let flags = flags & !ffi::SQLITE_OPEN_CREATE;
            let main = Path::new(OsStr::from_bytes(
                path.as_os_str().as_bytes().strip_suffix(b"-wal")?,
            ));
            (flags & REFUSED == 0 && sidecar_open_changes_nothing(main, path, true))
                .then_some(flags)
        }
        _ => None,
    }
}

fn inner_file(file: *mut ffi::sqlite3_file) -> *mut ffi::sqlite3_file {
    file.cast::<u8>().wrapping_add(INNER_OFFSET).cast()
}

unsafe extern "C" fn guard_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let guard = file.cast::<GuardFile>();
    // SAFETY: SQLite passes a file object of this VFS's `szOsFile` bytes,
    // which starts with a `GuardFile`, and a NUL-terminated name or null.
    unsafe {
        (*guard).base.pMethods = std::ptr::null();
        (*guard).name = std::ptr::null();
        let Some(flags) = allowed_open(name, flags) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let base = BASE_VFS.load(Ordering::Acquire);
        // `BASE_VFS` is set before this VFS is registered; the base file
        // object fits after `INNER_OFFSET`, as `szOsFile` was sized for it.
        let rc = match (*base).xOpen {
            Some(open) => open(base, name, inner_file(file), flags, out_flags),
            None => ffi::SQLITE_CANTOPEN,
        };
        if rc == ffi::SQLITE_OK {
            (*guard).base.pMethods = &GUARD_IO;
            if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
                (*guard).name = name;
            }
        }
        rc
    }
}

unsafe extern "C" fn guard_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    ffi::SQLITE_READONLY
}

/// The methods of every guarded file. Every member is named; version 2
/// leaves out memory-mapped reads.
static GUARD_IO: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write),
    xTruncate: Some(io_truncate),
    xSync: Some(io_sync),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock),
    xUnlock: Some(io_unlock),
    xCheckReservedLock: Some(io_check_reserved_lock),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: Some(io_shm_map),
    xShmLock: Some(io_shm_lock),
    xShmBarrier: Some(io_shm_barrier),
    xShmUnmap: Some(io_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};

/// A method that calls the base file object's own method.
macro_rules! pass_through {
    ($name:ident, $method:ident, ($($arg:ident: $ty:ty),*), $missing:expr) => {
        unsafe extern "C" fn $name(file: *mut ffi::sqlite3_file, $($arg: $ty),*) -> c_int {
            let inner = inner_file(file);
            // SAFETY: SQLite calls a file's methods only after its open
            // succeeded, so the base file object at `inner` is open and has
            // its own methods.
            unsafe {
                match (*(*inner).pMethods).$method {
                    Some(method) => method(inner, $($arg),*),
                    None => $missing,
                }
            }
        }
    };
}

pass_through!(io_close, xClose, (), ffi::SQLITE_OK);
pass_through!(io_read, xRead, (buffer: *mut c_void, amount: c_int, offset: ffi::sqlite3_int64), ffi::SQLITE_IOERR);
pass_through!(io_file_size, xFileSize, (size: *mut ffi::sqlite3_int64), ffi::SQLITE_IOERR);
pass_through!(base_lock, xLock, (level: c_int), ffi::SQLITE_IOERR);
pass_through!(io_unlock, xUnlock, (level: c_int), ffi::SQLITE_IOERR);
pass_through!(io_check_reserved_lock, xCheckReservedLock, (reserved: *mut c_int), ffi::SQLITE_IOERR);
pass_through!(base_file_control, xFileControl, (op: c_int, argument: *mut c_void), ffi::SQLITE_NOTFOUND);
pass_through!(io_sector_size, xSectorSize, (), 0);
pass_through!(io_device_characteristics, xDeviceCharacteristics, (), 0);
pass_through!(base_shm_map, xShmMap, (page: c_int, size: c_int, extend: c_int, map: *mut *mut c_void), ffi::SQLITE_IOERR);
pass_through!(base_shm_lock, xShmLock, (offset: c_int, count: c_int, flags: c_int), ffi::SQLITE_IOERR);
pass_through!(base_shm_unmap, xShmUnmap, (delete: c_int), ffi::SQLITE_OK);

unsafe extern "C" fn io_write(
    _file: *mut ffi::sqlite3_file,
    _buffer: *const c_void,
    _amount: c_int,
    _offset: ffi::sqlite3_int64,
) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn io_truncate(
    _file: *mut ffi::sqlite3_file,
    _size: ffi::sqlite3_int64,
) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn io_sync(_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_READONLY
}

/// Shared locks only: a reader never needs more, and a reserved, pending or
/// exclusive lock precedes every write, checkpoint and journal delete.
unsafe extern "C" fn io_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    if level != ffi::SQLITE_LOCK_SHARED {
        return ffi::SQLITE_READONLY;
    }
    // SAFETY: SQLite's own call, passed through unchanged.
    unsafe { base_lock(file, level) }
}

/// Read-only file controls; anything else is not handled.
unsafe extern "C" fn io_file_control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    argument: *mut c_void,
) -> c_int {
    match op {
        ffi::SQLITE_FCNTL_LOCKSTATE
        | ffi::SQLITE_FCNTL_LAST_ERRNO
        | ffi::SQLITE_FCNTL_VFSNAME
        | ffi::SQLITE_FCNTL_HAS_MOVED => {
            // SAFETY: SQLite's own call, passed through unchanged.
            unsafe { base_file_control(file, op, argument) }
        }
        _ => ffi::SQLITE_NOTFOUND,
    }
}

/// Map the `-shm` read-only or refuse. The open must carry `readonly_shm`,
/// so SQLite never opens the `-shm` read-write, creates or truncates it. It
/// must exist and be unchanged by its open, and is never grown. A mapping
/// that comes back writable, because another connection in this process
/// opened the `-shm` read-write, is refused: this reader would mark it.
unsafe extern "C" fn io_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    size: c_int,
    extend: c_int,
    map: *mut *mut c_void,
) -> c_int {
    // SAFETY: SQLite passes a guarded main-database file and an out-pointer.
    unsafe {
        *map = std::ptr::null_mut();
        let name = (*file.cast::<GuardFile>()).name;
        let readonly_shm =
            !name.is_null() && ffi::sqlite3_uri_boolean(name, c"readonly_shm".as_ptr(), 0) != 0;
        let unchanged = name_path(name)
            .is_some_and(|main| sidecar_open_changes_nothing(main, &sidecar(main, "-shm"), false));
        if extend != 0 || !readonly_shm || !unchanged {
            return ffi::SQLITE_CANTOPEN;
        }
        let rc = base_shm_map(file, page, size, extend, map);
        if rc == ffi::SQLITE_OK {
            *map = std::ptr::null_mut();
            return ffi::SQLITE_CANTOPEN;
        }
        rc
    }
}

/// Shared `-shm` locks and every unlock; an exclusive lock precedes every
/// `-shm` write.
unsafe extern "C" fn io_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    if flags == ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE {
        return ffi::SQLITE_READONLY;
    }
    // SAFETY: SQLite's own call, passed through unchanged.
    unsafe { base_shm_lock(file, offset, count, flags) }
}

unsafe extern "C" fn io_shm_barrier(file: *mut ffi::sqlite3_file) {
    let inner = inner_file(file);
    // SAFETY: as in `pass_through!`.
    unsafe {
        if let Some(barrier) = (*(*inner).pMethods).xShmBarrier {
            barrier(inner);
        }
    }
}

/// Unmap without ever deleting the `-shm`.
unsafe extern "C" fn io_shm_unmap(file: *mut ffi::sqlite3_file, _delete: c_int) -> c_int {
    // SAFETY: SQLite's own call, with deletion turned off.
    unsafe { base_shm_unmap(file, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Debug, PartialEq)]
    struct Entry {
        len: u64,
        mtime: (i64, i64),
        mode: u32,
        bytes: Vec<u8>,
    }

    /// Every entry of `dir` with its size, mtime, mode and bytes, and the
    /// directory's own mtime.
    fn home_state(dir: &Path) -> (BTreeMap<OsString, Entry>, (i64, i64)) {
        let entries = fs::read_dir(dir)
            .expect("list home")
            .map(|entry| {
                let entry = entry.expect("read home entry");
                let metadata = fs::symlink_metadata(entry.path()).expect("stat home entry");
                let state = Entry {
                    len: metadata.len(),
                    mtime: (metadata.mtime(), metadata.mtime_nsec()),
                    mode: metadata.mode(),
                    bytes: fs::read(entry.path()).expect("read home entry"),
                };
                (entry.file_name(), state)
            })
            .collect();
        let metadata = fs::metadata(dir).expect("stat home");
        (entries, (metadata.mtime(), metadata.mtime_nsec()))
    }

    fn wal_database(path: &Path, value: i64) -> Connection {
        let writer = Connection::open(path).expect("open fixture writer");
        writer
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL;\
                 PRAGMA wal_autocheckpoint=0;\
                 CREATE TABLE fixture (value INTEGER);\
                 INSERT INTO fixture VALUES ({value});"
            ))
            .expect("seed fixture");
        writer
    }

    fn value(read: &CodexSqliteRead) -> Result<i64> {
        read.read(|connection| {
            Ok(connection.query_row("SELECT value FROM fixture", [], |row| row.get(0))?)
        })
    }

    /// [regress] Every class of mutating operation, driven through the
    /// shared opener and the guard against a scratch Codex home, leaves the
    /// home byte-identical (entries, sizes, mtimes, modes, bytes):
    /// - a `-wal` Codex removed after the idle check (a plain open would
    ///   create it), refused CANTOPEN, after which the retry snapshots;
    /// - a `-wal` beside an empty main file (SQLite would delete it);
    /// - a zero-length `-wal` or `-shm` whose mode differs from the main
    ///   file's (SQLite would chmod it on open);
    /// - a `-wal` without its `-shm` (SQLite would create it);
    /// - on an open live database: writes, truncates, syncs, write locks,
    ///   `-shm` growth and exclusive `-shm` locks on the main file and the
    ///   `-wal`, and unhandled file controls;
    /// - create, journal and temporary opens and a delete through the VFS;
    /// - and temporary storage held in memory.
    #[cfg(unix)]
    #[test]
    fn guarded_reads_leave_the_codex_home_byte_identical() {
        let scratch = crate::test_scratch::unique_path("ottto-codex-sqlite-guard");
        let [home, work] = ["home", "work"].map(|name| scratch.join(name));
        for dir in [&home, &work] {
            fs::create_dir_all(dir).expect("create fixture dir");
        }
        let home = fs::canonicalize(&home).expect("resolve fixture home");
        let at = |name: &str| home.join(name);
        let set_mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode")
        };

        // A live database outside the home (value 8 only in its `-wal`),
        // copied in with and without its `-shm`; the copies have no
        // connection attached.
        let source = work.join("source.sqlite");
        let writer = wal_database(&source, 7);
        writer
            .execute_batch("UPDATE fixture SET value = 8;")
            .expect("write an uncheckpointed frame");
        for (name, suffixes) in [
            ("live.sqlite", &["", "-wal", "-shm"][..]),
            ("bare.sqlite", &["", "-wal"][..]),
        ] {
            for suffix in suffixes {
                fs::copy(sidecar(&source, suffix), sidecar(&at(name), suffix))
                    .expect("copy live fixture");
            }
        }
        fs::copy(
            sidecar(&source, "-wal"),
            sidecar(&at("empty.sqlite"), "-wal"),
        )
        .expect("copy -wal beside an empty main file");
        fs::write(at("empty.sqlite"), b"").expect("write empty main file");
        for (name, wal_mode, shm_mode) in [
            ("wal-mode.sqlite", Some(0o600), None),
            ("shm-mode.sqlite", Some(0o644), Some(0o600)),
        ] {
            fs::copy(&source, at(name)).expect("copy main file");
            set_mode(&at(name), 0o644);
            for (suffix, mode) in [("-wal", wal_mode), ("-shm", shm_mode)] {
                if let Some(mode) = mode {
                    fs::write(sidecar(&at(name), suffix), b"").expect("write empty sidecar");
                    set_mode(&sidecar(&at(name), suffix), mode);
                }
            }
        }
        drop(writer);
        drop(wal_database(&at("idle.sqlite"), 5));
        let raced_writer = wal_database(&at("raced.sqlite"), 6);
        let raced = route(&at("raced.sqlite"));
        assert!(matches!(raced, Route::Plain));
        drop(raced_writer);

        let before = home_state(&home);
        let open = |name: &str| CodexSqliteRead::open(&at(name), OpenFlags::SQLITE_OPEN_READ_ONLY);

        let Err(error) = CodexSqliteRead::open_routed(
            &at("raced.sqlite"),
            raced,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) else {
            panic!("plain open of a database gone idle succeeded");
        };
        assert!(matches!(
            error.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(failure, _))
                if failure.code == rusqlite::ErrorCode::CannotOpen
        ));
        let retry = open("raced.sqlite").expect("retry reads the snapshot");
        assert!(retry.is_snapshot());
        assert_eq!(value(&retry).expect("read raced snapshot"), 6);
        let idle = open("idle.sqlite").expect("open idle snapshot");
        assert!(idle.is_snapshot());
        assert_eq!(value(&idle).expect("read idle snapshot"), 5);
        for name in [
            "empty.sqlite",
            "wal-mode.sqlite",
            "shm-mode.sqlite",
            "bare.sqlite",
        ] {
            assert!(open(name).is_err(), "{name} opened");
        }

        let live = open("live.sqlite").expect("open live copy");
        assert!(!live.is_snapshot());
        assert_eq!(value(&live).expect("read live copy"), 8);
        let temp_store: i64 = live
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .expect("read temp_store");
        assert_eq!(temp_store, 2);
        for op in [
            ffi::SQLITE_FCNTL_FILE_POINTER,
            ffi::SQLITE_FCNTL_JOURNAL_POINTER,
        ] {
            let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
            // SAFETY: the connection is open; both controls store a file
            // pointer the connection keeps open, the second its `-wal`.
            let rc = unsafe {
                ffi::sqlite3_file_control(
                    live.handle(),
                    c"main".as_ptr(),
                    op,
                    std::ptr::addr_of_mut!(file).cast(),
                )
            };
            assert_eq!(rc, ffi::SQLITE_OK);
            assert!(!file.is_null());
            // SAFETY: `file` points to a file object the connection owns.
            assert!(!unsafe { (*file).pMethods }.is_null(), "file not open");
            let mut map: *mut c_void = std::ptr::null_mut();
            let mut hint: ffi::sqlite3_int64 = 1 << 20;
            // SAFETY: `file` is a guarded file open on `live`, and every
            // argument is valid for its method.
            let results = unsafe {
                let methods = &*(*file).pMethods;
                [
                    methods.xWrite.unwrap()(file, b"x".as_ptr().cast(), 1, 0),
                    methods.xTruncate.unwrap()(file, 0),
                    methods.xSync.unwrap()(file, ffi::SQLITE_SYNC_NORMAL),
                    methods.xLock.unwrap()(file, ffi::SQLITE_LOCK_RESERVED),
                    methods.xLock.unwrap()(file, ffi::SQLITE_LOCK_EXCLUSIVE),
                    methods.xShmMap.unwrap()(file, 0, 32768, 1, &mut map),
                    methods.xShmLock.unwrap()(
                        file,
                        0,
                        1,
                        ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE,
                    ),
                    methods.xFileControl.unwrap()(
                        file,
                        ffi::SQLITE_FCNTL_SIZE_HINT,
                        std::ptr::addr_of_mut!(hint).cast(),
                    ),
                ]
            };
            assert!(
                results.iter().all(|&rc| rc != ffi::SQLITE_OK),
                "{results:?}"
            );
            assert!(map.is_null());
        }

        // SAFETY: the guard VFS is registered (opens above used it).
        let vfs = unsafe { &*ffi::sqlite3_vfs_find(GUARD_VFS.as_ptr()) };
        let mut file = vec![0_u64; usize::try_from(vfs.szOsFile).unwrap().div_ceil(8)];
        for (name, flags) in [
            (
                Some(c"new.sqlite"),
                ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
            ),
            (
                Some(c"live.sqlite-journal"),
                ffi::SQLITE_OPEN_MAIN_JOURNAL
                    | ffi::SQLITE_OPEN_READWRITE
                    | ffi::SQLITE_OPEN_CREATE,
            ),
            (
                None,
                ffi::SQLITE_OPEN_TEMP_JOURNAL
                    | ffi::SQLITE_OPEN_READWRITE
                    | ffi::SQLITE_OPEN_CREATE
                    | ffi::SQLITE_OPEN_EXCLUSIVE
                    | ffi::SQLITE_OPEN_DELETEONCLOSE,
            ),
        ] {
            let path = name.map(|name| {
                let mut bytes = at(name.to_str().unwrap()).into_os_string().into_vec();
                bytes.push(0);
                bytes
            });
            let mut out = 0;
            // SAFETY: `file` has the VFS's `szOsFile` bytes, 8-aligned, and
            // the name is NUL-terminated or null.
            let rc = unsafe {
                vfs.xOpen.unwrap()(
                    std::ptr::from_ref(vfs).cast_mut(),
                    path.as_ref()
                        .map_or(std::ptr::null(), |path| path.as_ptr().cast()),
                    file.as_mut_ptr().cast(),
                    flags,
                    &mut out,
                )
            };
            assert_eq!(rc, ffi::SQLITE_CANTOPEN);
            assert_eq!(file[0], 0, "refused open left methods set");
        }
        let mut wal = sidecar(&at("live.sqlite"), "-wal")
            .into_os_string()
            .into_vec();
        wal.push(0);
        // SAFETY: a NUL-terminated name.
        let rc = unsafe {
            vfs.xDelete.unwrap()(std::ptr::from_ref(vfs).cast_mut(), wal.as_ptr().cast(), 0)
        };
        assert_ne!(rc, ffi::SQLITE_OK);

        drop((retry, idle, live));
        assert_eq!(home_state(&home), before);
        let _ = fs::remove_dir_all(scratch);
    }
}
