//! Test-only, fresh-child-process WAL high-water observer. The native commit
//! hook runs before a checkpoint can truncate the WAL, so a short-lived WAL
//! cannot disappear between filesystem samples. The engine fixes 4096-B pages.
use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

pub(crate) fn begin() {
    assert!(
        !ENABLED.swap(true, Ordering::SeqCst),
        "fresh peak child only"
    );
}
pub(super) fn register(conn: &Connection) {
    if !ENABLED.load(Ordering::SeqCst) {
        return;
    }
    unsafe extern "C" fn committed(
        _: *mut std::ffi::c_void,
        _: *mut rusqlite::ffi::sqlite3,
        _: *const std::ffi::c_char,
        frames: std::ffi::c_int,
    ) -> std::ffi::c_int {
        // No allocation, panic, SQL, or borrowed userdata crosses this callback.
        if frames > 0 {
            PEAK.fetch_max(32 + frames as u64 * (4096 + 24), Ordering::SeqCst);
        }
        rusqlite::ffi::SQLITE_OK
    }
    // SAFETY: the connection remains owned by Sqlite; this static callback
    // retains no connection/userdata and never unwinds across the C boundary.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(conn.handle(), Some(committed), std::ptr::null_mut());
    }
    CONNECTIONS.fetch_add(1, Ordering::SeqCst);
}
pub(crate) fn finish() -> u64 {
    assert!(
        CONNECTIONS.load(Ordering::SeqCst) > 0,
        "production v2 connection was not observed"
    );
    PEAK.load(Ordering::SeqCst)
}
