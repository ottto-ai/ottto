//! One `shutdown` row when the process receives SIGTERM.
//!
//! The row records that the stop signal arrived. It does not detect hangs and
//! says nothing about who sent the signal. Its absence proves nothing either:
//! SIGKILL, a crash, a signal before startup or a failed write all leave no row.
use super::{write_line, Observation, Record, Source, SCHEMA_VERSION};
use std::sync::OnceLock;

/// Rendered in place of the timestamp, then split out of the line.
const TIME_PLACEHOLDER: u64 = u64::MAX;
/// Stack buffer for the whole line; the test pins the row well below it.
pub(super) const LINE_BUFFER: usize = 1024;

struct Line {
    before_time: Box<[u8]>,
    after_time: Box<[u8]>,
}

static LINE: OnceLock<Line> = OnceLock::new();

/// Rendered once by `install`, before the handler exists, so the handler's
/// call is only an atomic load and never allocates.
fn line() -> &'static Line {
    LINE.get_or_init(|| {
        let mut observation = Observation::point();
        observation.observed_unix_ms = Some(TIME_PLACEHOLDER);
        // A fixed struct of numbers and static strings always serializes.
        let json = serde_json::to_string(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "shutdown",
            source: Source::Unknown,
            observation,
            counts: serde_json::json!({}),
        })
        .expect("shutdown row serializes");
        let mut line = Vec::new();
        write_line(&json, &mut line);
        let field = b"\"observed_unix_ms\":";
        let marker = [field.as_slice(), TIME_PLACEHOLDER.to_string().as_bytes()].concat();
        // The placeholder was just written into this field.
        let at = line
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("shutdown row has its time placeholder");
        Line {
            before_time: line[..at + field.len()].into(),
            after_time: line[at + marker.len()..].into(),
        }
    })
}

/// Called once from startup diagnostics.
pub(super) fn install() {
    line();
    // SAFETY: the handler only uses async-signal-safe calls (clock_gettime,
    // write, raise) on data that was fully initialized above.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigterm as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // Back to the default action on entry, so the re-raise ends the
        // process by SIGTERM with the same wait status as before.
        action.sa_flags = libc::SA_RESETHAND;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
    }
}

/// No allocation and no locks: one `write(2)` of a stack buffer, then the
/// default SIGTERM action.
extern "C" fn on_sigterm(_: libc::c_int) {
    let line = line();
    let mut buffer = [0u8; LINE_BUFFER];
    let mut len = 0;
    let mut push = |bytes: &[u8]| {
        buffer[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    push(&line.before_time);
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    let mut ms = now_unix_ms();
    loop {
        start -= 1;
        digits[start] = b'0' + (ms % 10) as u8;
        ms /= 10;
        if ms == 0 {
            break;
        }
    }
    push(&digits[start..]);
    push(&line.after_time);
    // SAFETY: the buffer is valid for `len` bytes; raise is async-signal-safe
    // and SA_RESETHAND restored SIG_DFL. A failed write changes nothing.
    unsafe {
        libc::write(libc::STDERR_FILENO, buffer.as_ptr().cast(), len);
        libc::raise(libc::SIGTERM);
    }
}

/// Not `SystemTime::now()` (as `Observation` uses): std does not document it
/// as async-signal-safe, and clock_gettime is.
fn now_unix_ms() -> u64 {
    // SAFETY: an all-zero timespec is valid; clock_gettime writes only `now`.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    now.tv_sec as u64 * 1000 + now.tv_nsec as u64 / 1_000_000
}
