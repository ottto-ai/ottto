//! One `shutdown` row when the process receives SIGTERM or calls `exit`.
//!
//! The row records that the stop signal (or a normal exit) arrived. It does
//! not detect hangs and says nothing about why the signal was sent. Its
//! absence proves nothing either: SIGKILL, a crash, a signal before startup
//! or a failed write all leave no row.
use super::{write_line, Observation, Record, Source, SCHEMA_VERSION};
use std::sync::OnceLock;

/// Rendered in place of the timestamp, then split out of the line.
const TIME_PLACEHOLDER: u64 = u64::MAX;
/// Stack buffer for the whole line; rendering refuses anything longer.
const LINE_CAPACITY: usize = 1024;
const MAX_MS_DIGITS: usize = 20;

struct Line {
    before_time: Box<[u8]>,
    after_time: Box<[u8]>,
}

/// [SIGTERM, exit], rendered once at startup so the handler never allocates.
static LINES: OnceLock<[Line; 2]> = OnceLock::new();
const SIGTERM_LINE: usize = 0;
const EXIT_LINE: usize = 1;

/// Called once from startup diagnostics. A second call changes nothing.
pub(super) fn install() {
    let (Some(term), Some(exit)) = (render(Some("SIGTERM")), render(None)) else {
        return;
    };
    if LINES.set([term, exit]).is_err() {
        return;
    }
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
        libc::atexit(on_exit);
    }
}

fn render(signal: Option<&'static str>) -> Option<Line> {
    let mut observation = Observation::point();
    observation.observed_unix_ms = Some(TIME_PLACEHOLDER);
    let json = serde_json::to_string(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "shutdown",
        source: Source::Unknown,
        observation,
        counts: serde_json::json!({ "signal": signal }),
    })
    .ok()?;
    let mut line = Vec::new();
    write_line(&json, &mut line);
    let field = b"\"observed_unix_ms\":";
    let placeholder = format!("{TIME_PLACEHOLDER}");
    let marker = [field.as_slice(), placeholder.as_bytes()].concat();
    let at = line
        .windows(marker.len())
        .position(|window| window == marker)?;
    let line = Line {
        before_time: line[..at + field.len()].into(),
        after_time: line[at + marker.len()..].into(),
    };
    (line.before_time.len() + MAX_MS_DIGITS + line.after_time.len() <= LINE_CAPACITY)
        .then_some(line)
}

extern "C" fn on_sigterm(_: libc::c_int) {
    write_row(SIGTERM_LINE);
    // SAFETY: raise is async-signal-safe; SA_RESETHAND restored SIG_DFL.
    unsafe {
        libc::raise(libc::SIGTERM);
    }
}

extern "C" fn on_exit() {
    write_row(EXIT_LINE);
}

/// No allocation and no locks: one `write(2)` of a stack buffer.
fn write_row(index: usize) {
    let Some(line) = LINES.get().map(|lines| &lines[index]) else {
        return;
    };
    let mut buffer = [0u8; LINE_CAPACITY];
    let mut len = 0;
    let mut push = |bytes: &[u8]| {
        buffer[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    push(&line.before_time);
    let mut digits = [0u8; MAX_MS_DIGITS];
    let mut start = digits.len();
    match now_unix_ms() {
        Some(mut ms) => loop {
            start -= 1;
            digits[start] = b'0' + (ms % 10) as u8;
            ms /= 10;
            if ms == 0 {
                break;
            }
        },
        None => {
            start -= 4;
            digits[start..].copy_from_slice(b"null");
        }
    }
    push(&digits[start..]);
    push(&line.after_time);
    // SAFETY: the buffer is valid for `len` bytes. A failed or short write
    // is ignored: diagnostics never change how the process stops.
    unsafe {
        libc::write(libc::STDERR_FILENO, buffer.as_ptr().cast(), len);
    }
}

fn now_unix_ms() -> Option<u64> {
    // SAFETY: an all-zero timespec is valid; clock_gettime is
    // async-signal-safe and writes only `now`.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
        return None;
    }
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let millis = u64::try_from(now.tv_nsec).ok()? / 1_000_000;
    seconds.checked_mul(1000)?.checked_add(millis)
}
