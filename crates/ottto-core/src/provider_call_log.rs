//! Local log of the daemon's calls to OpenAI and Anthropic.
//!
//! One JSON line per provider call: a direct HTTP request the daemon made
//! (`observed`), or one run of a provider CLI that contacts the provider
//! itself (`subprocess_lower_bound`, with the least number of requests that
//! run makes). Lines carry the call kind, why it ran, a short account hash
//! (8 hex characters of the existing identifier hash), the outcome and the
//! duration. Never a token, URL, prompt, email or response content: every
//! field is an enum, a number, or a hash prefix.
//!
//! Files live in `<support dir>/provider-calls/YYYY-MM-DD.jsonl` (UTC day),
//! owner-only. Days older than [`RETENTION_DAYS`] are deleted, and hard
//! bounds cap one day's entries and bytes and the directory's total bytes.
//! Writing is best effort: it never fails or delays the provider call beyond
//! a short local append, and a busy or unwritable log drops the line.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Directory under the support dir.
pub const PROVIDER_CALL_LOG_DIR_NAME: &str = "provider-calls";
/// Days kept, today included.
pub const RETENTION_DAYS: u64 = 7;
/// One line never exceeds this.
pub const MAX_LINE_BYTES: usize = 512;
/// One day's file never exceeds this.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Entries written per day; later calls that day are not logged (one
/// `log_full` marker line says so).
pub const MAX_ENTRIES_PER_DAY: u64 = 30_000;
/// All day files together never exceed this; the oldest days go first.
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

const SCHEMA_VERSION: u8 = 1;
const LOG_FULL_KIND: &str = "log_full";
const SECONDS_PER_DAY: u64 = 86_400;
/// How long a writer waits for another writer's lock before dropping a line.
const LOCK_WAIT: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Openai,
    Anthropic,
    /// A model request whose provider the daemon cannot tell, such as Pi's
    /// default route.
    Unknown,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Unknown => "unknown",
        }
    }
}

/// What was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `GET api.anthropic.com/api/oauth/usage` (Claude quota).
    ClaudeOauthUsage,
    /// `GET api.anthropic.com/api/oauth/profile`: proves which account owns
    /// the default login's token. Owner check only; nothing is kept but hashes.
    ClaudeOauthProfile,
    /// `GET chatgpt.com/.../daily-workspace-usage-counts` (Codex daily totals).
    CodexDailyWorkspaceUsage,
    /// One `codex app-server` quota read: a token refresh and a rate-limits
    /// read, plus a detailed rate-limits read when due. Counts the requests
    /// sent, answered or not: 2, or 3 with the detailed read.
    CodexAppServerQuota,
    /// One `codex cloud list` page.
    CodexCloudList,
    /// Verify smoke prompts (`codex exec`, `claude -p`, `pi --print`).
    CodexSmokePrompt,
    ClaudeSmokePrompt,
    PiSmokePrompt,
    /// `pi --print` on Pi's default route, whose provider is unknown.
    PiDefaultSmokePrompt,
    /// `claude -p /usage` run to keep an expiring login signed in.
    ClaudeLoginRefresh,
    /// `claude auth login` for a sign-in.
    ClaudeSignIn,
    /// `claude -p /context` probe; Claude Code may contact Anthropic on start.
    ClaudeContextProbe,
    /// Claude Code started as a stdio MCP server for the MCP inventory.
    ClaudeMcpInventoryProbe,
}

impl CallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeOauthUsage => "claude_oauth_usage",
            Self::ClaudeOauthProfile => "claude_oauth_profile",
            Self::CodexDailyWorkspaceUsage => "codex_daily_workspace_usage",
            Self::CodexAppServerQuota => "codex_app_server_quota",
            Self::CodexCloudList => "codex_cloud_list",
            Self::CodexSmokePrompt => "codex_smoke_prompt",
            Self::ClaudeSmokePrompt => "claude_smoke_prompt",
            Self::PiSmokePrompt => "pi_smoke_prompt",
            Self::PiDefaultSmokePrompt => "pi_default_smoke_prompt",
            Self::ClaudeLoginRefresh => "claude_login_refresh",
            Self::ClaudeSignIn => "claude_sign_in",
            Self::ClaudeContextProbe => "claude_context_probe",
            Self::ClaudeMcpInventoryProbe => "claude_mcp_inventory_probe",
        }
    }
}

/// Why the call ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The daemon's own schedule or timer.
    Schedule,
    /// A person's Refresh (`agent_status_refresh` with `quota_refresh`).
    ExplicitRefresh,
    /// An older companion app's status refresh, read as a Refresh.
    OlderAppCompat,
    /// Setup, sign-in or a setup check.
    Setup,
    /// The first pass after the daemon started.
    Startup,
    Other,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::ExplicitRefresh => "explicit_refresh",
            Self::OlderAppCompat => "older_app_compat",
            Self::Setup => "setup",
            Self::Startup => "startup",
            Self::Other => "other",
        }
    }
}

/// How the requests were counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// A direct HTTP request the daemon made: exactly one request.
    Observed,
    /// A provider CLI run: at least `requests_at_least` requests we cannot see.
    SubprocessLowerBound,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SubprocessLowerBound => "subprocess_lower_bound",
        }
    }
}

/// The outcome, without any provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallResult {
    Ok,
    /// An HTTP status other than success.
    Http(u16),
    Timeout,
    /// A short fixed class such as `transport_error`, `rpc_error`, `exit_1`.
    Error(&'static str),
    /// A non-zero exit code of a CLI run.
    Exit(i32),
}

impl CallResult {
    fn label(self) -> String {
        match self {
            Self::Ok => "ok".to_string(),
            Self::Http(status) => format!("http_{status}"),
            Self::Timeout => "timeout".to_string(),
            Self::Error(class) => sanitize_class(class),
            Self::Exit(code) => format!("exit_{code}"),
        }
    }
}

fn sanitize_class(class: &str) -> String {
    let cleaned: String = class
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || *ch == '_')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "error".to_string()
    } else {
        cleaned
    }
}

/// One provider call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCall {
    pub provider: Provider,
    pub kind: CallKind,
    pub trigger: Trigger,
    /// 8 hex characters, or `unknown`.
    pub account: String,
    pub result: CallResult,
    pub duration: Duration,
    pub basis: Basis,
    pub requests_at_least: u32,
}

impl ProviderCall {
    /// A direct HTTP request: one request.
    pub fn observed(
        provider: Provider,
        kind: CallKind,
        trigger: Trigger,
        account_identifier_hash: Option<&str>,
        result: CallResult,
        duration: Duration,
    ) -> Self {
        Self {
            provider,
            kind,
            trigger,
            account: short_account(account_identifier_hash),
            result,
            duration,
            basis: Basis::Observed,
            requests_at_least: 1,
        }
    }

    /// A provider CLI run that makes at least `requests_at_least` requests.
    pub fn subprocess(
        provider: Provider,
        kind: CallKind,
        trigger: Trigger,
        account_identifier_hash: Option<&str>,
        result: CallResult,
        duration: Duration,
        requests_at_least: u32,
    ) -> Self {
        Self {
            provider,
            kind,
            trigger,
            account: short_account(account_identifier_hash),
            result,
            duration,
            basis: Basis::SubprocessLowerBound,
            requests_at_least,
        }
    }
}

/// The first 8 hex characters of an identifier hash, or `unknown`.
pub fn short_account(account_identifier_hash: Option<&str>) -> String {
    account_identifier_hash
        .map(str::trim)
        .and_then(|hash| hash.get(..8))
        .filter(|prefix| {
            prefix
                .chars()
                .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        })
        .map_or_else(|| "unknown".to_string(), ToString::to_string)
}

thread_local! {
    static TRIGGER: Cell<Option<Trigger>> = const { Cell::new(None) };
}

/// Run `body` with `trigger` as the reason for any provider call it makes on
/// this thread. Threads `body` spawns start without one; pass
/// [`current_trigger`] on.
pub fn with_trigger<R>(trigger: Trigger, body: impl FnOnce() -> R) -> R {
    struct Restore(Option<Trigger>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TRIGGER.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(TRIGGER.with(|cell| cell.replace(Some(trigger))));
    body()
}

/// The trigger set by the nearest [`with_trigger`] on this thread.
pub fn current_trigger() -> Option<Trigger> {
    TRIGGER.with(Cell::get)
}

/// One stored line, as written. Read back leniently for the summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCallLine {
    pub v: u8,
    pub at: String,
    pub provider: String,
    pub kind: String,
    #[serde(default)]
    pub trigger: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub basis: String,
    #[serde(default)]
    pub requests_at_least: u32,
}

impl ProviderCallLine {
    fn new(call: &ProviderCall, at_epoch_seconds: u64) -> Self {
        Self {
            v: SCHEMA_VERSION,
            at: rfc3339_utc(at_epoch_seconds),
            provider: call.provider.as_str().to_string(),
            kind: call.kind.as_str().to_string(),
            trigger: call.trigger.as_str().to_string(),
            account: short_account(Some(&call.account)),
            result: call.result.label(),
            duration_ms: u64::try_from(call.duration.as_millis()).unwrap_or(u64::MAX),
            basis: call.basis.as_str().to_string(),
            requests_at_least: call.requests_at_least,
        }
    }

    fn log_full(at_epoch_seconds: u64) -> Self {
        Self {
            v: SCHEMA_VERSION,
            at: rfc3339_utc(at_epoch_seconds),
            provider: String::new(),
            kind: LOG_FULL_KIND.to_string(),
            trigger: String::new(),
            account: String::new(),
            result: String::new(),
            duration_ms: 0,
            basis: String::new(),
            requests_at_least: 0,
        }
    }
}

/// The log directory under `support_dir`.
pub fn provider_call_log_dir(support_dir: &Path) -> PathBuf {
    support_dir.join(PROVIDER_CALL_LOG_DIR_NAME)
}

/// Append `call` to the log under `support_dir`, best effort.
pub fn record_provider_call(support_dir: &Path, call: &ProviderCall, at: SystemTime) {
    let at = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let _ = append(&provider_call_log_dir(support_dir), call, at);
}

fn epoch_day(at_epoch_seconds: u64) -> i64 {
    i64::try_from(at_epoch_seconds / SECONDS_PER_DAY).unwrap_or(i64::MAX)
}

fn day_file_name(day: i64) -> String {
    let (year, month, date) = civil_from_days(day);
    format!("{year:04}-{month:02}-{date:02}.jsonl")
}

/// The epoch day a log file name stands for.
fn day_of_file_name(name: &str) -> Option<i64> {
    let stem = name.strip_suffix(".jsonl")?;
    let bytes = stem.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i64 = stem.get(0..4)?.parse().ok()?;
    let month: u32 = stem.get(5..7)?.parse().ok()?;
    let date: u32 = stem.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&date) {
        return None;
    }
    let day = days_from_civil(year, month, date);
    (day_file_name(day) == name).then_some(day)
}

/// Whether a day file is kept on `today`: inside retention. A file dated
/// after today (the clock stepped back) is kept; it expires in its turn.
fn day_retained(day: i64, today: i64) -> bool {
    day >= today - (RETENTION_DAYS as i64 - 1)
}

// Howard Hinnant's civil calendar conversions (proleptic Gregorian, UTC).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let date = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, date)
}

fn rfc3339_utc(at_epoch_seconds: u64) -> String {
    let (year, month, date) = civil_from_days(epoch_day(at_epoch_seconds));
    let seconds = at_epoch_seconds % SECONDS_PER_DAY;
    format!(
        "{year:04}-{month:02}-{date:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// Parse the `YYYY-MM-DDTHH:MM:SSZ` form this log writes.
fn parse_rfc3339_utc(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    let day = day_of_file_name(&format!("{}.jsonl", value.get(..10)?))?;
    let hours: u64 = value.get(11..13)?.parse().ok()?;
    let minutes: u64 = value.get(14..16)?.parse().ok()?;
    let seconds: u64 = value.get(17..19)?.parse().ok()?;
    if hours > 23 || minutes > 59 || seconds > 60 {
        return None;
    }
    u64::try_from(day)
        .ok()?
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(hours * 3600 + minutes * 60 + seconds)
}

#[cfg(unix)]
mod writer {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::{Mutex, PoisonError};
    use std::time::Instant;

    /// Entries in the current day file, remembered between writes so a
    /// write does not recount the file. Recounted when another process
    /// wrote in between (the size moved).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Count {
        dev: u64,
        ino: u64,
        len: u64,
        entries: u64,
    }

    static WRITER: Mutex<Option<Count>> = Mutex::new(None);

    #[cfg(test)]
    thread_local! {
        /// Bytes the next write on this thread gets out before it fails, as
        /// on a full disk.
        pub(super) static SHORT_WRITE: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
    }

    fn write_line(file: &mut File, line: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(partial) = SHORT_WRITE.with(std::cell::Cell::take) {
            file.write_all(&line[..partial.min(line.len())])?;
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
        }
        file.write_all(line)
    }

    pub(super) fn append(dir: &Path, call: &ProviderCall, at: u64) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(&ProviderCallLine::new(call, at))
            .map_err(|_| std::io::Error::other("unserializable line"))?;
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::other("line over bound"));
        }
        let mut count = WRITER.lock().unwrap_or_else(PoisonError::into_inner);
        ensure_dir(dir)?;
        let today = epoch_day(at);
        let path = dir.join(day_file_name(today));
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let _lock = FileLock::acquire(&file)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        prune(dir, today, &path, line.len() as u64)?;
        let entries = match *count {
            Some(known)
                if known.dev == metadata.dev()
                    && known.ino == metadata.ino()
                    && known.len == metadata.len() =>
            {
                known.entries
            }
            _ if metadata.len() > MAX_FILE_BYTES => MAX_ENTRIES_PER_DAY,
            _ => count_entries(&mut file)?,
        };
        let full = entries >= MAX_ENTRIES_PER_DAY
            || metadata.len() + line.len() as u64 > MAX_FILE_BYTES - MAX_LINE_BYTES as u64;
        let (written, entries) = if full {
            if ends_with_log_full(&mut file, metadata.len())? {
                *count = Some(Count {
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                    len: metadata.len(),
                    entries,
                });
                return Ok(());
            }
            let mut marker = serde_json::to_vec(&ProviderCallLine::log_full(at))
                .map_err(|_| std::io::Error::other("unserializable line"))?;
            marker.push(b'\n');
            (marker, entries)
        } else {
            (line, entries + 1)
        };
        if let Err(error) = write_line(&mut file, &written) {
            // Never leave part of a line (a full disk): the next line would
            // join it. The lock keeps other writers out until then.
            let _ = file.set_len(metadata.len());
            return Err(error);
        }
        *count = Some(Count {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len() + written.len() as u64,
            entries,
        });
        Ok(())
    }

    fn ensure_dir(dir: &Path) -> std::io::Result<()> {
        match std::fs::symlink_metadata(dir) {
            Ok(metadata) if metadata.is_dir() => {
                if metadata.permissions().mode() & 0o777 != 0o700 {
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
                }
                Ok(())
            }
            Ok(_) => Err(std::io::Error::other("log path is not a directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(dir)?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            }
            Err(error) => Err(error),
        }
    }

    /// An exclusive `flock` on the day file, so writers in other processes
    /// append whole lines and count consistently. Waits at most
    /// [`LOCK_WAIT`], then the line is dropped. Declared after the file it
    /// locks, so it is released first.
    struct FileLock(RawFd);

    impl FileLock {
        fn acquire(file: &File) -> std::io::Result<Self> {
            let fd = file.as_raw_fd();
            let started = Instant::now();
            loop {
                // SAFETY: flock on a descriptor that outlives this lock.
                if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    return Ok(Self(fd));
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EWOULDBLOCK) || started.elapsed() > LOCK_WAIT
                {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Drop for FileLock {
        fn drop(&mut self) {
            // SAFETY: unlocks the descriptor locked in `acquire`, still open.
            unsafe { libc::flock(self.0, libc::LOCK_UN) };
        }
    }

    fn count_entries(file: &mut File) -> std::io::Result<u64> {
        file.seek(SeekFrom::Start(0))?;
        let mut entries = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        let mut reader = file.take(MAX_FILE_BYTES);
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(entries);
            }
            entries += buffer[..read].iter().filter(|byte| **byte == b'\n').count() as u64;
        }
    }

    fn ends_with_log_full(file: &mut File, len: u64) -> std::io::Result<bool> {
        let tail = len.min(MAX_LINE_BYTES as u64);
        file.seek(SeekFrom::Start(len - tail))?;
        let mut bytes = Vec::with_capacity(tail as usize);
        file.take(tail).read_to_end(&mut bytes)?;
        let last_line = bytes
            .strip_suffix(b"\n")
            .unwrap_or(&bytes)
            .rsplit(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        Ok(serde_json::from_slice::<ProviderCallLine>(last_line)
            .is_ok_and(|line| line.kind == LOG_FULL_KIND))
    }

    /// Delete expired day files, then the oldest others until today's line
    /// fits under [`MAX_TOTAL_BYTES`]. Other files in the directory are
    /// left alone and not counted.
    fn prune(dir: &Path, today: i64, today_path: &Path, adding: u64) -> std::io::Result<()> {
        let mut kept = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let Some(day) = name.to_str().and_then(day_of_file_name) else {
                continue;
            };
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if day_retained(day, today) {
                kept.push((day, entry.path(), metadata.len()));
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        kept.sort();
        let mut total: u64 = kept.iter().map(|(_, _, len)| len).sum();
        for (_, path, len) in &kept {
            if total.saturating_add(adding) <= MAX_TOTAL_BYTES {
                break;
            }
            if path != today_path && std::fs::remove_file(path).is_ok() {
                total -= len;
            }
        }
        if total.saturating_add(adding) > MAX_TOTAL_BYTES {
            return Err(std::io::Error::other("log over its total bound"));
        }
        Ok(())
    }
}

#[cfg(unix)]
use writer::append;

#[cfg(not(unix))]
fn append(_dir: &Path, _call: &ProviderCall, _at: u64) -> std::io::Result<()> {
    Ok(())
}

/// Calls and the least number of provider requests they made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallCount {
    pub calls: u64,
    pub requests_at_least: u64,
}

impl CallCount {
    fn add(&mut self, requests: u64) {
        self.calls += 1;
        self.requests_at_least += requests;
    }
}

/// One UTC day of the summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCallDay {
    pub day: String,
    pub calls: u64,
    pub requests_at_least: u64,
    /// Direct HTTP requests (exact).
    pub observed_requests: u64,
    /// Provider CLI runs (each a lower bound).
    pub subprocess_runs: u64,
    /// The day hit a bound and later calls were not logged.
    pub log_full: bool,
    pub by_provider: BTreeMap<String, CallCount>,
    pub by_kind: BTreeMap<String, CallCount>,
    pub by_trigger: BTreeMap<String, CallCount>,
    pub by_result: BTreeMap<String, CallCount>,
    /// `<provider>/<kind>/<trigger>`.
    pub by_provider_kind_trigger: BTreeMap<String, CallCount>,
}

/// `ottto provider-requests` output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCallSummary {
    pub schema_version: u8,
    pub generated_at: String,
    /// Lines at or after this time are counted (the retention window when
    /// no `--since` was given).
    pub since: String,
    pub retention_days: u64,
    pub calls: u64,
    pub requests_at_least: u64,
    pub by_provider: BTreeMap<String, CallCount>,
    pub days: Vec<ProviderCallDay>,
    /// Lines that could not be read.
    pub skipped_lines: u64,
}

/// Summarize the log under `support_dir` for lines at or after
/// `now - since` (all retained days when `since` is `None`).
pub fn summarize_provider_calls(
    support_dir: &Path,
    since: Option<Duration>,
    now: SystemTime,
) -> ProviderCallSummary {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let today = epoch_day(now);
    let retention_start =
        u64::try_from(today - (RETENTION_DAYS as i64 - 1)).unwrap_or(0) * SECONDS_PER_DAY;
    let since_at = since.map_or(retention_start, |since| {
        now.saturating_sub(since.as_secs()).max(retention_start)
    });
    let mut summary = ProviderCallSummary {
        schema_version: SCHEMA_VERSION,
        generated_at: rfc3339_utc(now),
        since: rfc3339_utc(since_at),
        retention_days: RETENTION_DAYS,
        ..ProviderCallSummary::default()
    };
    let mut days = BTreeMap::<i64, ProviderCallDay>::new();
    let dir = provider_call_log_dir(support_dir);
    let mut files = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let day = entry.file_name().to_str().and_then(day_of_file_name)?;
                    day_retained(day, today).then(|| (day, entry.path()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    files.sort();
    for (_, path) in files {
        let Some(body) = read_bounded(&path) else {
            continue;
        };
        for raw in body.split(|byte| *byte == b'\n') {
            if raw.is_empty() {
                continue;
            }
            let Some((line, at)) = serde_json::from_slice::<ProviderCallLine>(raw)
                .ok()
                .and_then(|line| parse_rfc3339_utc(&line.at).map(|at| (line, at)))
            else {
                summary.skipped_lines += 1;
                continue;
            };
            let is_log_full = line.kind == LOG_FULL_KIND;
            // A full day drops every later call that day: it concerns any
            // window that reaches past the marker into that day.
            let in_window = if is_log_full {
                at <= now && since_at < (epoch_day(at) as u64 + 1) * SECONDS_PER_DAY
            } else {
                at >= since_at && at <= now.saturating_add(SECONDS_PER_DAY)
            };
            if !in_window {
                continue;
            }
            let day = days
                .entry(epoch_day(at))
                .or_insert_with(|| ProviderCallDay {
                    day: day_file_name(epoch_day(at))
                        .trim_end_matches(".jsonl")
                        .to_string(),
                    ..ProviderCallDay::default()
                });
            if is_log_full {
                day.log_full = true;
                continue;
            }
            let requests = u64::from(line.requests_at_least);
            day.calls += 1;
            day.requests_at_least += requests;
            if line.basis == Basis::Observed.as_str() {
                day.observed_requests += requests;
            } else {
                day.subprocess_runs += 1;
            }
            day.by_provider
                .entry(line.provider.clone())
                .or_default()
                .add(requests);
            day.by_kind
                .entry(line.kind.clone())
                .or_default()
                .add(requests);
            day.by_trigger
                .entry(line.trigger.clone())
                .or_default()
                .add(requests);
            day.by_result
                .entry(line.result.clone())
                .or_default()
                .add(requests);
            day.by_provider_kind_trigger
                .entry(format!("{}/{}/{}", line.provider, line.kind, line.trigger))
                .or_default()
                .add(requests);
            summary.calls += 1;
            summary.requests_at_least += requests;
            summary
                .by_provider
                .entry(line.provider)
                .or_default()
                .add(requests);
        }
    }
    summary.days = days.into_values().collect();
    summary
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut body = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES + MAX_LINE_BYTES as u64)
        .read_to_end(&mut body)
        .ok()?;
    Some(body)
}

/// A short plain-text rendering of a summary.
pub fn render_provider_call_summary(summary: &ProviderCallSummary) -> String {
    let mut out = format!(
        "Provider requests since {} (local log, UTC days, kept {} days)\n",
        summary.since, summary.retention_days
    );
    if summary.days.is_empty() {
        out.push_str("No provider calls logged.\n");
        return out;
    }
    for day in &summary.days {
        let providers = day
            .by_provider
            .iter()
            .map(|(provider, count)| {
                format!(
                    "{provider} {} calls, >= {} requests",
                    count.calls, count.requests_at_least
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&format!(
            "{}: {} calls, >= {} requests ({providers}){}\n",
            day.day,
            day.calls,
            day.requests_at_least,
            if day.log_full {
                " [log full: later calls not logged]"
            } else {
                ""
            }
        ));
        for (key, count) in &day.by_provider_kind_trigger {
            out.push_str(&format!(
                "  {key}: {} calls, >= {} requests\n",
                count.calls, count.requests_at_least
            ));
        }
        let results = day
            .by_result
            .iter()
            .map(|(result, count)| format!("{result} {}", count.calls))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  results: {results}\n"));
    }
    out.push_str(&format!(
        "Total: {} calls, >= {} requests\n",
        summary.calls, summary.requests_at_least
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ottto-provider-call-log-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn at(epoch_seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(epoch_seconds)
    }

    // 2026-10-15T12:00:00Z
    const NOON: u64 = 1_792_065_600;

    fn codex_read(trigger: Trigger, result: CallResult) -> ProviderCall {
        ProviderCall::subprocess(
            Provider::Openai,
            CallKind::CodexAppServerQuota,
            trigger,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            result,
            Duration::from_millis(1250),
            2,
        )
    }

    fn lines(support_dir: &Path, day: &str) -> Vec<String> {
        std::fs::read_to_string(provider_call_log_dir(support_dir).join(format!("{day}.jsonl")))
            .unwrap_or_default()
            .lines()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(rfc3339_utc(NOON), "2026-10-15T12:00:00Z");
        assert_eq!(parse_rfc3339_utc("2026-10-15T12:00:00Z"), Some(NOON));
        assert_eq!(day_file_name(epoch_day(NOON)), "2026-10-15.jsonl");
        assert_eq!(day_of_file_name("2026-10-15.jsonl"), Some(epoch_day(NOON)));
        assert_eq!(day_of_file_name("2024-02-29.jsonl"), Some(19_782));
        assert_eq!(day_of_file_name("2026-02-30.jsonl"), None);
        assert_eq!(day_of_file_name("notes.jsonl"), None);
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_call_is_one_owner_only_line_without_secrets() {
        let support = scratch("line");
        record_provider_call(
            &support,
            &codex_read(Trigger::Schedule, CallResult::Ok),
            at(NOON),
        );
        record_provider_call(
            &support,
            &ProviderCall::observed(
                Provider::Anthropic,
                CallKind::ClaudeOauthUsage,
                Trigger::ExplicitRefresh,
                Some("not-a-hash"),
                CallResult::Http(429),
                Duration::from_millis(80),
            ),
            at(NOON + 1),
        );
        let written = lines(&support, "2026-10-15");
        assert_eq!(
            written,
            [
                r#"{"v":1,"at":"2026-10-15T12:00:00Z","provider":"openai","kind":"codex_app_server_quota","trigger":"schedule","account":"01234567","result":"ok","duration_ms":1250,"basis":"subprocess_lower_bound","requests_at_least":2}"#,
                r#"{"v":1,"at":"2026-10-15T12:00:01Z","provider":"anthropic","kind":"claude_oauth_usage","trigger":"explicit_refresh","account":"unknown","result":"http_429","duration_ms":80,"basis":"observed","requests_at_least":1}"#,
            ]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = provider_call_log_dir(&support);
            let file = dir.join("2026-10-15.jsonl");
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(support);
    }

    #[test]
    fn error_classes_are_sanitized_and_accounts_are_eight_hex() {
        assert_eq!(
            CallResult::Error("Bearer sk-SECRET token").label(),
            "earersktoken"
        );
        assert_eq!(CallResult::Error("").label(), "error");
        assert_eq!(CallResult::Exit(2).label(), "exit_2");
        assert_eq!(short_account(Some("ABCDEF0123")), "unknown");
        assert_eq!(short_account(Some("abc")), "unknown");
        assert_eq!(short_account(None), "unknown");
        assert_eq!(short_account(Some("deadbeefcafe")), "deadbeef");
    }

    #[test]
    fn the_trigger_scope_is_per_thread_and_restored() {
        assert_eq!(current_trigger(), None);
        with_trigger(Trigger::Setup, || {
            assert_eq!(current_trigger(), Some(Trigger::Setup));
            with_trigger(Trigger::ExplicitRefresh, || {
                assert_eq!(current_trigger(), Some(Trigger::ExplicitRefresh));
            });
            assert_eq!(current_trigger(), Some(Trigger::Setup));
            std::thread::spawn(|| assert_eq!(current_trigger(), None))
                .join()
                .unwrap();
        });
        assert_eq!(current_trigger(), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_full_day_stops_at_its_entry_bound_with_one_marker() {
        let support = scratch("entries");
        let dir = provider_call_log_dir(&support);
        std::fs::create_dir_all(&dir).unwrap();
        // A day already at its entry bound, written by another process.
        let line = String::from_utf8(
            serde_json::to_vec(&ProviderCallLine::new(
                &codex_read(Trigger::Schedule, CallResult::Ok),
                NOON,
            ))
            .unwrap(),
        )
        .unwrap();
        let body = format!("{line}\n").repeat(MAX_ENTRIES_PER_DAY as usize);
        std::fs::write(dir.join("2026-10-15.jsonl"), body).unwrap();
        for second in 0..3 {
            record_provider_call(
                &support,
                &codex_read(Trigger::Schedule, CallResult::Ok),
                at(NOON + 10 + second),
            );
        }
        let written = lines(&support, "2026-10-15");
        assert_eq!(written.len() as u64, MAX_ENTRIES_PER_DAY + 1);
        assert!(written.last().unwrap().contains(r#""kind":"log_full""#));
        let summary = summarize_provider_calls(&support, None, at(NOON + 60));
        assert_eq!(summary.days.len(), 1);
        assert!(summary.days[0].log_full);
        assert_eq!(summary.calls, MAX_ENTRIES_PER_DAY);
        // A window that starts after the day filled still says so.
        let later =
            summarize_provider_calls(&support, Some(Duration::from_secs(600)), at(NOON + 7_200));
        assert_eq!(later.calls, 0);
        assert_eq!(later.days.len(), 1);
        assert!(later.days[0].log_full);
        // A window that starts the next day does not.
        let next_day = summarize_provider_calls(
            &support,
            Some(Duration::from_secs(60)),
            at(NOON + SECONDS_PER_DAY),
        );
        assert!(next_day.days.iter().all(|day| !day.log_full));
        // The next day starts a new file.
        record_provider_call(
            &support,
            &codex_read(Trigger::Schedule, CallResult::Ok),
            at(NOON + SECONDS_PER_DAY),
        );
        assert_eq!(lines(&support, "2026-10-16").len(), 1);
        let _ = std::fs::remove_dir_all(support);
    }

    /// A write that fails part-way (a full disk) leaves no partial line,
    /// and the next write appends a whole line after the earlier ones.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_no_partial_line() {
        let support = scratch("short-write");
        let call = codex_read(Trigger::Schedule, CallResult::Ok);
        record_provider_call(&support, &call, at(NOON));
        let before = lines(&support, "2026-10-15");
        assert_eq!(before.len(), 1);
        writer::SHORT_WRITE.with(|short| short.set(Some(20)));
        record_provider_call(&support, &call, at(NOON + 1));
        assert_eq!(writer::SHORT_WRITE.with(std::cell::Cell::get), None);
        let raw = std::fs::read_to_string(provider_call_log_dir(&support).join("2026-10-15.jsonl"))
            .unwrap();
        assert_eq!(raw, format!("{}\n", before[0]));
        record_provider_call(&support, &call, at(NOON + 2));
        let after = lines(&support, "2026-10-15");
        assert_eq!(after.len(), 2);
        assert!(after[1].contains(r#""at":"2026-10-15T12:00:02Z""#));
        let summary = summarize_provider_calls(&support, None, at(NOON + 60));
        assert_eq!((summary.calls, summary.skipped_lines), (2, 0));
        let _ = std::fs::remove_dir_all(support);
    }

    #[cfg(unix)]
    #[test]
    fn a_day_stops_at_its_byte_bound() {
        let support = scratch("bytes");
        let dir = provider_call_log_dir(&support);
        std::fs::create_dir_all(&dir).unwrap();
        // Few long lines: the byte bound, not the entry bound, is reached.
        let filler = format!("{}\n", "x".repeat(1023));
        let body = filler.repeat((MAX_FILE_BYTES / 1024) as usize - 1);
        std::fs::write(dir.join("2026-10-15.jsonl"), &body).unwrap();
        for second in 0..6 {
            record_provider_call(
                &support,
                &codex_read(Trigger::Schedule, CallResult::Ok),
                at(NOON + second),
            );
        }
        let file = dir.join("2026-10-15.jsonl");
        let len = std::fs::metadata(&file).unwrap().len();
        assert!(len <= MAX_FILE_BYTES, "{len}");
        let written = lines(&support, "2026-10-15");
        assert!(written.last().unwrap().contains(r#""kind":"log_full""#));
        assert_eq!(
            written
                .iter()
                .filter(|line| line.contains("log_full"))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(support);
    }

    #[cfg(unix)]
    #[test]
    fn old_days_expire_and_the_total_bound_drops_the_oldest_days() {
        let support = scratch("expiry");
        let dir = provider_call_log_dir(&support);
        std::fs::create_dir_all(&dir).unwrap();
        let today = epoch_day(NOON);
        for back in 1..=9 {
            std::fs::write(dir.join(day_file_name(today - back)), b"{}\n").unwrap();
        }
        std::fs::write(dir.join("notes.txt"), b"not a log").unwrap();
        record_provider_call(
            &support,
            &codex_read(Trigger::Schedule, CallResult::Ok),
            at(NOON),
        );
        let mut names = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "2026-10-09.jsonl",
                "2026-10-10.jsonl",
                "2026-10-11.jsonl",
                "2026-10-12.jsonl",
                "2026-10-13.jsonl",
                "2026-10-14.jsonl",
                "2026-10-15.jsonl",
                "notes.txt",
            ]
        );

        // Six full older days push the total over its bound: the oldest go.
        let big = vec![b'\n'; (MAX_FILE_BYTES - 1024) as usize];
        for back in 1..=6 {
            std::fs::write(dir.join(day_file_name(today - back)), &big).unwrap();
        }
        record_provider_call(
            &support,
            &codex_read(Trigger::Schedule, CallResult::Ok),
            at(NOON + 1),
        );
        let total: u64 = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(day_of_file_name)
                    .is_some()
            })
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        assert!(total <= MAX_TOTAL_BYTES, "{total}");
        assert!(!dir.join("2026-10-09.jsonl").exists());
        assert!(!dir.join("2026-10-10.jsonl").exists());
        assert!(dir.join("2026-10-14.jsonl").exists());
        assert_eq!(lines(&support, "2026-10-15").len(), 2);
        let _ = std::fs::remove_dir_all(support);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_writers_append_whole_lines() {
        let support = scratch("concurrent");
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let support = &support;
                scope.spawn(move || {
                    for index in 0..25 {
                        record_provider_call(
                            support,
                            &codex_read(Trigger::Schedule, CallResult::Exit(thread)),
                            at(NOON + index),
                        );
                    }
                });
            }
        });
        let written = lines(&support, "2026-10-15");
        assert_eq!(written.len(), 200);
        assert!(written
            .iter()
            .all(|line| serde_json::from_str::<ProviderCallLine>(line).is_ok()));
        let _ = std::fs::remove_dir_all(support);
    }

    #[cfg(unix)]
    #[test]
    fn the_summary_counts_per_day_by_provider_kind_trigger_and_result() {
        let support = scratch("summary");
        let yesterday = NOON - SECONDS_PER_DAY;
        for offset in 0..3 {
            record_provider_call(
                &support,
                &codex_read(Trigger::Schedule, CallResult::Ok),
                at(yesterday + offset),
            );
        }
        record_provider_call(
            &support,
            &codex_read(Trigger::ExplicitRefresh, CallResult::Timeout),
            at(NOON),
        );
        record_provider_call(
            &support,
            &ProviderCall::observed(
                Provider::Anthropic,
                CallKind::ClaudeOauthUsage,
                Trigger::Schedule,
                Some("feedface00"),
                CallResult::Ok,
                Duration::from_millis(300),
            ),
            at(NOON + 5),
        );
        std::fs::write(
            provider_call_log_dir(&support).join("2026-10-13.jsonl"),
            b"not json\n",
        )
        .unwrap();

        let summary = summarize_provider_calls(&support, None, at(NOON + 60));
        assert_eq!(summary.calls, 5);
        assert_eq!(summary.requests_at_least, 9);
        assert_eq!(summary.skipped_lines, 1);
        assert_eq!(summary.days.len(), 2);
        let today = &summary.days[1];
        assert_eq!(today.day, "2026-10-15");
        assert_eq!(today.calls, 2);
        assert_eq!(today.requests_at_least, 3);
        assert_eq!(today.observed_requests, 1);
        assert_eq!(today.subprocess_runs, 1);
        assert_eq!(
            today.by_result.get("timeout"),
            Some(&CallCount {
                calls: 1,
                requests_at_least: 2
            })
        );
        assert_eq!(
            today
                .by_provider_kind_trigger
                .get("openai/codex_app_server_quota/explicit_refresh")
                .map(|count| count.calls),
            Some(1)
        );
        assert_eq!(
            summary.by_provider.get("openai"),
            Some(&CallCount {
                calls: 4,
                requests_at_least: 8
            })
        );

        let recent =
            summarize_provider_calls(&support, Some(Duration::from_secs(3600)), at(NOON + 60));
        assert_eq!(recent.calls, 2);
        assert_eq!(recent.since, "2026-10-15T11:01:00Z");

        let text = render_provider_call_summary(&summary);
        assert!(
            text.contains("2026-10-15: 2 calls, >= 3 requests"),
            "{text}"
        );
        assert!(text.contains("openai/codex_app_server_quota/schedule: 3 calls, >= 6 requests"));
        let _ = std::fs::remove_dir_all(support);
    }
}
