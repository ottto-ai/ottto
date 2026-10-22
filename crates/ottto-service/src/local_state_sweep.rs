//! Removes snapshot checkpoint temp files that a daemon left behind when it
//! died mid-save.
//!
//! Every artifact recognized here is created and then renamed or removed by
//! its writer while that writer holds a non-blocking exclusive flock on the
//! canonical checkpoint's `<base>.lock` sibling:
//!
//! - `<base>.json.<pid>.tmp`: `ScanIndex::save_internal` under
//!   `CheckpointLock`, and `SnapshotUploadProgress::save_with_read_limit`
//!   under `SnapshotProgressLock`.
//! - `<base>.json.<pid>.migrate`: `adopt_legacy_checkpoint_file`, under the
//!   stable target's `SnapshotProgressLock`.
//! - `<base>.tmp.<pid>.<nanos>.json`: the terminal status journal writer,
//!   under `SnapshotProgressLock`.
//! - `<base>.cleared.<pid>.<nanos>.json`: `SnapshotUploadProgress::clear`,
//!   under `SnapshotProgressLock`.
//!
//! Taking the same lock therefore proves no writer is between creating and
//! settling such a file. The lock is necessary but not trusted alone: the
//! file must also be an old, single-link regular file owned by this user
//! whose recorded writer pid no longer exists, and its identity must be
//! unchanged immediately before the unlink. Any doubt keeps the file.
//!
//! Only `<support>/snapshots/destinations/<64 lowercase hex>/` is visited,
//! one level deep, through directory descriptors that never follow symlinks.
//! Canonical checkpoints, lock files, quarantined `*.corrupt.*` copies,
//! directories and anything else are never removed, and no lock file is ever
//! created. Startup and the hidden `local-state-sweep` command share this
//! code; the command's plan mode takes no locks and changes nothing.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

/// Exact `SnapshotSource::api_slug` values.
const SOURCES: [&str; 3] = ["claude_code", "codex", "pi"];
const MIN_AGE: Duration = Duration::from_secs(60 * 60);
const MAX_DIR_ENTRIES: usize = 10_000;
const TIME_BUDGET: Duration = Duration::from_secs(10);
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactKind {
    /// `<base>.json.<pid>.tmp`
    PidTemp,
    /// `<base>.json.<pid>.migrate`
    Migrate,
    /// `<base>.tmp.<pid>.<nanos>.json`
    TerminalTemp,
    /// `<base>.cleared.<pid>.<nanos>.json`
    ClearedTombstone,
}

/// Canonical base suffixes and the artifacts their writers are proven to
/// create only under the base's lock.
const BASES: [(&str, &[ArtifactKind]); 3] = [
    (
        "-scan-index-v3",
        &[ArtifactKind::PidTemp, ArtifactKind::Migrate],
    ),
    (
        "-scan-index-v3-upload-progress",
        &[
            ArtifactKind::PidTemp,
            ArtifactKind::Migrate,
            ArtifactKind::ClearedTombstone,
        ],
    ),
    ("-terminal-status-v1", &[ArtifactKind::TerminalTemp]),
];

#[derive(Debug, PartialEq, Eq)]
struct Artifact {
    base: String,
    kind: ArtifactKind,
    pid: i32,
    name_nanos: Option<u64>,
}

fn parse_artifact(name: &str) -> Option<Artifact> {
    for source in SOURCES {
        let Some(after_source) = name.strip_prefix(source) else {
            continue;
        };
        for (suffix, kinds) in BASES {
            let Some(rest) = after_source.strip_prefix(suffix) else {
                continue;
            };
            for kind in kinds {
                if let Some((pid, name_nanos)) = parse_artifact_suffix(*kind, rest) {
                    return Some(Artifact {
                        base: format!("{source}{suffix}"),
                        kind: *kind,
                        pid,
                        name_nanos,
                    });
                }
            }
        }
    }
    None
}

fn parse_artifact_suffix(kind: ArtifactKind, rest: &str) -> Option<(i32, Option<u64>)> {
    let pid_and_nanos = |middle: &str| {
        let (pid, nanos) = middle.split_once('.')?;
        Some((parse_pid(pid)?, Some(parse_nanos(nanos)?)))
    };
    match kind {
        ArtifactKind::PidTemp => {
            let pid = rest.strip_prefix(".json.")?.strip_suffix(".tmp")?;
            Some((parse_pid(pid)?, None))
        }
        ArtifactKind::Migrate => {
            let pid = rest.strip_prefix(".json.")?.strip_suffix(".migrate")?;
            Some((parse_pid(pid)?, None))
        }
        ArtifactKind::TerminalTemp => {
            pid_and_nanos(rest.strip_prefix(".tmp.")?.strip_suffix(".json")?)
        }
        ArtifactKind::ClearedTombstone => {
            pid_and_nanos(rest.strip_prefix(".cleared.")?.strip_suffix(".json")?)
        }
    }
}

/// A writer's `std::process::id()`: plain decimal in `1..=i32::MAX`.
fn parse_pid(value: &str) -> Option<i32> {
    if value.is_empty()
        || value.len() > 10
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<i32>().ok().filter(|pid| *pid > 0)
}

/// A writer's nanoseconds since the epoch, or `0` for a pre-epoch clock.
fn parse_nanos(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok()
}

fn is_destination_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PidState {
    Alive,
    Dead,
    Unknown,
}

fn probe_pid(pid: i32) -> PidState {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return PidState::Alive;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => PidState::Dead,
        // Exists but belongs to someone else.
        Some(libc::EPERM) => PidState::Alive,
        _ => PidState::Unknown,
    }
}

struct Policy {
    now: SystemTime,
    min_age: Duration,
    own_pid: i32,
    uid: u32,
    probe: fn(i32) -> PidState,
    max_entries: usize,
    time_budget: Duration,
    /// Runs after the lock is taken and before the final identity check.
    #[cfg(test)]
    before_recheck: Option<Box<dyn Fn(&str)>>,
}

impl Policy {
    fn production() -> Self {
        Self {
            now: SystemTime::now(),
            min_age: MIN_AGE,
            own_pid: i32::try_from(std::process::id()).unwrap_or(0),
            uid: unsafe { libc::getuid() },
            probe: probe_pid,
            max_entries: MAX_DIR_ENTRIES,
            time_budget: TIME_BUDGET,
            #[cfg(test)]
            before_recheck: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Read-only: no locks, no writes.
    Plan,
    Apply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SkipReason {
    Locked,
    Recent,
    LivePid,
    NoLockFile,
    Changed,
    UnsafeEntry,
    TooManyEntries,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
struct SkipCounts {
    locked: u64,
    recent: u64,
    live_pid: u64,
    no_lock_file: u64,
    changed: u64,
    unsafe_entry: u64,
    too_many_entries: u64,
}

impl SkipCounts {
    fn add(&mut self, reason: SkipReason) {
        let count = match reason {
            SkipReason::Locked => &mut self.locked,
            SkipReason::Recent => &mut self.recent,
            SkipReason::LivePid => &mut self.live_pid,
            SkipReason::NoLockFile => &mut self.no_lock_file,
            SkipReason::Changed => &mut self.changed,
            SkipReason::UnsafeEntry => &mut self.unsafe_entry,
            SkipReason::TooManyEntries => &mut self.too_many_entries,
        };
        *count += 1;
    }

    fn total(&self) -> u64 {
        self.locked
            + self.recent
            + self.live_pid
            + self.no_lock_file
            + self.changed
            + self.unsafe_entry
            + self.too_many_entries
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EntryOutcome {
    Removed,
    WouldRemove,
    Skipped,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LockState {
    NotChecked,
    Acquired,
    Held,
}

/// One recognized artifact or skipped directory, relative to the support
/// directory. Only the hidden command prints these; logs never do.
#[derive(Clone, Debug, Serialize)]
struct EntryReport {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<ArtifactKind>,
    bytes: u64,
    outcome: EntryOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<SkipReason>,
    lock: LockState,
}

#[derive(Debug, Default, Serialize)]
struct SweepReport {
    removed: u64,
    bytes_removed: u64,
    /// Plan mode: files that passed every check except the lock.
    candidates: u64,
    candidate_bytes: u64,
    skipped: SkipCounts,
    errors: u64,
    time_budget_exhausted: bool,
    entries: Vec<EntryReport>,
}

impl SweepReport {
    /// Content-free startup line, or `None` when there is nothing to say.
    fn log_line(&self, stage: &'static str) -> Option<String> {
        #[derive(Serialize)]
        struct Line<'a> {
            schema_version: u32,
            stage: &'static str,
            removed: u64,
            bytes_removed: u64,
            skipped: &'a SkipCounts,
            errors: u64,
            time_budget_exhausted: bool,
        }
        if self.removed == 0
            && self.skipped.total() == 0
            && self.errors == 0
            && !self.time_budget_exhausted
        {
            return None;
        }
        serde_json::to_string(&Line {
            schema_version: SCHEMA_VERSION,
            stage,
            removed: self.removed,
            bytes_removed: self.bytes_removed,
            skipped: &self.skipped,
            errors: self.errors,
            time_budget_exhausted: self.time_budget_exhausted,
        })
        .ok()
    }
}

/// File identity and every timestamp the age rule reads. Two looks that
/// compare equal name the same, unmodified file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    size: i64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    birthtime: Option<(i64, i64)>,
}

impl Identity {
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(stat: &libc::stat) -> Self {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let birthtime = Some((stat.st_birthtime as i64, stat.st_birthtime_nsec as i64));
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let birthtime = None;
        Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            mode: stat.st_mode as u32,
            uid: stat.st_uid as u32,
            nlink: stat.st_nlink as u64,
            size: stat.st_size as i64,
            mtime: (stat.st_mtime as i64, stat.st_mtime_nsec as i64),
            ctime: (stat.st_ctime as i64, stat.st_ctime_nsec as i64),
            birthtime,
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn file_type(&self) -> u32 {
        self.mode & libc::S_IFMT as u32
    }

    #[allow(clippy::unnecessary_cast)]
    fn is_regular(&self) -> bool {
        self.file_type() == libc::S_IFREG as u32
    }

    #[allow(clippy::unnecessary_cast)]
    fn is_directory(&self) -> bool {
        self.file_type() == libc::S_IFDIR as u32
    }

    fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    fn bytes(&self) -> u64 {
        u64::try_from(self.size).unwrap_or(0)
    }
}

fn stat_at(dir: RawFd, name: &CStr) -> std::io::Result<Identity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Identity::from_stat(unsafe { &stat.assume_init() }))
}

fn stat_fd(fd: RawFd) -> std::io::Result<Identity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Identity::from_stat(unsafe { &stat.assume_init() }))
}

fn open_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn clear_errno() {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
    }
}

enum Listing {
    Names(Vec<String>),
    TooMany,
    Failed,
}

/// Every UTF-8 entry name of `dir`, sorted; at most `cap` entries in total.
fn list_dir(dir: &OwnedFd, cap: usize) -> Listing {
    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return Listing::Failed;
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Listing::Failed;
    }
    // The duplicate shares the descriptor's offset; start from the top.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let mut seen = 0_usize;
    let listing = loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(0) | None => break Listing::Names(names),
                Some(_) => break Listing::Failed,
            }
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        seen += 1;
        if seen > cap {
            break Listing::TooMany;
        }
        if let Ok(name) = std::str::from_utf8(name) {
            names.push(name.to_string());
        }
    };
    unsafe { libc::closedir(stream) };
    match listing {
        Listing::Names(mut names) => {
            names.sort();
            Listing::Names(names)
        }
        other => other,
    }
}

/// An exclusive flock on an existing checkpoint lock file, released on drop.
struct HeldLock(OwnedFd);

impl Drop for HeldLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

enum LockFailure {
    Skip(SkipReason),
    Error,
}

enum Verdict {
    Removed,
    WouldRemove,
    Skip(SkipReason),
    Error,
}

struct Sweep<'a> {
    mode: Mode,
    policy: &'a Policy,
    started: Instant,
    record_entries: bool,
    report: SweepReport,
}

impl Sweep<'_> {
    fn out_of_time(&mut self) -> bool {
        if self.started.elapsed() > self.policy.time_budget {
            self.report.time_budget_exhausted = true;
        }
        self.report.time_budget_exhausted
    }

    fn record(&mut self, path: String, bytes: u64, verdict: &Verdict, lock: LockState) {
        self.record_artifact(path, None, bytes, verdict, lock);
    }

    fn record_artifact(
        &mut self,
        path: String,
        artifact: Option<ArtifactKind>,
        bytes: u64,
        verdict: &Verdict,
        lock: LockState,
    ) {
        let (outcome, reason) = match verdict {
            Verdict::Removed => {
                self.report.removed += 1;
                self.report.bytes_removed += bytes;
                (EntryOutcome::Removed, None)
            }
            Verdict::WouldRemove => {
                self.report.candidates += 1;
                self.report.candidate_bytes += bytes;
                (EntryOutcome::WouldRemove, None)
            }
            Verdict::Skip(reason) => {
                self.report.skipped.add(*reason);
                (EntryOutcome::Skipped, Some(*reason))
            }
            Verdict::Error => {
                self.report.errors += 1;
                (EntryOutcome::Error, None)
            }
        };
        if self.record_entries {
            self.report.entries.push(EntryReport {
                path,
                artifact,
                bytes,
                outcome,
                reason,
                lock,
            });
        }
    }

    fn run(&mut self, support_dir: &Path) {
        let Ok(path) = CString::new(support_dir.as_os_str().as_bytes()) else {
            self.record(".".to_string(), 0, &Verdict::Error, LockState::NotChecked);
            return;
        };
        let Some(support) = self.open_directory(libc::AT_FDCWD, &path, ".".to_string()) else {
            return;
        };
        let Some(snapshots) =
            self.open_directory(support.as_raw_fd(), c"snapshots", "snapshots".to_string())
        else {
            return;
        };
        let Some(destinations) = self.open_directory(
            snapshots.as_raw_fd(),
            c"destinations",
            "snapshots/destinations".to_string(),
        ) else {
            return;
        };
        let Some(names) = self.list(&destinations, "snapshots/destinations") else {
            return;
        };
        for name in names {
            if self.out_of_time() {
                return;
            }
            if !is_destination_name(&name) {
                continue;
            }
            let Ok(c_name) = CString::new(name.as_str()) else {
                continue;
            };
            let relative = format!("snapshots/destinations/{name}");
            if let Some(destination) =
                self.open_directory(destinations.as_raw_fd(), &c_name, relative.clone())
            {
                self.sweep_destination(&destination, &relative);
            }
        }
    }

    /// Opens `name` under `parent` as a real directory owned by this user
    /// and writable only by it. A missing directory is silently absent;
    /// anything else that is not such a directory is counted and skipped.
    fn open_directory(&mut self, parent: RawFd, name: &CStr, relative: String) -> Option<OwnedFd> {
        let first = match stat_at(parent, name) {
            Ok(identity) => identity,
            Err(error) if error.kind() == ErrorKind::NotFound => return None,
            Err(_) => {
                self.record(relative, 0, &Verdict::Error, LockState::NotChecked);
                return None;
            }
        };
        if !self.safe_directory(&first) {
            self.record(
                relative,
                0,
                &Verdict::Skip(SkipReason::UnsafeEntry),
                LockState::NotChecked,
            );
            return None;
        }
        let directory = match open_at(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        ) {
            Ok(directory) => directory,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) =>
            {
                self.record(
                    relative,
                    0,
                    &Verdict::Skip(SkipReason::UnsafeEntry),
                    LockState::NotChecked,
                );
                return None;
            }
            Err(_) => {
                self.record(relative, 0, &Verdict::Error, LockState::NotChecked);
                return None;
            }
        };
        match stat_fd(directory.as_raw_fd()) {
            Ok(opened) if opened.same_object(&first) && self.safe_directory(&opened) => {
                Some(directory)
            }
            Ok(_) => {
                self.record(
                    relative,
                    0,
                    &Verdict::Skip(SkipReason::Changed),
                    LockState::NotChecked,
                );
                None
            }
            Err(_) => {
                self.record(relative, 0, &Verdict::Error, LockState::NotChecked);
                None
            }
        }
    }

    fn safe_directory(&self, identity: &Identity) -> bool {
        identity.is_directory() && identity.uid == self.policy.uid && identity.mode & 0o022 == 0
    }

    fn list(&mut self, directory: &OwnedFd, relative: &str) -> Option<Vec<String>> {
        match list_dir(directory, self.policy.max_entries) {
            Listing::Names(names) => Some(names),
            Listing::TooMany => {
                self.record(
                    relative.to_string(),
                    0,
                    &Verdict::Skip(SkipReason::TooManyEntries),
                    LockState::NotChecked,
                );
                None
            }
            Listing::Failed => {
                self.record(
                    relative.to_string(),
                    0,
                    &Verdict::Error,
                    LockState::NotChecked,
                );
                None
            }
        }
    }

    fn sweep_destination(&mut self, directory: &OwnedFd, relative: &str) {
        let Some(names) = self.list(directory, relative) else {
            return;
        };
        let mut removed_any = false;
        for name in names {
            if self.out_of_time() {
                break;
            }
            let Some(artifact) = parse_artifact(&name) else {
                continue;
            };
            let (verdict, bytes, lock) = self.consider(directory.as_raw_fd(), &name, &artifact);
            removed_any |= matches!(verdict, Verdict::Removed);
            self.record_artifact(
                format!("{relative}/{name}"),
                Some(artifact.kind),
                bytes,
                &verdict,
                lock,
            );
        }
        if removed_any && unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
            self.report.errors += 1;
        }
    }

    fn consider(
        &mut self,
        dir: RawFd,
        name: &str,
        artifact: &Artifact,
    ) -> (Verdict, u64, LockState) {
        let not_checked = |verdict, bytes| (verdict, bytes, LockState::NotChecked);
        let Ok(c_name) = CString::new(name) else {
            return not_checked(Verdict::Skip(SkipReason::UnsafeEntry), 0);
        };
        let first = match stat_at(dir, &c_name) {
            Ok(identity) => identity,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return not_checked(Verdict::Skip(SkipReason::Changed), 0)
            }
            Err(_) => return not_checked(Verdict::Error, 0),
        };
        let bytes = first.bytes();
        if !first.is_regular() || first.uid != self.policy.uid || first.nlink != 1 {
            return not_checked(Verdict::Skip(SkipReason::UnsafeEntry), bytes);
        }
        let Ok(lock_name) = CString::new(format!("{}.lock", artifact.base)) else {
            return not_checked(Verdict::Error, bytes);
        };
        let lock_identity = match stat_at(dir, &lock_name) {
            Ok(identity) if identity.is_regular() && identity.uid == self.policy.uid => identity,
            Ok(_) => return not_checked(Verdict::Skip(SkipReason::UnsafeEntry), bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return not_checked(Verdict::Skip(SkipReason::NoLockFile), bytes)
            }
            Err(_) => return not_checked(Verdict::Error, bytes),
        };
        if !self.old_enough(&first, artifact.name_nanos) {
            return not_checked(Verdict::Skip(SkipReason::Recent), bytes);
        }
        if !self.writer_gone(artifact.pid) {
            return not_checked(Verdict::Skip(SkipReason::LivePid), bytes);
        }
        if self.mode == Mode::Plan {
            return not_checked(Verdict::WouldRemove, bytes);
        }
        let _lock = match self.lock(dir, &lock_name, &lock_identity) {
            Ok(lock) => lock,
            Err(LockFailure::Skip(SkipReason::Locked)) => {
                return (Verdict::Skip(SkipReason::Locked), bytes, LockState::Held)
            }
            Err(LockFailure::Skip(reason)) => return not_checked(Verdict::Skip(reason), bytes),
            Err(LockFailure::Error) => return not_checked(Verdict::Error, bytes),
        };
        let acquired = |verdict| (verdict, bytes, LockState::Acquired);
        #[cfg(test)]
        if let Some(hook) = &self.policy.before_recheck {
            hook(name);
        }
        match stat_at(dir, &c_name) {
            Ok(second) if second == first => {}
            Ok(_) => return acquired(Verdict::Skip(SkipReason::Changed)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return acquired(Verdict::Skip(SkipReason::Changed))
            }
            Err(_) => return acquired(Verdict::Error),
        }
        if !self.writer_gone(artifact.pid) {
            return acquired(Verdict::Skip(SkipReason::LivePid));
        }
        if unsafe { libc::unlinkat(dir, c_name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            return acquired(if error.kind() == ErrorKind::NotFound {
                Verdict::Skip(SkipReason::Changed)
            } else {
                Verdict::Error
            });
        }
        acquired(Verdict::Removed)
    }

    /// Non-blocking exclusive flock on the existing canonical lock file. The
    /// lock file is opened read-only and is never created or replaced.
    fn lock(
        &self,
        dir: RawFd,
        name: &CStr,
        expected: &Identity,
    ) -> std::result::Result<HeldLock, LockFailure> {
        let fd = match open_at(
            dir,
            name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(LockFailure::Skip(SkipReason::NoLockFile))
            }
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(LockFailure::Skip(SkipReason::UnsafeEntry))
            }
            Err(_) => return Err(LockFailure::Error),
        };
        match stat_fd(fd.as_raw_fd()) {
            Ok(opened) if opened.same_object(expected) && opened.is_regular() => {}
            Ok(_) => return Err(LockFailure::Skip(SkipReason::Changed)),
            Err(_) => return Err(LockFailure::Error),
        }
        if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                LockFailure::Skip(SkipReason::Locked)
            } else {
                LockFailure::Error
            });
        }
        Ok(HeldLock(fd))
    }

    /// The newest of every timestamp, including one recorded in the name,
    /// must be at least `min_age` old. A future timestamp is never old.
    fn old_enough(&self, identity: &Identity, name_nanos: Option<u64>) -> bool {
        const NANOS: i128 = 1_000_000_000;
        let Ok(now) = self.policy.now.duration_since(UNIX_EPOCH) else {
            return false;
        };
        let now = now.as_nanos() as i128;
        let to_nanos =
            |(seconds, nanos): (i64, i64)| i128::from(seconds) * NANOS + i128::from(nanos);
        let mut newest = to_nanos(identity.mtime).max(to_nanos(identity.ctime));
        if let Some(birthtime) = identity.birthtime {
            newest = newest.max(to_nanos(birthtime));
        }
        if let Some(name_nanos) = name_nanos {
            newest = newest.max(i128::from(name_nanos));
        }
        newest <= now && now - newest >= self.policy.min_age.as_nanos() as i128
    }

    /// Only a pid that is not ours and that the kernel says does not exist.
    fn writer_gone(&self, pid: i32) -> bool {
        pid != self.policy.own_pid && (self.policy.probe)(pid) == PidState::Dead
    }
}

fn sweep(support_dir: &Path, mode: Mode, policy: &Policy, record_entries: bool) -> SweepReport {
    let mut sweep = Sweep {
        mode,
        policy,
        started: Instant::now(),
        record_entries,
        report: SweepReport::default(),
    };
    sweep.run(support_dir);
    sweep.report
}

/// Best-effort startup pass over the daemon's own support directory. Call
/// before any snapshot worker starts. Never fails or panics; logs one
/// content-free line only when it removed, skipped or failed something.
pub fn sweep_local_state_at_startup() {
    let support_dir = ottto_core::default_support_dir();
    let report =
        std::panic::catch_unwind(|| sweep(&support_dir, Mode::Apply, &Policy::production(), false))
            .unwrap_or_else(|_| SweepReport {
                errors: 1,
                ..SweepReport::default()
            });
    if let Some(line) = report.log_line("startup") {
        eprintln!("ottto-service: local_state_sweep {line}");
    }
}

/// Directories the hidden command must never apply to: the daemon cleans
/// its own support directory at startup.
fn protected_support_dirs() -> Vec<PathBuf> {
    let mut directories = vec![ottto_core::default_support_dir()];
    if let Ok(home) = std::env::var("HOME") {
        directories.push(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Ottto"),
        );
    }
    directories
}

/// Refuses when `support_dir` (or its snapshot folders) is the same
/// directory as a protected support directory, however it is spelled.
fn refuse_protected(support_dir: &Path, protected: &[PathBuf]) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let identity = |path: &Path| {
        std::fs::metadata(path)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()))
    };
    let within = |root: &Path| {
        [
            root.to_path_buf(),
            root.join("snapshots"),
            root.join("snapshots").join("destinations"),
        ]
    };
    let protected: Vec<(u64, u64)> = protected
        .iter()
        .flat_map(|root| within(root.as_path()))
        .filter_map(|path| identity(&path))
        .collect();
    for path in within(support_dir) {
        if identity(&path).is_some_and(|candidate| protected.contains(&candidate)) {
            return Err(anyhow!(
                "refusing --apply on the daemon's own support directory; the daemon cleans it at startup"
            ));
        }
    }
    Ok(())
}

/// The hidden `local-state-sweep` command. `--plan` takes no locks and
/// writes nothing; `--apply` uses the startup guards and refuses the real
/// support directory.
pub fn run_local_state_sweep_command(support_dir: &Path, apply: bool, json: bool) -> Result<()> {
    let mode = if apply {
        refuse_protected(support_dir, &protected_support_dirs())?;
        Mode::Apply
    } else {
        Mode::Plan
    };
    let report = sweep(support_dir, mode, &Policy::production(), true);
    if json {
        #[derive(Serialize)]
        struct Output<'a> {
            schema_version: u32,
            mode: &'static str,
            #[serde(flatten)]
            report: &'a SweepReport,
        }
        let output = Output {
            schema_version: SCHEMA_VERSION,
            mode: if apply { "apply" } else { "plan" },
            report: &report,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("encode local state sweep report")?
        );
    } else {
        for entry in &report.entries {
            let reason = entry
                .reason
                .and_then(|reason| serde_json::to_value(reason).ok())
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            println!(
                "{:?} {} {} {reason}",
                entry.outcome, entry.bytes, entry.path
            );
        }
        println!(
            "removed {} ({} bytes), candidates {} ({} bytes), skipped {}, errors {}",
            report.removed,
            report.bytes_removed,
            report.candidates,
            report.candidate_bytes,
            report.skipped.total(),
            report.errors
        );
    }
    Ok(())
}
