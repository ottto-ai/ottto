//! Removes snapshot checkpoint temp files that a daemon left behind when it
//! died mid-save, and ages out old quarantined copies of invalid
//! checkpoints.
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
//! - `<base>.corrupt.<pid>.<nanos>.json`: the scan index's and the upload
//!   progress's loads rename a file they reject to this name
//!   (`quarantine_invalid_scan_index` under `CheckpointLock`,
//!   `quarantine_invalid_progress` under `SnapshotProgressLock`).
//!
//! Taking the same lock therefore proves no writer is between creating and
//! settling such a file. Only a single-link lock file owned by this user is
//! ever flocked, so a hard-linked copy of another tree's live lock is not.
//! The lock is necessary but not trusted alone: the file must also be an
//! old, single-link regular file owned by this user whose recorded writer
//! pid no longer exists, and its identity must be unchanged immediately
//! before the unlink. Any doubt keeps the file.
//!
//! Holding a free lock is not harmless either: every writer takes it
//! without blocking, so a save that another daemon starts while the sweep
//! holds it fails. Those writers live only in the `ottto-service`
//! executable (the `ottto` CLI does not link them, and `snapshot-audit` is
//! an `ottto-service` process too). So nothing is applied, and no lock is
//! taken, while any other process of this user runs an executable named
//! `ottto-service`: the process table is read before the pass applies
//! anything and again before every lock attempt, and once it shows such a
//! process, or cannot be read completely before the time budget runs out,
//! the rest of the pass applies nothing (`skipped.other_daemon`). An empty
//! table, one without this process, or a live process of this user whose
//! name or executable cannot be read all count as unreadable; a process
//! whose executable was deleted or replaced is known by its kernel name.
//! The startup pass runs before this daemon starts any worker of its own.
//! What remains is a daemon launched between the last process-table read
//! and the unlink, a window of a few syscalls;
//! launchd starts one instance per label, so that needs a second, manually
//! started daemon racing the first one's startup, and even then its save
//! only fails once and is retried on its next cycle.
//! The hidden command's `--apply` skips this check and reports
//! `not_applicable_non_default_dir`: it refuses, by device and inode, every
//! support directory a daemon of this user can use (the environment's and
//! the account database's home), so it only ever runs on copies.
//!
//! Nothing reads a quarantined copy's contents again; it is kept as
//! evidence, and its name next to the Claude index is prior-history
//! evidence (`claude_prior_history` in `snapshot_sync`), so every group
//! keeps at least one copy for good. Copies are pruned per group, one exact
//! base in one destination directory, and only from a complete look at the
//! whole group: the directory was listed in full, and every member is a
//! safe regular file with no future timestamp. A copy's age counts from the
//! newest of its name's timestamp, mtime, ctime and birthtime, since a
//! rename keeps the old index's mtime. The group's newest copies (by that
//! age, and by the name's timestamp; ties all count) are never removed;
//! every other copy is removed once 7 days old, and a plan that would leave
//! the group empty removes nothing from it. A group is pruned only while its
//! canonical `<base>.json` exists as a non-empty regular file of this user,
//! which shows the daemon rebuilt it; a copy is never opened or read. Each
//! removal takes the same guards as a temp: the existing lock, a writer pid
//! that no longer exists, no other daemon, and an unchanged identity, with
//! the canonical file and a kept copy of the group checked again under the
//! lock.
//!
//! Only `<support>/snapshots/destinations/<64 lowercase hex>/` is visited,
//! one level deep, through directory descriptors that never follow symlinks.
//! The support directory itself is opened one component at a time from `/`,
//! so a symlink anywhere on its path, or a `.`, `..`, empty or trailing-slash
//! component, skips the whole pass. Canonical checkpoints, lock files, the
//! upload receipts' `json.corrupt.*` copies, directories and anything else
//! are never removed, and no lock file is ever created. Startup and the
//! hidden `local-state-sweep` command share this code; the command's plan
//! mode takes no locks and changes nothing.
//!
//! The time budget is checked before every directory entry, path component
//! and candidate, and no directory is fsynced: an unlink lost to a crash is
//! simply redone at the next startup. A single syscall on a stalled local
//! filesystem can still block, exactly as the startup recovery hooks that
//! run just before this pass already block synchronously on the same
//! support directory (`FilePendingDeviceCredentialStore::load` in
//! `recover_pending_device_credential_at_startup`, the browser-auth
//! `read_state`, then `load_or_create_control_token`), so the pass adds no
//! new kind of startup hang.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr};
use std::io::{ErrorKind, Write};
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
/// A quarantined copy other than its group's newest is kept at least this
/// long; the newest are never removed.
const QUARANTINE_OTHER_MIN_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Canonical base suffixes whose loads quarantine an invalid file: the scan
/// index (`quarantine_invalid_scan_index`) and its upload progress
/// (`quarantine_invalid_progress`).
const QUARANTINE_BASES: [&str; 2] = ["-scan-index-v3", "-scan-index-v3-upload-progress"];
/// The only executable that links the checkpoint writers.
const DAEMON_EXECUTABLE: &str = ottto_core::OTTTO_SERVICE_BINARY_NAME;

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
    /// `<base>.corrupt.<pid>.<nanos>.json`, aged out by group instead of
    /// by `parse_artifact`.
    QuarantineCopy,
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
        ArtifactKind::QuarantineCopy => None,
    }
}

/// A quarantined copy's writer pid and the nanoseconds in its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuarantineCopy {
    pid: i32,
    name_nanos: u64,
}

/// For a name in a quarantine family, `<base>.corrupt.<anything>`, its exact
/// base and, when the rest is `<pid>.<nanos>.json` exactly as the writers
/// spell it, the parsed copy. A family name that does not parse is not a
/// copy, but it keeps its group from being pruned.
fn quarantine_member(name: &str) -> Option<(String, Option<QuarantineCopy>)> {
    for source in SOURCES {
        let Some(after_source) = name.strip_prefix(source) else {
            continue;
        };
        for suffix in QUARANTINE_BASES {
            let Some(rest) = after_source
                .strip_prefix(suffix)
                .and_then(|rest| rest.strip_prefix(".corrupt."))
            else {
                continue;
            };
            let copy = rest
                .strip_suffix(".json")
                .and_then(|middle| middle.split_once('.'))
                .and_then(|(pid, nanos)| {
                    Some(QuarantineCopy {
                        pid: parse_pid(pid)?,
                        name_nanos: parse_nanos(nanos)?,
                    })
                });
            return Some((format!("{source}{suffix}"), copy));
        }
    }
    None
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

/// What happens to each copy of one fully looked-at group, given its
/// `(age, name nanos)`: `None` removes it, `Some` keeps it for that reason.
/// The newest copies, by age and by the name's timestamp (ties all count),
/// are never removed; every other copy goes once 7 days old.
fn quarantine_plan(copies: &[(i128, u64)]) -> Vec<Option<SkipReason>> {
    let youngest = copies.iter().map(|&(age, _)| age).min();
    let latest_name = copies.iter().map(|&(_, name_nanos)| name_nanos).max();
    let mut plan: Vec<Option<SkipReason>> = copies
        .iter()
        .map(|&(age, name_nanos)| {
            if Some(age) == youngest || Some(name_nanos) == latest_name {
                Some(SkipReason::QuarantineKeptNewest)
            } else if age < QUARANTINE_OTHER_MIN_AGE.as_nanos() as i128 {
                Some(SkipReason::QuarantineRecent)
            } else {
                None
            }
        })
        .collect();
    keep_last_copies(&mut plan);
    plan
}

/// A plan that would remove every copy of a group removes none: a
/// quarantined copy next to the Claude index is prior-history evidence
/// (`claude_prior_history`), so a group is never emptied. The newest rule
/// already keeps one; this holds even if that rule changes.
fn keep_last_copies(plan: &mut [Option<SkipReason>]) {
    if plan.iter().all(Option::is_none) {
        plan.fill(Some(SkipReason::QuarantineKeptNewest));
    }
}

/// What a quarantined copy's removal checks again under its group's lock:
/// the canonical file still shows a rebuild, and a copy the plan keeps is
/// still there.
#[derive(Clone, Copy)]
struct KeptGroup<'a> {
    canonical: &'a CStr,
    kept: &'a CStr,
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

/// Whether another `ottto-service` process of this user may be running.
/// An error means the process table could not be read completely, also
/// when the sweep's deadline (asked before every process) ran out.
type DaemonProbe = Box<dyn Fn(&mut dyn FnMut() -> bool) -> std::io::Result<bool>>;

fn timed_out() -> std::io::Error {
    std::io::ErrorKind::TimedOut.into()
}

enum OtherDaemonCheck {
    /// Probe before applying anything and again before every lock attempt.
    Probe(DaemonProbe),
    /// The hidden command on a directory that `--apply` already proved is
    /// not a default support directory, which is the only one a daemon uses.
    NotApplicable,
}

struct Policy {
    now: SystemTime,
    min_age: Duration,
    own_pid: i32,
    uid: u32,
    probe: fn(i32) -> PidState,
    other_daemon: OtherDaemonCheck,
    max_entries: usize,
    time_budget: Duration,
    /// Runs after the lock is taken and before the final identity check.
    #[cfg(test)]
    before_recheck: Option<RecheckHook>,
    /// Treats the budget as spent after this many deadline checks.
    #[cfg(test)]
    expire_after_checks: Option<usize>,
}

#[cfg(test)]
type RecheckHook = Box<dyn Fn(&str)>;

impl Policy {
    fn production() -> Self {
        Self {
            now: SystemTime::now(),
            min_age: MIN_AGE,
            own_pid: i32::try_from(std::process::id()).unwrap_or(0),
            uid: unsafe { libc::getuid() },
            probe: probe_pid,
            other_daemon: OtherDaemonCheck::Probe(Box::new(other_daemon_running)),
            max_entries: MAX_DIR_ENTRIES,
            time_budget: TIME_BUDGET,
            #[cfg(test)]
            before_recheck: None,
            #[cfg(test)]
            expire_after_checks: None,
        }
    }
}

fn is_daemon_name(name: &[u8]) -> bool {
    name == DAEMON_EXECUTABLE.as_bytes()
}

fn is_daemon_path(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| is_daemon_name(name.as_bytes()))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod process_table {
    use std::mem::size_of;

    /// `PROC_PIDT_SHORTBSDINFO` and `struct proc_bsdshortinfo` from
    /// `<sys/proc_info.h>`. Unlike the full BSD info, the kernel serves it
    /// for every process, so a process of another user never reads as an
    /// error.
    const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)] // Mirrors the C layout; only some fields are read.
    pub(super) struct ShortBsdInfo {
        pub(super) pid: u32,
        pub(super) ppid: u32,
        pub(super) pgid: u32,
        pub(super) status: u32,
        pub(super) comm: [u8; 16],
        pub(super) flags: u32,
        pub(super) uid: libc::uid_t,
        pub(super) gid: libc::gid_t,
        pub(super) ruid: libc::uid_t,
        pub(super) rgid: libc::gid_t,
        pub(super) svuid: libc::uid_t,
        pub(super) svgid: libc::gid_t,
        pub(super) rfu: u32,
    }

    /// A libproc call's C return value and the errno read right after it.
    #[derive(Clone, Copy, Debug)]
    pub(super) struct Raw {
        pub(super) value: libc::c_int,
        pub(super) errno: i32,
    }

    /// The three libproc calls, behind a seam so tests can make them fail.
    pub(super) trait Libproc {
        /// `proc_listallpids`; an empty buffer asks for an estimate.
        fn list_all_pids(&self, pids: &mut [libc::pid_t]) -> Raw;
        /// `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)`.
        fn short_info(&self, pid: libc::pid_t, info: &mut ShortBsdInfo) -> Raw;
        /// `proc_pidpath`.
        fn path(&self, pid: libc::pid_t, buffer: &mut [u8]) -> Raw;
    }

    struct Native;

    fn raw(value: libc::c_int) -> Raw {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Raw { value, errno }
    }

    impl Libproc for Native {
        fn list_all_pids(&self, pids: &mut [libc::pid_t]) -> Raw {
            if pids.is_empty() {
                return raw(unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) });
            }
            let Ok(bytes) = libc::c_int::try_from(std::mem::size_of_val(pids)) else {
                return Raw {
                    value: -1,
                    errno: libc::EOVERFLOW,
                };
            };
            raw(unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) })
        }

        fn short_info(&self, pid: libc::pid_t, info: &mut ShortBsdInfo) -> Raw {
            raw(unsafe {
                libc::proc_pidinfo(
                    pid,
                    PROC_PIDT_SHORTBSDINFO,
                    0,
                    (info as *mut ShortBsdInfo).cast(),
                    size_of::<ShortBsdInfo>() as libc::c_int,
                )
            })
        }

        fn path(&self, pid: libc::pid_t, buffer: &mut [u8]) -> Raw {
            let size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            raw(unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), size) })
        }
    }

    fn failure(call: Raw) -> std::io::Error {
        match call.errno {
            0 => std::io::Error::other("process table call failed without an error"),
            errno => std::io::Error::from_raw_os_error(errno),
        }
    }

    fn all_pids(api: &dyn Libproc, own: libc::pid_t) -> std::io::Result<Vec<libc::pid_t>> {
        for _ in 0..4 {
            // libproc returns 0, not -1, when the underlying syscall fails,
            // so an empty table is a failure too.
            let estimate = api.list_all_pids(&mut []);
            if estimate.value <= 0 {
                return Err(failure(estimate));
            }
            let capacity = estimate.value as usize + 256;
            let mut pids = vec![0 as libc::pid_t; capacity];
            let count = api.list_all_pids(&mut pids);
            if count.value <= 0 {
                return Err(failure(count));
            }
            // A full buffer may have been truncated; ask again.
            if (count.value as usize) < capacity {
                pids.truncate(count.value as usize);
                // A table without this very process is not the whole table.
                if !pids.contains(&own) {
                    return Err(std::io::Error::other("process table without this process"));
                }
                return Ok(pids);
            }
        }
        Err(std::io::Error::other("process table kept growing"))
    }

    pub(super) fn other_daemon_running(
        out_of_time: &mut dyn FnMut() -> bool,
    ) -> std::io::Result<bool> {
        let own = libc::pid_t::try_from(std::process::id()).map_err(std::io::Error::other)?;
        other_daemon_running_with(&Native, own, unsafe { libc::getuid() }, out_of_time)
    }

    /// A same-user process is another daemon when its kernel name (`comm`)
    /// or its executable's basename is the daemon's. ESRCH (the process
    /// exited since the listing) is ignored, and a path lookup's ENOENT (its
    /// executable was deleted or replaced, as in an upgrade while it runs)
    /// leaves `comm` as its identity. Any other failure leaves the identity
    /// unknown, which fails the whole read.
    pub(super) fn other_daemon_running_with(
        api: &dyn Libproc,
        own: libc::pid_t,
        uid: libc::uid_t,
        out_of_time: &mut dyn FnMut() -> bool,
    ) -> std::io::Result<bool> {
        for pid in all_pids(api, own)? {
            if out_of_time() {
                return Err(super::timed_out());
            }
            if pid <= 0 || pid == own {
                continue;
            }
            let mut info = ShortBsdInfo::default();
            let filled = api.short_info(pid, &mut info);
            if filled.value <= 0 {
                if filled.errno == libc::ESRCH {
                    continue;
                }
                return Err(failure(filled));
            }
            if filled.value != size_of::<ShortBsdInfo>() as libc::c_int {
                return Err(std::io::Error::other("short process info"));
            }
            if info.uid != uid && info.ruid != uid {
                continue;
            }
            // `comm` is the executed file's name, cut at 16 bytes, which is
            // longer than the daemon's name.
            let comm = info.comm.split(|byte| *byte == 0).next().unwrap_or(&[]);
            if super::is_daemon_name(comm) {
                return Ok(true);
            }
            if pid_path(api, pid)?.is_some_and(|path| super::is_daemon_path(&path)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `None` when the process exited or its executable no longer exists.
    fn pid_path(
        api: &dyn Libproc,
        pid: libc::pid_t,
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        use std::os::unix::ffi::OsStrExt;
        let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let length = api.path(pid, &mut buffer);
        if length.value <= 0 {
            if length.errno == libc::ESRCH || length.errno == libc::ENOENT {
                return Ok(None);
            }
            return Err(failure(length));
        }
        buffer.truncate((length.value as usize).min(buffer.len()));
        Ok(Some(std::ffi::OsStr::from_bytes(&buffer).into()))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod process_table {
    use std::io::ErrorKind;

    fn gone(error: &std::io::Error) -> bool {
        error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    pub(super) fn other_daemon_running(
        out_of_time: &mut dyn FnMut() -> bool,
    ) -> std::io::Result<bool> {
        let own = std::process::id();
        let uid = unsafe { libc::getuid() };
        let mut saw_own = false;
        for entry in std::fs::read_dir("/proc")? {
            if out_of_time() {
                return Err(super::timed_out());
            }
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == own {
                saw_own = true;
                continue;
            }
            let dir = entry.path();
            let status = match std::fs::read_to_string(dir.join("status")) {
                Ok(status) => status,
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error),
            };
            let ids = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .ok_or_else(|| std::io::Error::other("process status without Uid"))?;
            // Real and effective uid.
            if !ids
                .split_whitespace()
                .take(2)
                .any(|id| id.parse::<u32>().ok() == Some(uid))
            {
                continue;
            }
            let comm = match std::fs::read(dir.join("comm")) {
                Ok(comm) => comm,
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error),
            };
            let comm = comm.strip_suffix(b"\n").unwrap_or(&comm);
            if super::is_daemon_name(comm) {
                return Ok(true);
            }
            // A deleted or missing executable leaves `comm`, checked above,
            // as the identity; any other unreadable executable link of a
            // live process of this user fails the whole read.
            let exe = match std::fs::read_link(dir.join("exe")) {
                Ok(exe) => exe.to_string_lossy().into_owned(),
                Err(error) if gone(&error) => continue,
                Err(error) => return Err(error),
            };
            let exe = std::path::PathBuf::from(exe.strip_suffix(" (deleted)").unwrap_or(&exe));
            if super::is_daemon_path(&exe) {
                return Ok(true);
            }
        }
        // A table without this very process is not the whole table.
        if !saw_own {
            return Err(std::io::Error::other("process table without this process"));
        }
        Ok(false)
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
mod process_table {
    pub(super) fn other_daemon_running(
        _out_of_time: &mut dyn FnMut() -> bool,
    ) -> std::io::Result<bool> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

use process_table::other_daemon_running;

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
    OtherDaemon,
    /// One of its group's newest quarantined copies, which are never
    /// removed.
    QuarantineKeptNewest,
    /// Another quarantined copy younger than 7 days, or one with a future
    /// timestamp.
    QuarantineRecent,
    /// The group's canonical file is missing or not a rebuilt one.
    QuarantineNoCanonical,
    /// Another member of the group could not be fully looked at.
    QuarantineGroupIncomplete,
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
    other_daemon: u64,
    quarantine_kept_newest: u64,
    quarantine_recent: u64,
    quarantine_no_canonical: u64,
    quarantine_group_incomplete: u64,
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
            SkipReason::OtherDaemon => &mut self.other_daemon,
            SkipReason::QuarantineKeptNewest => &mut self.quarantine_kept_newest,
            SkipReason::QuarantineRecent => &mut self.quarantine_recent,
            SkipReason::QuarantineNoCanonical => &mut self.quarantine_no_canonical,
            SkipReason::QuarantineGroupIncomplete => &mut self.quarantine_group_incomplete,
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
            + self.other_daemon
            + self.quarantine_kept_newest
            + self.quarantine_recent
            + self.quarantine_no_canonical
            + self.quarantine_group_incomplete
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

/// What the pass knows about other daemons. Anything but `clear` or
/// `not_applicable_non_default_dir` means nothing was applied after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OtherDaemonState {
    /// Plan mode, which takes no locks.
    #[default]
    NotChecked,
    Clear,
    Present,
    ProbeFailed,
    NotApplicableNonDefaultDir,
}

impl OtherDaemonState {
    fn blocks_apply(self) -> bool {
        matches!(self, Self::Present | Self::ProbeFailed)
    }
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
    /// Temps only; quarantined copies are counted apart.
    removed: u64,
    bytes_removed: u64,
    removed_quarantine: u64,
    bytes_removed_quarantine: u64,
    /// Plan mode: files that passed every check except the lock.
    candidates: u64,
    candidate_bytes: u64,
    skipped: SkipCounts,
    errors: u64,
    time_budget_exhausted: bool,
    other_daemon_check: OtherDaemonState,
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
            removed_quarantine: u64,
            bytes_removed_quarantine: u64,
            skipped: &'a SkipCounts,
            errors: u64,
            time_budget_exhausted: bool,
            other_daemon_check: OtherDaemonState,
        }
        if self.removed == 0
            && self.removed_quarantine == 0
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
            removed_quarantine: self.removed_quarantine,
            bytes_removed_quarantine: self.bytes_removed_quarantine,
            skipped: &self.skipped,
            errors: self.errors,
            time_budget_exhausted: self.time_budget_exhausted,
            other_daemon_check: self.other_daemon_check,
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
    OutOfTime,
}

/// Every UTF-8 entry name of `dir`, sorted; at most `cap` entries in total.
/// `out_of_time` is asked before every entry.
fn list_dir(dir: &OwnedFd, cap: usize, out_of_time: &mut dyn FnMut() -> bool) -> Listing {
    // `fdopendir` owns and closes its descriptor, so give it a copy, which
    // must not leak into a child that a running thread spawns meanwhile.
    let duplicate = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
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
        if out_of_time() {
            break Listing::OutOfTime;
        }
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
    #[cfg(test)]
    deadline_checks: usize,
}

impl Sweep<'_> {
    fn out_of_time(&mut self) -> bool {
        #[cfg(test)]
        {
            self.deadline_checks += 1;
            if self
                .policy
                .expire_after_checks
                .is_some_and(|checks| self.deadline_checks > checks)
            {
                self.report.time_budget_exhausted = true;
            }
        }
        if self.started.elapsed() > self.policy.time_budget {
            self.report.time_budget_exhausted = true;
        }
        self.report.time_budget_exhausted
    }

    /// Reads the process table unless an earlier read already stopped the
    /// pass from applying. Returns whether applying must stop. The read
    /// asks the deadline before every process; a read cut short by it, or
    /// a deadline that passed during it, counts as failed, so nothing is
    /// locked after the budget is spent.
    fn other_daemon_may_run(&mut self) -> bool {
        if self.report.other_daemon_check.blocks_apply() {
            return true;
        }
        let policy = self.policy;
        let state = match &policy.other_daemon {
            OtherDaemonCheck::NotApplicable => OtherDaemonState::NotApplicableNonDefaultDir,
            OtherDaemonCheck::Probe(probe) => {
                let result = probe(&mut || self.out_of_time());
                match result {
                    _ if self.out_of_time() => OtherDaemonState::ProbeFailed,
                    Ok(false) => OtherDaemonState::Clear,
                    Ok(true) => OtherDaemonState::Present,
                    Err(_) => OtherDaemonState::ProbeFailed,
                }
            }
        };
        self.report.other_daemon_check = state;
        state.blocks_apply()
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
            Verdict::Removed if artifact == Some(ArtifactKind::QuarantineCopy) => {
                self.report.removed_quarantine += 1;
                self.report.bytes_removed_quarantine += bytes;
                (EntryOutcome::Removed, None)
            }
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
        if self.mode == Mode::Apply {
            // The result sticks; candidates count as `other_daemon` below.
            self.other_daemon_may_run();
        }
        let Some(support) = self.open_support(support_dir) else {
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

    /// Opens the absolute `support_dir` one component at a time from `/`,
    /// none of which may be a symlink, and requires the last to be a safe
    /// directory. Spellings that a kernel lookup would normalize (`.`,
    /// `..`, empty components, a trailing slash) are refused, not resolved.
    fn open_support(&mut self, support_dir: &Path) -> Option<OwnedFd> {
        let unsafe_root = |sweep: &mut Self| {
            sweep.record(
                ".".to_string(),
                0,
                &Verdict::Skip(SkipReason::UnsafeEntry),
                LockState::NotChecked,
            );
            None
        };
        let Some(relative) = support_dir.as_os_str().as_bytes().strip_prefix(b"/") else {
            return unsafe_root(self);
        };
        let mut components = Vec::new();
        for component in relative.split(|byte| *byte == b'/') {
            match CString::new(component) {
                Ok(name) if !matches!(component, b"" | b"." | b"..") => components.push(name),
                _ => return unsafe_root(self),
            }
        }
        let Some((last, ancestors)) = components.split_last() else {
            return unsafe_root(self);
        };
        let mut parent = match open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(root) => root,
            Err(_) => {
                self.record(".".to_string(), 0, &Verdict::Error, LockState::NotChecked);
                return None;
            }
        };
        for name in ancestors {
            if self.out_of_time() {
                return None;
            }
            parent = match open_at(
                parent.as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            ) {
                Ok(directory) => directory,
                Err(error) if error.kind() == ErrorKind::NotFound => return None,
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR)
                    ) =>
                {
                    return unsafe_root(self)
                }
                Err(_) => {
                    self.record(".".to_string(), 0, &Verdict::Error, LockState::NotChecked);
                    return None;
                }
            };
        }
        if self.out_of_time() {
            return None;
        }
        self.open_directory(parent.as_raw_fd(), last, ".".to_string())
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
        let cap = self.policy.max_entries;
        match list_dir(directory, cap, &mut || self.out_of_time()) {
            Listing::Names(names) => Some(names),
            // Already recorded as `time_budget_exhausted`.
            Listing::OutOfTime => None,
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
        for name in &names {
            if self.out_of_time() {
                break;
            }
            let Some(artifact) = parse_artifact(name) else {
                continue;
            };
            let (verdict, bytes, lock) = self.consider(directory.as_raw_fd(), name, &artifact);
            self.record_artifact(
                format!("{relative}/{name}"),
                Some(artifact.kind),
                bytes,
                &verdict,
                lock,
            );
        }
        if !self.report.time_budget_exhausted {
            self.sweep_quarantine(directory.as_raw_fd(), relative, &names);
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
        let (lock_name, lock_identity) = match self.lock_file(dir, &artifact.base) {
            Ok(lock) => lock,
            Err(verdict) => return not_checked(verdict, bytes),
        };
        if !self.old_enough(&first, artifact.name_nanos) {
            return not_checked(Verdict::Skip(SkipReason::Recent), bytes);
        }
        self.unlink_under_lock(
            dir,
            name,
            &c_name,
            &first,
            &lock_name,
            &lock_identity,
            artifact.pid,
            None,
        )
    }

    /// The base's existing lock file: a single-link regular file of this
    /// user. A hard-linked lock may be another tree's live lock: never
    /// flock it.
    fn lock_file(
        &self,
        dir: RawFd,
        base: &str,
    ) -> std::result::Result<(CString, Identity), Verdict> {
        let Ok(lock_name) = CString::new(format!("{base}.lock")) else {
            return Err(Verdict::Error);
        };
        match stat_at(dir, &lock_name) {
            Ok(identity)
                if identity.is_regular()
                    && identity.uid == self.policy.uid
                    && identity.nlink == 1 =>
            {
                Ok((lock_name, identity))
            }
            Ok(_) => Err(Verdict::Skip(SkipReason::UnsafeEntry)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                Err(Verdict::Skip(SkipReason::NoLockFile))
            }
            Err(_) => Err(Verdict::Error),
        }
    }

    /// Ages out the quarantined copies among a fully listed destination's
    /// `names`, one group (one exact base) at a time. Returns early, with
    /// nothing more removed, once the time budget runs out.
    fn sweep_quarantine(&mut self, dir: RawFd, relative: &str, names: &[String]) {
        let mut groups: BTreeMap<String, Vec<(&str, Option<QuarantineCopy>)>> = BTreeMap::new();
        for name in names {
            if let Some((base, copy)) = quarantine_member(name) {
                groups.entry(base).or_default().push((name.as_str(), copy));
            }
        }
        for (base, members) in groups {
            if !self.prune_group(dir, relative, &base, &members) {
                return;
            }
        }
    }

    /// Looks at every member of one group before deciding anything; a
    /// member that cannot be looked at fully keeps the whole group. Returns
    /// `false` when the time budget ran out.
    fn prune_group(
        &mut self,
        dir: RawFd,
        relative: &str,
        base: &str,
        members: &[(&str, Option<QuarantineCopy>)],
    ) -> bool {
        struct Look<'n> {
            name: &'n str,
            c_name: CString,
            copy: QuarantineCopy,
            identity: Identity,
            age: i128,
        }
        let path = |name: &str| format!("{relative}/{name}");
        let kind = Some(ArtifactKind::QuarantineCopy);
        let mut looks = Vec::new();
        let mut complete = true;
        for &(name, copy) in members {
            if self.out_of_time() {
                return false;
            }
            // A family name its writers cannot produce is left alone.
            let (Some(copy), Ok(c_name)) = (copy, CString::new(name)) else {
                complete = false;
                continue;
            };
            let unsafe_entry = Verdict::Skip(SkipReason::UnsafeEntry);
            let (verdict, bytes) = match stat_at(dir, &c_name) {
                Ok(identity)
                    if identity.is_regular()
                        && identity.uid == self.policy.uid
                        && identity.nlink == 1 =>
                {
                    match self.age(&identity, Some(copy.name_nanos)) {
                        Some(age) => {
                            looks.push(Look {
                                name,
                                c_name,
                                copy,
                                identity,
                                age,
                            });
                            continue;
                        }
                        None => (
                            Verdict::Skip(SkipReason::QuarantineRecent),
                            identity.bytes(),
                        ),
                    }
                }
                Ok(identity) => (unsafe_entry, identity.bytes()),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    (Verdict::Skip(SkipReason::Changed), 0)
                }
                Err(_) => (Verdict::Error, 0),
            };
            complete = false;
            self.record_artifact(path(name), kind, bytes, &verdict, LockState::NotChecked);
        }
        let canonical = match CString::new(format!("{base}.json")) {
            Ok(canonical) if complete && self.rebuilt(dir, &canonical) => canonical,
            _ => {
                let verdict = Verdict::Skip(if complete {
                    SkipReason::QuarantineNoCanonical
                } else {
                    SkipReason::QuarantineGroupIncomplete
                });
                for look in &looks {
                    let bytes = look.identity.bytes();
                    self.record_artifact(
                        path(look.name),
                        kind,
                        bytes,
                        &verdict,
                        LockState::NotChecked,
                    );
                }
                return true;
            }
        };
        let ages: Vec<(i128, u64)> = looks
            .iter()
            .map(|look| (look.age, look.copy.name_nanos))
            .collect();
        let plan = quarantine_plan(&ages);
        // The plan keeps a copy of every group; it must still be there under
        // each removal's lock.
        let Some(kept) = plan.iter().position(Option::is_some) else {
            return true;
        };
        let group = KeptGroup {
            canonical: &canonical,
            kept: &looks[kept].c_name,
        };
        for (look, keep) in looks.iter().zip(&plan) {
            if self.out_of_time() {
                return false;
            }
            let bytes = look.identity.bytes();
            let (verdict, bytes, lock) = match keep {
                Some(reason) => (Verdict::Skip(*reason), bytes, LockState::NotChecked),
                None => match self.lock_file(dir, base) {
                    Ok((lock_name, lock_identity)) => self.unlink_under_lock(
                        dir,
                        look.name,
                        &look.c_name,
                        &look.identity,
                        &lock_name,
                        &lock_identity,
                        look.copy.pid,
                        Some(group),
                    ),
                    Err(verdict) => (verdict, bytes, LockState::NotChecked),
                },
            };
            self.record_artifact(path(look.name), kind, bytes, &verdict, lock);
        }
        true
    }

    /// Whether the canonical `<base>.json` shows the daemon rebuilt the
    /// quarantined checkpoint: a non-empty regular file this user owns and
    /// can read. It is never opened.
    fn rebuilt(&self, dir: RawFd, canonical: &CStr) -> bool {
        stat_at(dir, canonical).is_ok_and(|identity| {
            identity.is_regular()
                && identity.uid == self.policy.uid
                && identity.mode & 0o400 != 0
                && identity.size > 0
        })
    }

    /// The guards from the writer pid on, shared by temps and quarantined
    /// copies: a writer pid that no longer exists, no other daemon, the
    /// flock on the already checked `lock_name`, then under it an unchanged
    /// identity, the pid again and, for a quarantined copy, a canonical
    /// file that still shows a rebuild and a kept copy of its group that is
    /// still there. Plan mode stops before the lock.
    #[allow(clippy::too_many_arguments)]
    fn unlink_under_lock(
        &mut self,
        dir: RawFd,
        name: &str,
        c_name: &CStr,
        first: &Identity,
        lock_name: &CStr,
        lock_identity: &Identity,
        pid: i32,
        group: Option<KeptGroup<'_>>,
    ) -> (Verdict, u64, LockState) {
        let bytes = first.bytes();
        let not_checked = |verdict| (verdict, bytes, LockState::NotChecked);
        #[cfg(not(test))]
        let _ = name;
        if !self.writer_gone(pid) {
            return not_checked(Verdict::Skip(SkipReason::LivePid));
        }
        if self.mode == Mode::Plan {
            return not_checked(Verdict::WouldRemove);
        }
        if self.other_daemon_may_run() {
            return not_checked(Verdict::Skip(SkipReason::OtherDaemon));
        }
        let _lock = match self.lock(dir, lock_name, lock_identity) {
            Ok(lock) => lock,
            Err(LockFailure::Skip(SkipReason::Locked)) => {
                return (Verdict::Skip(SkipReason::Locked), bytes, LockState::Held)
            }
            Err(LockFailure::Skip(reason)) => return not_checked(Verdict::Skip(reason)),
            Err(LockFailure::Error) => return not_checked(Verdict::Error),
        };
        let acquired = |verdict| (verdict, bytes, LockState::Acquired);
        #[cfg(test)]
        if let Some(hook) = &self.policy.before_recheck {
            hook(name);
        }
        match stat_at(dir, c_name) {
            Ok(second) if second == *first => {}
            Ok(_) => return acquired(Verdict::Skip(SkipReason::Changed)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return acquired(Verdict::Skip(SkipReason::Changed))
            }
            Err(_) => return acquired(Verdict::Error),
        }
        if !self.writer_gone(pid) {
            return acquired(Verdict::Skip(SkipReason::LivePid));
        }
        if let Some(group) = group {
            if !self.rebuilt(dir, group.canonical) {
                return acquired(Verdict::Skip(SkipReason::QuarantineNoCanonical));
            }
            match stat_at(dir, group.kept) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return acquired(Verdict::Skip(SkipReason::Changed))
                }
                Err(_) => return acquired(Verdict::Error),
            }
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
            Ok(opened) if opened.same_object(expected) && opened.is_regular() => {
                if opened.nlink != 1 {
                    return Err(LockFailure::Skip(SkipReason::UnsafeEntry));
                }
            }
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
        self.age(identity, name_nanos)
            .is_some_and(|age| age >= self.policy.min_age.as_nanos() as i128)
    }

    /// Nanoseconds since the newest of every timestamp, including one
    /// recorded in the name; `None` for a timestamp in the future or a
    /// clock before the epoch.
    fn age(&self, identity: &Identity, name_nanos: Option<u64>) -> Option<i128> {
        const NANOS: i128 = 1_000_000_000;
        let now = self.policy.now.duration_since(UNIX_EPOCH).ok()?;
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
        (newest <= now).then_some(now - newest)
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
        #[cfg(test)]
        deadline_checks: 0,
    };
    sweep.run(support_dir);
    sweep.report
}

/// Best-effort startup pass over the daemon's own support directory. Call
/// before any snapshot worker starts. Never fails or panics; logs one
/// content-free line only when it removed, skipped or failed something.
pub fn sweep_local_state_at_startup() {
    let support_dir = ottto_core::default_support_dir();
    let report = startup_report(&support_dir, Policy::production);
    if let Some(line) = report.log_line("startup") {
        eprintln!("ottto-service: local_state_sweep {line}");
    }
}

/// The startup pass always checks for other daemons: `policy` must come
/// with a process-table probe.
fn startup_report(support_dir: &Path, policy: impl FnOnce() -> Policy) -> SweepReport {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let policy = policy();
        if !matches!(policy.other_daemon, OtherDaemonCheck::Probe(_)) {
            return SweepReport {
                errors: 1,
                ..SweepReport::default()
            };
        }
        sweep(support_dir, Mode::Apply, &policy, false)
    }))
    .unwrap_or_else(|_| SweepReport {
        errors: 1,
        ..SweepReport::default()
    })
}

/// Directories the hidden command must never apply to: every spelling of
/// the support directory a daemon of this user could be using, which the
/// daemon cleans itself at startup.
fn protected_support_dirs() -> Result<Vec<PathBuf>> {
    let under_home = |home: &Path| {
        home.join("Library")
            .join("Application Support")
            .join("Ottto")
    };
    let mut directories = vec![
        ottto_core::default_support_dir(),
        std::env::temp_dir().join("Ottto"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        directories.push(under_home(Path::new(&home)));
    }
    // HOME can be overridden; the account database cannot.
    let home = account_home().context("look up this account's home directory")?;
    directories.push(under_home(&home));
    Ok(directories)
}

/// This uid's home directory from the account database (`getpwuid_r`).
fn account_home() -> Result<PathBuf> {
    let mut buffer_len = 4096_usize;
    loop {
        let mut buffer = vec![0 as libc::c_char; buffer_len];
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer_len < 1 << 20 {
            buffer_len *= 2;
            continue;
        }
        if status != 0 || found.is_null() {
            return Err(anyhow!("no account entry for this uid"));
        }
        let directory = unsafe { (*found).pw_dir };
        if directory.is_null() {
            return Err(anyhow!("account entry without a home directory"));
        }
        let home = unsafe { CStr::from_ptr(directory) }.to_bytes();
        if home.is_empty() {
            return Err(anyhow!("account entry without a home directory"));
        }
        return Ok(PathBuf::from(OsStr::from_bytes(home)));
    }
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
    let protected = if apply {
        protected_support_dirs()?
    } else {
        Vec::new()
    };
    let stdout = std::io::stdout();
    local_state_sweep_command(
        support_dir,
        apply,
        json,
        &protected,
        Policy::production(),
        &mut stdout.lock(),
    )
}

fn local_state_sweep_command(
    support_dir: &Path,
    apply: bool,
    json: bool,
    protected: &[PathBuf],
    policy: Policy,
    out: &mut dyn Write,
) -> Result<()> {
    // The walk needs an absolute path. It is not normalized or
    // canonicalized, so a symlink or an odd spelling still skips the pass.
    let support_dir = if support_dir.is_absolute() {
        support_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve --support-dir")?
            .join(support_dir)
    };
    let mode = if apply {
        refuse_protected(&support_dir, protected)?;
        Mode::Apply
    } else {
        Mode::Plan
    };
    // `--apply` was just refused for every support directory a daemon of
    // this user can use, so no daemon contends for these locks.
    let policy = Policy {
        other_daemon: OtherDaemonCheck::NotApplicable,
        ..policy
    };
    let report = sweep(&support_dir, mode, &policy, true);
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
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&output).context("encode local state sweep report")?
        )?;
    } else {
        for entry in &report.entries {
            let reason = entry
                .reason
                .and_then(|reason| serde_json::to_value(reason).ok())
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            writeln!(
                out,
                "{:?} {} {} {reason}",
                entry.outcome, entry.bytes, entry.path
            )?;
        }
        let other_daemon_check = serde_json::to_value(report.other_daemon_check)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        writeln!(
            out,
            "removed {} ({} bytes), removed quarantined {} ({} bytes), candidates {} ({} bytes), skipped {}, errors {}, other daemon check {other_daemon_check}",
            report.removed,
            report.bytes_removed,
            report.removed_quarantine,
            report.bytes_removed_quarantine,
            report.candidates,
            report.candidate_bytes,
            report.skipped.total(),
            report.errors
        )?;
    }
    Ok(())
}
