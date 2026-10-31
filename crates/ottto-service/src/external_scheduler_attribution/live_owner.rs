//! Live proof that a provider session runs inside a launchd job's process tree.
//!
//! Claude Code opens and closes its transcript on every write, so an open-file
//! listing almost never names the owner. Each running Claude session instead
//! registers `<config>/sessions/<pid>.json` with its session id and process
//! start time, and the owner is that pid while a process with that start time
//! still runs. Codex keeps its rollout open for the life of a session, so the
//! owner shows up in the open files of a running candidate job's process tree.
//!
//! A scan asks `launchctl` about each candidate label at most once and lists
//! each running job tree's open files at most once. While no candidate job
//! runs, nothing beyond `launchctl` happens. Process records are read fresh for
//! every decision, and a job counts only while its pid still runs with the
//! start read right after `launchctl`, so a pid reused during the scan cannot
//! stand in for the job or one of its processes. A proven owner is remembered
//! for the session, so attribution survives the job's exit. Any doubt (a pid
//! reused, two live claims, two jobs, an incomplete listing) yields no proof.

use crate::snapshots::SnapshotSource;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use time::OffsetDateTime;

const MAX_ANCESTOR_DEPTH: usize = 8;
const MAX_TREE_DEPTH: usize = 8;
const MAX_TREE_PROCESSES: usize = 256;
const MAX_TREE_OPEN_PATHS: usize = 4096;
/// Claude config dirs whose registry a scan keeps. A registry beyond this is
/// read again for each session instead of skipped, so whether a session is
/// checked never depends on the order sessions are scanned in.
const MAX_CACHED_CLAUDE_REGISTRIES: usize = 64;
const MAX_PROVEN_SESSIONS: usize = 4096;
/// launchd starts every job's main process as its own direct child.
const LAUNCHD_PID: u32 = 1;

/// The parent, start time, and effective user of a running process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProcessRecord {
    pub(super) parent: u32,
    pub(super) started_unix_seconds: u64,
    pub(super) uid: u32,
}

/// A running Claude session's own registration claim. Untrusted until the pid
/// is shown to still run with the claimed start.
#[derive(Clone)]
pub(super) struct ClaudeSessionClaim {
    pub(super) pid: u32,
    pub(super) session_id: String,
    pub(super) proc_start: String,
}

/// What reading a process found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcessRead {
    Running(ProcessRecord),
    /// No such process runs.
    Gone,
    /// The process runs but its record is off limits, for example because
    /// another user owns it.
    Unreadable,
}

/// The children of a process. `complete` is false when the listing may have
/// been cut short.
pub(super) struct ChildList {
    pub(super) pids: Vec<u32>,
    pub(super) complete: bool,
}

/// The open file paths of a process. `complete` is false when the listing
/// failed or may have been cut short.
pub(super) struct OpenFileList {
    pub(super) paths: Vec<PathBuf>,
    pub(super) complete: bool,
}

/// What the live check reads from the operating system.
pub(super) trait ProcessHost {
    fn launchd_job_pid(&self, label: &str) -> Option<u32>;
    fn read_process(&self, pid: u32) -> ProcessRead;
    fn children(&self, pid: u32) -> ChildList;
    fn open_files(&self, pid: u32) -> OpenFileList;
    fn claude_sessions(&self, registry: &Path) -> Vec<ClaudeSessionClaim>;
    /// The effective user the daemon runs as.
    fn user_id(&self) -> u32;

    /// The record of a running process the daemon may read.
    fn process(&self, pid: u32) -> Option<ProcessRecord> {
        match self.read_process(pid) {
            ProcessRead::Running(record) => Some(record),
            ProcessRead::Gone | ProcessRead::Unreadable => None,
        }
    }
}

/// The session a live owner is sought for.
pub(super) struct OwnerQuery<'a> {
    pub(super) source: SnapshotSource,
    pub(super) source_session_id: &'a str,
    pub(super) transcript_path: &'a Path,
}

#[derive(Clone, Copy)]
pub(super) struct RunningJob {
    pid: u32,
    started_unix_seconds: u64,
}

impl RunningJob {
    /// Whether `record` is still the job's own process, not a later process
    /// that reused its pid.
    fn is_own_process(&self, record: &ProcessRecord) -> bool {
        record.started_unix_seconds == self.started_unix_seconds && record.parent == LAUNCHD_PID
    }

    fn still_runs(&self, host: &impl ProcessHost) -> bool {
        host.process(self.pid)
            .is_some_and(|record| self.is_own_process(&record))
    }
}

/// The job `launchctl` reports for `label`, anchored to its start time read
/// right after. Runs a subprocess, so callers keep it outside any lock.
pub(super) fn running_job(host: &impl ProcessHost, label: &str) -> Option<RunningJob> {
    let pid = host.launchd_job_pid(label)?;
    let record = host.process(pid)?;
    (record.parent == LAUNCHD_PID).then_some(RunningJob {
        pid,
        started_unix_seconds: record.started_unix_seconds,
    })
}

struct TreeOpenFiles {
    paths: BTreeSet<PathBuf>,
    complete: bool,
}

/// Process facts gathered once per scan and shared by every session in it.
#[derive(Default)]
pub(super) struct LiveScan {
    jobs: BTreeMap<String, Option<RunningJob>>,
    claude_registries: BTreeMap<PathBuf, Vec<ClaudeSessionClaim>>,
    job_open_files: BTreeMap<String, TreeOpenFiles>,
}

impl LiveScan {
    /// Candidate labels this scan has not yet asked `launchctl` about.
    pub(super) fn unknown_labels(&self, labels: &[&str]) -> Vec<String> {
        labels
            .iter()
            .filter(|label| !self.jobs.contains_key(**label))
            .map(|label| (*label).to_string())
            .collect()
    }

    /// Jobs looked up outside the scan lock. A label already answered keeps
    /// its first answer.
    pub(super) fn record_jobs(&mut self, jobs: Vec<(String, Option<RunningJob>)>) {
        for (label, job) in jobs {
            self.jobs.entry(label).or_insert(job);
        }
    }

    /// Candidate labels whose running job has the session in its process tree.
    pub(super) fn owner_labels(
        &mut self,
        host: &impl ProcessHost,
        query: &OwnerQuery<'_>,
        candidate_labels: &[&str],
    ) -> BTreeSet<String> {
        // A job that exited since `launchctl` answered, even if its pid now
        // runs something else, is no longer a candidate.
        let jobs = self
            .running_jobs(host, candidate_labels)
            .into_iter()
            .filter(|(_, job)| job.still_runs(host))
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            return BTreeSet::new();
        }
        match query.source {
            SnapshotSource::ClaudeCode => self.claude_owner_labels(host, query, &jobs),
            SnapshotSource::Codex | SnapshotSource::Pi => {
                self.open_file_owner_labels(host, query, &jobs)
            }
        }
    }

    fn running_jobs(
        &mut self,
        host: &impl ProcessHost,
        labels: &[&str],
    ) -> Vec<(String, RunningJob)> {
        labels
            .iter()
            .filter_map(|label| {
                let job = *self
                    .jobs
                    .entry((*label).to_string())
                    .or_insert_with(|| running_job(host, label));
                job.map(|job| ((*label).to_string(), job))
            })
            .collect()
    }

    fn claude_owner_labels(
        &mut self,
        host: &impl ProcessHost,
        query: &OwnerQuery<'_>,
        jobs: &[(String, RunningJob)],
    ) -> BTreeSet<String> {
        let Some(registry) = claude_registry_dir(query.transcript_path) else {
            return BTreeSet::new();
        };
        let transcript_stem = query
            .transcript_path
            .file_stem()
            .and_then(|value| value.to_str());
        let user = host.user_id();
        // A claim counts only while its pid still runs, as this user, with
        // the claimed start; a stale file whose pid was reused names a
        // different process.
        let owners = self
            .claude_claims(host, &registry)
            .into_iter()
            .filter(|claim| {
                claim.session_id == query.source_session_id
                    || Some(claim.session_id.as_str()) == transcript_stem
            })
            .filter_map(|claim| {
                let record = host.process(claim.pid)?;
                (record.uid == user
                    && process_start_witness(record.started_unix_seconds).as_deref()
                        == Some(claim.proc_start.trim()))
                .then_some((claim.pid, record))
            })
            .collect::<BTreeMap<_, _>>();
        // Two live processes claiming one session cannot both own it.
        if owners.len() != 1 {
            return BTreeSet::new();
        }
        let Some((owner, record)) = owners.into_iter().next() else {
            return BTreeSet::new();
        };
        let ancestors = ancestors(host, owner, record);
        // A chain read while the owner was reparented or replaced proves
        // nothing.
        if host.process(owner) != Some(record) {
            return BTreeSet::new();
        }
        jobs.iter()
            .filter(|(_, job)| {
                job.started_unix_seconds <= record.started_unix_seconds
                    && ancestors
                        .get(&job.pid)
                        .is_some_and(|ancestor| job.is_own_process(ancestor))
            })
            .map(|(label, _)| label.clone())
            .collect()
    }

    fn claude_claims(
        &mut self,
        host: &impl ProcessHost,
        registry: &Path,
    ) -> Vec<ClaudeSessionClaim> {
        if let Some(claims) = self.claude_registries.get(registry) {
            return claims.clone();
        }
        let claims = host.claude_sessions(registry);
        if self.claude_registries.len() < MAX_CACHED_CLAUDE_REGISTRIES {
            self.claude_registries
                .insert(registry.to_path_buf(), claims.clone());
        }
        claims
    }

    fn open_file_owner_labels(
        &mut self,
        host: &impl ProcessHost,
        query: &OwnerQuery<'_>,
        jobs: &[(String, RunningJob)],
    ) -> BTreeSet<String> {
        let resolved = std::fs::canonicalize(query.transcript_path).ok();
        let mut labels = BTreeSet::new();
        for (label, job) in jobs {
            let files = self
                .job_open_files
                .entry(label.clone())
                .or_insert_with(|| tree_open_files(host, *job));
            // An incomplete listing of any running candidate could hide a
            // second owner, so it cannot back a unique answer.
            if !files.complete {
                return BTreeSet::new();
            }
            if files.paths.contains(query.transcript_path)
                || resolved
                    .as_deref()
                    .is_some_and(|path| files.paths.contains(path))
            {
                labels.insert(label.clone());
            }
        }
        labels
    }
}

/// The owner and its ancestors, each read fresh. A parent must have started
/// no later than its child; otherwise the parent pid was reused and the walk
/// stops.
fn ancestors(
    host: &impl ProcessHost,
    owner: u32,
    record: ProcessRecord,
) -> BTreeMap<u32, ProcessRecord> {
    let mut values = BTreeMap::from([(owner, record)]);
    let (mut pid, mut child) = (record.parent, record);
    for _ in 0..MAX_ANCESTOR_DEPTH {
        if pid <= LAUNCHD_PID || values.contains_key(&pid) {
            break;
        }
        let Some(parent) = host.process(pid) else {
            break;
        };
        if parent.started_unix_seconds > child.started_unix_seconds {
            break;
        }
        values.insert(pid, parent);
        (pid, child) = (parent.parent, parent);
    }
    values
}

/// Open files across a running job's process tree. The root must still be the
/// job's own process. Any other process counts only when it is still the
/// listed parent's child and started no earlier than that parent, so a reused
/// pid is skipped, and so is a process that exited. A process the daemon may
/// not read (another user's) hides its own subtree, as does a failed or
/// cut-short listing or a process that changed while it was listed; each
/// leaves the result incomplete.
fn tree_open_files(host: &impl ProcessHost, job: RunningJob) -> TreeOpenFiles {
    let mut files = TreeOpenFiles {
        paths: BTreeSet::new(),
        complete: true,
    };
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([(job.pid, None::<(u32, u64)>, 0_usize)]);
    while let Some((pid, parent, depth)) = queue.pop_front() {
        if !visited.insert(pid) {
            continue;
        }
        if visited.len() > MAX_TREE_PROCESSES || depth > MAX_TREE_DEPTH {
            files.complete = false;
            break;
        }
        let before = match host.read_process(pid) {
            ProcessRead::Running(record) => Some(record),
            ProcessRead::Gone => None,
            ProcessRead::Unreadable => {
                files.complete = false;
                continue;
            }
        };
        let before = before.filter(|record| match parent {
            None => job.is_own_process(record),
            Some((parent, parent_started)) => {
                record.parent == parent && record.started_unix_seconds >= parent_started
            }
        });
        let Some(before) = before else {
            // Without its own process the job no longer runs at all.
            if parent.is_none() {
                files.complete = false;
            }
            continue;
        };
        let children = host.children(pid);
        let open = host.open_files(pid);
        match host.read_process(pid) {
            ProcessRead::Running(after) if after == before => {}
            // Exited meanwhile: it holds nothing now.
            ProcessRead::Gone if parent.is_some() => continue,
            _ => {
                files.complete = false;
                continue;
            }
        }
        if !children.complete || !open.complete {
            files.complete = false;
        }
        for path in open.paths {
            if files.paths.len() >= MAX_TREE_OPEN_PATHS {
                files.complete = false;
                break;
            }
            files.paths.insert(path);
        }
        queue.extend(
            children
                .pids
                .into_iter()
                .filter(|child| *child > LAUNCHD_PID)
                .map(|child| (child, Some((pid, before.started_unix_seconds)), depth + 1)),
        );
    }
    files
}

/// Whole entries in a `PROC_PIDLISTFDS` result of `written` bytes, or `None`
/// when the listing proves nothing. libproc reports a failure (no permission,
/// process gone) as 0 rather than -1 and sets `errno`, so 0 counts as no
/// descriptors only while `errno` stayed clear. A partial entry is a short
/// write, and a full buffer may have been cut short.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn listed_descriptor_count(
    written: i32,
    errno: i32,
    entry_size: usize,
    capacity: usize,
) -> Option<usize> {
    let written = usize::try_from(written)
        .ok()
        .filter(|written| *written > 0 || errno == 0)?;
    if entry_size == 0 || written % entry_size != 0 {
        return None;
    }
    let count = written / entry_size;
    (count < capacity).then_some(count)
}

/// `<config>/sessions` for a transcript at `<config>/projects/<slug>/<id>.jsonl`.
/// Claude keeps its running-session registry beside `projects` in whichever
/// config directory wrote the transcript.
fn claude_registry_dir(transcript_path: &Path) -> Option<PathBuf> {
    transcript_path
        .ancestors()
        .skip(1)
        .take(4)
        .find(|path| path.file_name().and_then(|value| value.to_str()) == Some("projects"))
        .and_then(Path::parent)
        .map(|config| config.join("sessions"))
}

/// The process start as Claude records it in `procStart`: the output of
/// `LC_ALL=C TZ=UTC ps -o lstart=`, for example `Wed Oct 14 14:55:36 2026`.
pub(super) fn process_start_witness(started_unix_seconds: u64) -> Option<String> {
    let value =
        OffsetDateTime::from_unix_timestamp(i64::try_from(started_unix_seconds).ok()?).ok()?;
    let weekday = value.weekday().to_string();
    let month = value.month().to_string();
    Some(format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {}",
        weekday.get(..3)?,
        month.get(..3)?,
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.year()
    ))
}

/// Sessions already proven to run under a single job, so a later scan keeps
/// the attribution after the job and its registration are gone. Bounded; the
/// oldest proof is forgotten first.
#[derive(Default)]
pub(super) struct ProvenOwners {
    order: VecDeque<(&'static str, String)>,
    owners: BTreeMap<(&'static str, String), String>,
}

impl ProvenOwners {
    pub(super) fn labels(&self, source: SnapshotSource, session_id: &str) -> BTreeSet<String> {
        self.owners
            .get(&(source.api_slug(), session_id.to_string()))
            .cloned()
            .into_iter()
            .collect()
    }

    /// Keeps only a unique owner. Two or more labels are an ambiguous answer
    /// that a later scan must stay free to settle.
    pub(super) fn remember(
        &mut self,
        source: SnapshotSource,
        session_id: &str,
        labels: &BTreeSet<String>,
    ) {
        if session_id.is_empty() || labels.len() != 1 {
            return;
        }
        let Some(label) = labels.first() else {
            return;
        };
        let key = (source.api_slug(), session_id.to_string());
        if self.owners.contains_key(&key) {
            return;
        }
        while self.order.len() >= MAX_PROVEN_SESSIONS {
            if let Some(oldest) = self.order.pop_front() {
                self.owners.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.owners.insert(key, label.clone());
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn proven_owners() -> &'static Mutex<ProvenOwners> {
    static PROVEN: OnceLock<Mutex<ProvenOwners>> = OnceLock::new();
    PROVEN.get_or_init(|| Mutex::new(ProvenOwners::default()))
}

#[cfg(target_os = "macos")]
pub(super) struct NativeHost;

#[cfg(target_os = "macos")]
mod native {
    use super::{
        ChildList, ClaudeSessionClaim, NativeHost, OpenFileList, ProcessHost, ProcessRead,
        ProcessRecord,
    };
    use std::path::{Path, PathBuf};

    const MAX_CHILDREN: usize = 256;
    const MAX_FILE_DESCRIPTORS: usize = 2048;
    /// `PROC_PIDFDVNODEPATHINFO` from `<sys/proc_info.h>`; `libc` binds the
    /// call but not this flavor or its result type.
    const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;

    /// `struct proc_fileinfo` from `<sys/proc_info.h>`. Only its size matters.
    #[allow(dead_code)]
    #[repr(C)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: libc::off_t,
        fi_type: i32,
        fi_guardflags: u32,
    }

    /// `struct vnode_fdinfowithpath` from `<sys/proc_info.h>`.
    #[allow(dead_code)]
    #[repr(C)]
    struct VnodeFdInfoWithPath {
        pfi: ProcFileInfo,
        pvip: libc::vnode_info_path,
    }

    impl ProcessHost for NativeHost {
        fn launchd_job_pid(&self, label: &str) -> Option<u32> {
            super::super::launchd_job_pid(label)
        }

        fn read_process(&self, pid: u32) -> ProcessRead {
            let Ok(kernel_pid) = libc::pid_t::try_from(pid) else {
                return ProcessRead::Gone;
            };
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let Ok(size) = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()) else {
                return ProcessRead::Unreadable;
            };
            clear_errno();
            // SAFETY: the buffer is writable for `size` bytes; the kernel
            // writes at most that many and reports how many it wrote.
            let returned = unsafe {
                libc::proc_pidinfo(
                    kernel_pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    size,
                )
            };
            if returned != size {
                // Another user's process is denied (EPERM) rather than
                // missing (ESRCH), and its subtree must not read as empty.
                return if returned == 0 && errno() == libc::ESRCH {
                    ProcessRead::Gone
                } else {
                    ProcessRead::Unreadable
                };
            }
            // SAFETY: the kernel filled the complete zero-initialized buffer.
            let info = unsafe { info.assume_init() };
            if info.pbi_pid != pid || info.pbi_start_tvsec == 0 {
                return ProcessRead::Unreadable;
            }
            ProcessRead::Running(ProcessRecord {
                parent: info.pbi_ppid,
                started_unix_seconds: info.pbi_start_tvsec,
                uid: info.pbi_uid,
            })
        }

        fn children(&self, pid: u32) -> ChildList {
            let Ok(kernel_pid) = libc::pid_t::try_from(pid) else {
                return ChildList {
                    pids: Vec::new(),
                    complete: false,
                };
            };
            let mut buffer = vec![0 as libc::pid_t; MAX_CHILDREN];
            let bytes = libc::c_int::try_from(std::mem::size_of_val(buffer.as_slice()))
                .unwrap_or(libc::c_int::MAX);
            // SAFETY: the buffer is writable for `bytes` bytes and the call
            // returns how many pids it wrote into it.
            let count =
                unsafe { libc::proc_listchildpids(kernel_pid, buffer.as_mut_ptr().cast(), bytes) };
            let Ok(count) = usize::try_from(count) else {
                return ChildList {
                    pids: Vec::new(),
                    complete: false,
                };
            };
            // A full buffer may mean more children than fit.
            let complete = count < MAX_CHILDREN;
            buffer.truncate(count.min(MAX_CHILDREN));
            ChildList {
                pids: buffer
                    .into_iter()
                    .filter_map(|child| u32::try_from(child).ok())
                    .filter(|child| *child > 1)
                    .collect(),
                complete,
            }
        }

        fn open_files(&self, pid: u32) -> OpenFileList {
            let incomplete = OpenFileList {
                paths: Vec::new(),
                complete: false,
            };
            let Ok(kernel_pid) = libc::pid_t::try_from(pid) else {
                return incomplete;
            };
            let entry = std::mem::size_of::<libc::proc_fdinfo>();
            let mut descriptors = Vec::<libc::proc_fdinfo>::with_capacity(MAX_FILE_DESCRIPTORS);
            let Ok(bytes) = libc::c_int::try_from(MAX_FILE_DESCRIPTORS * entry) else {
                return incomplete;
            };
            clear_errno();
            // SAFETY: the vector's spare capacity is writable for `bytes`
            // bytes; the kernel reports how many bytes of whole entries it wrote.
            let written = unsafe {
                libc::proc_pidinfo(
                    kernel_pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    descriptors.as_mut_ptr().cast(),
                    bytes,
                )
            };
            let Some(count) =
                super::listed_descriptor_count(written, errno(), entry, MAX_FILE_DESCRIPTORS)
            else {
                return incomplete;
            };
            // SAFETY: the kernel initialized `count` whole entries, and
            // `count` is below the capacity.
            unsafe { descriptors.set_len(count) };
            let mut paths = Vec::new();
            for descriptor in descriptors {
                if descriptor.proc_fdtype != libc::PROX_FDTYPE_VNODE as u32 {
                    continue;
                }
                // An unreadable vnode could be the transcript.
                let Some(path) = vnode_path(kernel_pid, descriptor.proc_fd) else {
                    return incomplete;
                };
                paths.extend(path);
            }
            OpenFileList {
                paths,
                complete: true,
            }
        }

        fn claude_sessions(&self, registry: &Path) -> Vec<ClaudeSessionClaim> {
            crate::claude_session_registrations::session_processes(registry)
                .into_iter()
                .map(|claim| ClaudeSessionClaim {
                    pid: claim.pid,
                    session_id: claim.session_id,
                    proc_start: claim.proc_start,
                })
                .collect()
        }

        fn user_id(&self) -> u32 {
            // SAFETY: `geteuid` has no preconditions and does not access memory.
            unsafe { libc::geteuid() }
        }
    }

    fn clear_errno() {
        // SAFETY: `__error` returns this thread's `errno`, valid for writes.
        unsafe { *libc::__error() = 0 };
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// The path of a vnode descriptor: `None` when the kernel would not
    /// describe it, `Some(None)` when it holds no path now (unlinked, or
    /// closed since it was listed).
    pub(super) fn vnode_path(pid: libc::pid_t, fd: i32) -> Option<Option<PathBuf>> {
        use std::os::unix::ffi::OsStrExt;
        let mut info = std::mem::MaybeUninit::<VnodeFdInfoWithPath>::zeroed();
        let size = libc::c_int::try_from(std::mem::size_of::<VnodeFdInfoWithPath>()).ok()?;
        clear_errno();
        // SAFETY: the buffer is writable for `size` bytes and the kernel
        // reports how many it wrote; only a complete result is read.
        let returned = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDVNODEPATHINFO,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if returned != size {
            // EBADF: the descriptor was closed, or reused for something
            // other than a file, after it was listed.
            return (returned == 0 && errno() == libc::EBADF).then_some(None);
        }
        // SAFETY: the kernel filled the complete zero-initialized buffer.
        let info = unsafe { info.assume_init() };
        let raw = info
            .pvip
            .vip_path
            .iter()
            .flatten()
            .map(|value| *value as u8)
            .collect::<Vec<_>>();
        // A path the kernel did not terminate was cut short.
        let end = raw.iter().position(|value| *value == 0)?;
        Some((end > 0).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&raw[..end]))))
    }
}

crate::heap_layout_bound::fields!(LiveScan; jobs, claude_registries, job_open_files);

crate::heap_layout_bound::fields!(RunningJob; pid, started_unix_seconds);

crate::heap_layout_bound::fields!(ProcessRecord; parent, started_unix_seconds, uid);

crate::heap_layout_bound::fields!(ClaudeSessionClaim; pid, session_id, proc_start);

crate::heap_layout_bound::fields!(TreeOpenFiles; paths, complete);

#[cfg(test)]
mod tests {
    use super::super::{
        ExternalSchedulerDefinition, ExternalSchedulerInventory, ExternalSchedulerKind,
        ExternalSchedulerSession, ScheduleConstraint, LIVE_OWNER_WRITE_WINDOW,
    };
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::time::SystemTime;

    #[derive(Default)]
    struct FakeHost {
        jobs: BTreeMap<String, u32>,
        processes: RefCell<BTreeMap<u32, ProcessRecord>>,
        /// Once a pid has been read this many times, it reads as the given
        /// record from then on (`None`: exited), mid-call if need be.
        replaced: BTreeMap<u32, (usize, Option<ProcessRecord>)>,
        reads: RefCell<BTreeMap<u32, usize>>,
        children: BTreeMap<u32, Vec<u32>>,
        cut_short_children: BTreeSet<u32>,
        open_files: BTreeMap<u32, Vec<PathBuf>>,
        failed_listings: BTreeSet<u32>,
        listed: RefCell<Vec<u32>>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl ProcessHost for FakeHost {
        fn launchd_job_pid(&self, label: &str) -> Option<u32> {
            self.calls.borrow_mut().push("launchctl");
            self.jobs.get(label).copied()
        }
        fn read_process(&self, pid: u32) -> ProcessRead {
            self.calls.borrow_mut().push("process");
            let mut reads = self.reads.borrow_mut();
            let read = reads.entry(pid).or_default();
            *read += 1;
            let record = match self.replaced.get(&pid) {
                Some((after, record)) if *read > *after => *record,
                _ => self.processes.borrow().get(&pid).copied(),
            };
            // As on macOS, another user's process is there but off limits.
            match record {
                Some(record) if record.uid == USER => ProcessRead::Running(record),
                Some(_) => ProcessRead::Unreadable,
                None => ProcessRead::Gone,
            }
        }
        fn children(&self, pid: u32) -> ChildList {
            self.calls.borrow_mut().push("children");
            ChildList {
                pids: self.children.get(&pid).cloned().unwrap_or_default(),
                complete: !self.cut_short_children.contains(&pid),
            }
        }
        fn open_files(&self, pid: u32) -> OpenFileList {
            self.calls.borrow_mut().push("open_files");
            self.listed.borrow_mut().push(pid);
            if self.failed_listings.contains(&pid) {
                return OpenFileList {
                    paths: Vec::new(),
                    complete: false,
                };
            }
            OpenFileList {
                paths: self.open_files.get(&pid).cloned().unwrap_or_default(),
                complete: true,
            }
        }
        fn claude_sessions(&self, registry: &Path) -> Vec<ClaudeSessionClaim> {
            self.calls.borrow_mut().push("claude_sessions");
            // The real registration reader over fixture files.
            crate::claude_session_registrations::session_processes(registry)
                .into_iter()
                .map(|claim| ClaudeSessionClaim {
                    pid: claim.pid,
                    session_id: claim.session_id,
                    proc_start: claim.proc_start,
                })
                .collect()
        }
        fn user_id(&self) -> u32 {
            USER
        }
    }

    impl FakeHost {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }

        fn set(&self, pid: u32, record: ProcessRecord) {
            self.processes.borrow_mut().insert(pid, record);
        }
    }

    const JOB: &str = "com.example.scheduled";
    const OTHER_JOB: &str = "com.example.other";
    const JOB_STARTED: u64 = 1_791_989_000;
    const OWNER_STARTED: u64 = 1_791_989_736;
    const USER: u32 = 501;

    fn scan_inventory(source: SnapshotSource, labels: &[&str]) -> ExternalSchedulerInventory {
        ExternalSchedulerInventory::from_definitions(
            labels
                .iter()
                .map(|label| ExternalSchedulerDefinition {
                    scheduler_kind: ExternalSchedulerKind::Launchd,
                    opaque_id: format!("opaque-{label}"),
                    launchd_label: Some((*label).to_string()),
                    provider_source: Some(source),
                    prompt_signature: None,
                    repository_hash: Some("repository".to_string()),
                    // Keep-alive / interval: no calendar, so only live proof counts.
                    schedule: ScheduleConstraint::default(),
                })
                .collect(),
        )
    }

    fn session<'a>(
        source: SnapshotSource,
        session_id: &'a str,
        transcript_path: &'a Path,
    ) -> ExternalSchedulerSession<'a> {
        ExternalSchedulerSession {
            source,
            normalized_template: None,
            repository_hash: Some("repository"),
            source_started_at: Some("2026-10-14T14:55:37Z"),
            source_session_id: session_id,
            transcript_path,
        }
    }

    fn query<'a>(source: SnapshotSource, transcript_path: &'a Path) -> OwnerQuery<'a> {
        OwnerQuery {
            source,
            source_session_id: "session",
            transcript_path,
        }
    }

    /// A Claude config dir holding a just-written transcript and the
    /// session's registration file, as Claude Code lays them out.
    struct ClaudeFixture {
        root: PathBuf,
        transcript: PathBuf,
    }

    impl ClaudeFixture {
        fn new(session_id: &str, registrations: &[(u32, &str)]) -> Self {
            let root = crate::test_scratch::private_dir("ottto-live-owner-claude");
            let project = root.join("projects/-repo");
            let sessions = root.join("sessions");
            fs::create_dir_all(&project).expect("project");
            fs::create_dir_all(&sessions).expect("sessions");
            let transcript = project.join(format!("{session_id}.jsonl"));
            fs::write(&transcript, "{}\n").expect("transcript");
            for (pid, start) in registrations {
                fs::write(
                    sessions.join(format!("{pid}.json")),
                    serde_json::json!({
                        "pid": pid, "sessionId": session_id, "cwd": "/repo",
                        "startedAt": OWNER_STARTED * 1000 + 1005, "procStart": start,
                        "kind": "interactive", "entrypoint": "sdk-cli", "pidDomain": "darwin",
                    })
                    .to_string(),
                )
                .expect("registration");
            }
            Self { root, transcript }
        }
    }

    impl Drop for ClaudeFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// launchd job 500 -> /bin/sh 600 -> provider 700.
    fn job_tree() -> FakeHost {
        FakeHost {
            jobs: BTreeMap::from([(JOB.to_string(), 500)]),
            processes: RefCell::new(BTreeMap::from([
                (500, record(1, JOB_STARTED)),
                (600, record(500, JOB_STARTED)),
                (700, record(600, OWNER_STARTED)),
            ])),
            children: BTreeMap::from([(500, vec![600]), (600, vec![700])]),
            ..FakeHost::default()
        }
    }

    /// `job_tree` with provider 700 holding `rollout` open.
    fn codex_job_tree(rollout: &Path) -> FakeHost {
        let mut host = job_tree();
        host.open_files.insert(700, vec![rollout.to_path_buf()]);
        host
    }

    fn witness() -> String {
        process_start_witness(OWNER_STARTED).expect("witness")
    }

    fn record(parent: u32, started_unix_seconds: u64) -> ProcessRecord {
        ProcessRecord {
            parent,
            started_unix_seconds,
            uid: USER,
        }
    }

    #[test]
    fn claude_session_is_attributed_through_its_registration_without_open_files() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness())]);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        let host = job_tree();
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        let labels = inventory.live_owner_labels(&session, &host, &proven, SystemTime::now());
        assert_eq!(labels, BTreeSet::from([JOB.to_string()]));
        assert!(!host.calls().contains(&"open_files"));
        let matched = inventory
            .correlate_with_live_labels(session, &labels)
            .expect("live match");
        assert_eq!(matched.evidence_kind, "live_process");
        assert_eq!(matched.evidence_strength, "direct");
    }

    #[test]
    fn claude_chain_through_a_reused_or_changed_process_proves_nothing() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness())]);
        let query = query(SnapshotSource::ClaudeCode, &fixture.transcript);
        // The shell's pid now runs a process that started after the owner.
        let reused_ancestor = job_tree();
        reused_ancestor.set(600, record(500, OWNER_STARTED + 5));
        // The owner was reparented while its chain was read.
        let mut reparented = job_tree();
        reparented
            .replaced
            .insert(700, (1, Some(record(1, OWNER_STARTED))));
        // The owner is younger than the job, but its chain no longer reaches it.
        let changed_parent = job_tree();
        changed_parent.set(700, record(650, OWNER_STARTED));
        changed_parent.set(650, record(1, JOB_STARTED));
        for host in [reused_ancestor, reparented, changed_parent] {
            assert!(LiveScan::default()
                .owner_labels(&host, &query, &[JOB])
                .is_empty());
        }
        // Control: the unchanged tree proves the job.
        assert_eq!(
            LiveScan::default().owner_labels(&job_tree(), &query, &[JOB]),
            BTreeSet::from([JOB.to_string()])
        );
    }

    #[test]
    fn users_own_claude_session_outside_the_job_proves_nothing() {
        let fixture = ClaudeFixture::new("claude-session", &[(900, &witness())]);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        // The job runs, but the session belongs to a terminal shell.
        let host = job_tree();
        host.set(800, record(1, JOB_STARTED - 3_600));
        host.set(900, record(800, OWNER_STARTED));
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        assert!(inventory
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
            .is_empty());
        assert!(!host.calls().contains(&"open_files"));
        assert!(proven
            .lock()
            .expect("proven")
            .labels(SnapshotSource::ClaudeCode, "claude-session")
            .is_empty());
    }

    #[test]
    fn codex_rollout_open_in_the_job_tree_is_attributed_once_per_scan() {
        let scratch = crate::test_scratch::private_dir("ottto-live-owner-codex");
        let first = scratch.join("rollout-first.jsonl");
        let second = scratch.join("rollout-second.jsonl");
        fs::write(&first, "{}\n").expect("first");
        fs::write(&second, "{}\n").expect("second");
        let mut host = job_tree();
        host.open_files.insert(
            700,
            vec![
                fs::canonicalize(&first).expect("first path"),
                fs::canonicalize(&second).expect("second path"),
            ],
        );
        let inventory = scan_inventory(SnapshotSource::Codex, &[JOB]);
        let proven = Mutex::new(ProvenOwners::default());
        for (id, path) in [("first", &first), ("second", &second)] {
            let session = session(SnapshotSource::Codex, id, path);
            assert_eq!(
                inventory.live_owner_labels(&session, &host, &proven, SystemTime::now()),
                BTreeSet::from([JOB.to_string()])
            );
        }
        let calls = host.calls();
        let count = |name| calls.iter().filter(|call| **call == name).count();
        assert_eq!(count("launchctl"), 1);
        assert_eq!(count("open_files"), 3);
        assert_eq!(count("claude_sessions"), 0);
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn an_incomplete_tree_listing_proves_nothing() {
        let rollout = PathBuf::from("/h/.codex/sessions/rollout-a.jsonl");
        let query = query(SnapshotSource::Codex, &rollout);
        // The shell's listing failed, so it may hold the rollout too.
        let mut failed = codex_job_tree(&rollout);
        failed.failed_listings.insert(600);
        // The job's children did not all fit.
        let mut cut_short = codex_job_tree(&rollout);
        cut_short.cut_short_children.insert(500);
        for host in [failed, cut_short] {
            assert!(LiveScan::default()
                .owner_labels(&host, &query, &[JOB])
                .is_empty());
        }
        assert_eq!(
            LiveScan::default().owner_labels(&codex_job_tree(&rollout), &query, &[JOB]),
            BTreeSet::from([JOB.to_string()])
        );
    }

    #[test]
    fn job_pid_reused_within_a_scan_proves_nothing_for_codex() {
        let first = PathBuf::from("/h/.codex/sessions/rollout-first.jsonl");
        let second = PathBuf::from("/h/.codex/sessions/rollout-second.jsonl");
        let reused = record(1, JOB_STARTED + 100);
        // After the listing: the job exits and its pid is reused, so the
        // listing taken earlier no longer stands for a running job.
        let mut host = job_tree();
        host.open_files
            .insert(700, vec![first.clone(), second.clone()]);
        let mut scan = LiveScan::default();
        assert_eq!(
            scan.owner_labels(&host, &query(SnapshotSource::Codex, &first), &[JOB]),
            BTreeSet::from([JOB.to_string()])
        );
        host.set(500, reused);
        assert!(scan
            .owner_labels(&host, &query(SnapshotSource::Codex, &second), &[JOB])
            .is_empty());
        // Before the listing: the pid is reused after the job is confirmed
        // but before its tree is read, and the reused process holds the
        // rollout.
        let mut host = FakeHost {
            jobs: BTreeMap::from([(JOB.to_string(), 500)]),
            processes: RefCell::new(BTreeMap::from([(500, record(1, JOB_STARTED))])),
            open_files: BTreeMap::from([(500, vec![first.clone()])]),
            ..FakeHost::default()
        };
        host.replaced.insert(500, (2, Some(reused)));
        assert!(LiveScan::default()
            .owner_labels(&host, &query(SnapshotSource::Codex, &first), &[JOB])
            .is_empty());
    }

    #[test]
    fn proven_owner_outlives_the_job() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness())]);
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        let first_scan = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        assert_eq!(
            first_scan.live_owner_labels(&session, &job_tree(), &proven, SystemTime::now()),
            BTreeSet::from([JOB.to_string()])
        );
        // The job exited and Claude removed its registration.
        fs::remove_file(fixture.root.join("sessions/700.json")).expect("registration");
        let later_scan = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        let gone = FakeHost::default();
        let later = SystemTime::now() + LIVE_OWNER_WRITE_WINDOW * 3;
        let labels = later_scan.live_owner_labels(&session, &gone, &proven, later);
        assert_eq!(labels, BTreeSet::from([JOB.to_string()]));
        assert!(gone.calls().is_empty());
        assert!(later_scan
            .correlate_with_live_labels(session, &labels)
            .is_some());
    }

    #[test]
    fn rollout_open_under_two_equal_jobs_is_ambiguous_and_not_remembered() {
        let scratch = crate::test_scratch::private_dir("ottto-live-owner-codex");
        let rollout = scratch.join("rollout.jsonl");
        fs::write(&rollout, "{}\n").expect("rollout");
        let path = fs::canonicalize(&rollout).expect("path");
        let host = FakeHost {
            jobs: BTreeMap::from([(JOB.to_string(), 500), (OTHER_JOB.to_string(), 800)]),
            processes: RefCell::new(BTreeMap::from([
                (500, record(1, JOB_STARTED)),
                (800, record(1, JOB_STARTED)),
            ])),
            open_files: BTreeMap::from([(500, vec![path.clone()]), (800, vec![path])]),
            ..FakeHost::default()
        };
        let inventory = scan_inventory(SnapshotSource::Codex, &[JOB, OTHER_JOB]);
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(SnapshotSource::Codex, "rollout", &rollout);
        let labels = inventory.live_owner_labels(&session, &host, &proven, SystemTime::now());
        assert_eq!(labels.len(), 2);
        assert!(inventory
            .correlate_with_live_labels(session, &labels)
            .is_none());
        assert!(proven
            .lock()
            .expect("proven")
            .labels(SnapshotSource::Codex, "rollout")
            .is_empty());
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn a_failed_or_partial_descriptor_listing_proves_nothing() {
        // libproc reports failure as 0 with errno set, sometimes -1.
        assert_eq!(listed_descriptor_count(0, libc::EPERM, 8, 2048), None);
        assert_eq!(listed_descriptor_count(-1, libc::EPERM, 8, 2048), None);
        assert_eq!(listed_descriptor_count(-1, 0, 8, 2048), None);
        assert_eq!(listed_descriptor_count(8 * 3 + 4, 0, 8, 2048), None);
        assert_eq!(listed_descriptor_count(8 * 2048, 0, 8, 2048), None);
        assert_eq!(listed_descriptor_count(8 * 3, 0, 8, 2048), Some(3));
        // A process that closed every descriptor.
        assert_eq!(listed_descriptor_count(0, 0, 8, 2048), Some(0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_host_reads_this_process_and_its_open_files() {
        let host = NativeHost;
        let pid = std::process::id();
        let own = host.process(pid).expect("own process record");
        assert_eq!(own.uid, host.user_id());
        // The native start must render exactly as `ps` renders it, since
        // Claude writes `procStart` from `ps`.
        let ps = crate::external_scheduler_attribution::bounded_command_stdout_with_env(
            "/bin/ps",
            &["-o", "lstart=", "-p", &pid.to_string()],
            256,
            &[("LC_ALL", "C"), ("TZ", "UTC")],
        )
        .and_then(|value| String::from_utf8(value).ok())
        .expect("ps start");
        assert_eq!(
            process_start_witness(own.started_unix_seconds).as_deref(),
            Some(ps.trim())
        );

        let scratch = crate::test_scratch::private_dir("ottto-live-owner");
        let held = scratch.join("rollout-held.jsonl");
        let file = std::fs::File::create(&held).expect("held file");
        let resolved = std::fs::canonicalize(&held).expect("resolved");
        // Other test threads open and close files meanwhile; a descriptor
        // closed between the listing and its path read is skipped.
        let open = host.open_files(pid);
        assert!(open.complete);
        assert!(open.paths.contains(&resolved));
        {
            use std::os::fd::AsRawFd;
            let kernel_pid = libc::pid_t::try_from(pid).expect("pid");
            let closed = std::fs::File::open(&held).expect("closed file");
            let fd = closed.as_raw_fd();
            assert_eq!(
                native::vnode_path(kernel_pid, fd),
                Some(Some(resolved.clone()))
            );
            drop(closed);
            // Closed reads as holding nothing, not as a failure, unless
            // another thread reused the number for a file of its own.
            let after = native::vnode_path(kernel_pid, fd);
            assert!(
                after
                    .as_ref()
                    .is_some_and(|path| path.as_ref() != Some(&resolved)),
                "{after:?}"
            );
        }
        drop(file);

        // launchd is another user's process to a normal user: its record and
        // descriptors are off limits, and neither reads as gone or empty.
        if host.user_id() != 0 {
            assert_eq!(host.read_process(1), ProcessRead::Unreadable);
            assert!(!host.open_files(1).complete);
        }
        let gone = std::process::Command::new("/usr/bin/true")
            .spawn()
            .and_then(|mut child| child.wait().map(|_| child.id()))
            .expect("exited child");
        assert_eq!(host.read_process(gone), ProcessRead::Gone);

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("child");
        let children = host.children(pid);
        assert!(children.complete);
        assert!(children.pids.contains(&child.id()));
        let child_record = host.process(child.id()).expect("child record");
        assert_eq!(child_record.parent, pid);
        assert!(child_record.started_unix_seconds >= own.started_unix_seconds);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(scratch);
    }
}
