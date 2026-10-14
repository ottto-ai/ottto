//! Live proof that a provider session runs inside a launchd job's process tree.
//!
//! Claude Code opens and closes its transcript on every write, so an open-file
//! listing almost never names the owner. Each running Claude session instead
//! registers `<config>/sessions/<pid>.json` with its session id and process
//! start time, and the owner is that pid while a process with that start time
//! still runs. Codex keeps its rollout open for the life of a session, so the
//! owner shows up in the open files of a running candidate job's process tree.
//!
//! A scan asks `launchctl` about each candidate label at most once, reads each
//! process at most once, and lists each running job tree's open files at most
//! once. While no candidate job runs, nothing beyond `launchctl` happens.
//! A proven owner is remembered for the session, so attribution survives the
//! job's exit. Any doubt (a pid reused, two live claims, a truncated listing)
//! yields no proof.

use crate::snapshots::SnapshotSource;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use time::OffsetDateTime;

const MAX_ANCESTOR_DEPTH: usize = 8;
const MAX_TREE_DEPTH: usize = 8;
const MAX_TREE_PROCESSES: usize = 256;
const MAX_TREE_OPEN_PATHS: usize = 4096;
const MAX_REMEMBERED_PROCESSES: usize = 4096;
const MAX_CLAUDE_REGISTRIES: usize = 8;
const MAX_PROVEN_SESSIONS: usize = 4096;
const MAX_PROVEN_LABELS: usize = 8;

/// The parent and start time of a running process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProcessRecord {
    pub(super) parent: u32,
    pub(super) started_unix_seconds: u64,
}

/// A running Claude session's own registration claim. Untrusted until the pid
/// is shown to still run with the claimed start.
#[derive(Clone)]
pub(super) struct ClaudeSessionClaim {
    pub(super) pid: u32,
    pub(super) session_id: String,
    pub(super) proc_start: String,
}

/// The children of a process. `complete` is false when the listing may have
/// been cut short.
pub(super) struct ChildList {
    pub(super) pids: Vec<u32>,
    pub(super) complete: bool,
}

/// The open file paths of a process. `complete` is false when the listing may
/// have been cut short.
pub(super) struct OpenFileList {
    pub(super) paths: Vec<PathBuf>,
    pub(super) complete: bool,
}

/// What the live check reads from the operating system.
pub(super) trait ProcessHost {
    fn launchd_job_pid(&self, label: &str) -> Option<u32>;
    fn process(&self, pid: u32) -> Option<ProcessRecord>;
    fn children(&self, pid: u32) -> ChildList;
    fn open_files(&self, pid: u32) -> OpenFileList;
    fn claude_sessions(&self, registry: &Path) -> Vec<ClaudeSessionClaim>;
}

/// The session a live owner is sought for.
pub(super) struct OwnerQuery<'a> {
    pub(super) source: SnapshotSource,
    pub(super) source_session_id: &'a str,
    pub(super) transcript_path: &'a Path,
}

#[derive(Clone, Copy)]
struct RunningJob {
    pid: u32,
    started_unix_seconds: u64,
}

struct TreeOpenFiles {
    paths: BTreeSet<PathBuf>,
    complete: bool,
}

/// Process facts gathered once per scan and shared by every session in it.
#[derive(Default)]
pub(super) struct LiveScan {
    jobs: BTreeMap<String, Option<RunningJob>>,
    processes: BTreeMap<u32, Option<ProcessRecord>>,
    claude_registries: BTreeMap<PathBuf, Vec<ClaudeSessionClaim>>,
    job_open_files: BTreeMap<String, TreeOpenFiles>,
}

impl LiveScan {
    /// Candidate labels whose running job has the session in its process tree.
    pub(super) fn owner_labels(
        &mut self,
        host: &impl ProcessHost,
        query: &OwnerQuery<'_>,
        candidate_labels: &[&str],
    ) -> BTreeSet<String> {
        let jobs = self.running_jobs(host, candidate_labels);
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
        let mut running = Vec::new();
        for label in labels {
            let job = match self.jobs.get(*label) {
                Some(job) => *job,
                None => {
                    // The job's own start time anchors every later reuse check.
                    let job = host.launchd_job_pid(label).and_then(|pid| {
                        self.process(host, pid).map(|record| RunningJob {
                            pid,
                            started_unix_seconds: record.started_unix_seconds,
                        })
                    });
                    self.jobs.insert((*label).to_string(), job);
                    job
                }
            };
            if let Some(job) = job {
                running.push(((*label).to_string(), job));
            }
        }
        running
    }

    fn process(&mut self, host: &impl ProcessHost, pid: u32) -> Option<ProcessRecord> {
        if let Some(record) = self.processes.get(&pid) {
            return *record;
        }
        let record = host.process(pid);
        if self.processes.len() < MAX_REMEMBERED_PROCESSES {
            self.processes.insert(pid, record);
        }
        record
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
        let claims = self
            .claude_claims(host, &registry)
            .into_iter()
            .filter(|claim| {
                claim.session_id == query.source_session_id
                    || Some(claim.session_id.as_str()) == transcript_stem
            })
            .collect::<Vec<_>>();
        // A claim counts only while its pid still runs with the claimed start;
        // a stale file whose pid was reused names a different process.
        let owners = claims
            .into_iter()
            .filter_map(|claim| {
                let record = self.process(host, claim.pid)?;
                (process_start_witness(record.started_unix_seconds).as_deref()
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
        let ancestors = self.ancestors(host, owner, record);
        jobs.iter()
            .filter(|(_, job)| {
                ancestors.contains(&job.pid)
                    && job.started_unix_seconds <= record.started_unix_seconds
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
        if self.claude_registries.len() >= MAX_CLAUDE_REGISTRIES {
            return Vec::new();
        }
        let claims = host.claude_sessions(registry);
        self.claude_registries
            .insert(registry.to_path_buf(), claims.clone());
        claims
    }

    /// The owner and its ancestors. A parent must have started no later than
    /// its child; otherwise the parent pid was reused and the walk stops.
    fn ancestors(
        &mut self,
        host: &impl ProcessHost,
        owner: u32,
        record: ProcessRecord,
    ) -> BTreeSet<u32> {
        let mut values = BTreeSet::from([owner]);
        let (mut pid, mut child) = (record.parent, record);
        for _ in 0..MAX_ANCESTOR_DEPTH {
            if pid <= 1 || values.contains(&pid) {
                break;
            }
            let Some(parent) = self.process(host, pid) else {
                break;
            };
            if parent.started_unix_seconds > child.started_unix_seconds {
                break;
            }
            values.insert(pid);
            (pid, child) = (parent.parent, parent);
        }
        values
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
            // A cut-short listing of any running candidate could hide a
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

/// Open files across a running job's process tree. A process counts only when
/// it is still the listed parent's child, started no earlier than that parent,
/// and kept the same parent and start across its listing, so a reused pid is
/// skipped.
fn tree_open_files(host: &impl ProcessHost, job: RunningJob) -> TreeOpenFiles {
    let mut files = TreeOpenFiles {
        paths: BTreeSet::new(),
        complete: true,
    };
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([(job.pid, None, job.started_unix_seconds, 0_usize)]);
    while let Some((pid, parent, parent_started, depth)) = queue.pop_front() {
        if !visited.insert(pid) {
            continue;
        }
        if visited.len() > MAX_TREE_PROCESSES || depth > MAX_TREE_DEPTH {
            files.complete = false;
            break;
        }
        let Some(before) = host.process(pid) else {
            continue;
        };
        if before.started_unix_seconds < parent_started
            || parent.is_some_and(|parent| parent != before.parent)
        {
            continue;
        }
        let children = host.children(pid);
        let open = host.open_files(pid);
        if host.process(pid) != Some(before) {
            continue;
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
                .filter(|child| *child > 1)
                .map(|child| (child, Some(pid), before.started_unix_seconds, depth + 1)),
        );
    }
    files
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

/// Sessions already proven to run under a job, so a later scan keeps the
/// attribution after the job and its registration are gone. Bounded; the
/// oldest proof is forgotten first.
#[derive(Default)]
pub(super) struct ProvenOwners {
    order: VecDeque<(&'static str, String)>,
    labels: BTreeMap<(&'static str, String), BTreeSet<String>>,
}

impl ProvenOwners {
    pub(super) fn labels(&self, source: SnapshotSource, session_id: &str) -> BTreeSet<String> {
        self.labels
            .get(&(source.api_slug(), session_id.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn remember(
        &mut self,
        source: SnapshotSource,
        session_id: &str,
        labels: &BTreeSet<String>,
    ) {
        if session_id.is_empty() || labels.is_empty() {
            return;
        }
        let key = (source.api_slug(), session_id.to_string());
        if let Some(current) = self.labels.get_mut(&key) {
            for label in labels {
                if current.len() >= MAX_PROVEN_LABELS {
                    break;
                }
                current.insert(label.clone());
            }
            return;
        }
        while self.order.len() >= MAX_PROVEN_SESSIONS {
            if let Some(oldest) = self.order.pop_front() {
                self.labels.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.labels.insert(
            key,
            labels.iter().take(MAX_PROVEN_LABELS).cloned().collect(),
        );
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
        ChildList, ClaudeSessionClaim, NativeHost, OpenFileList, ProcessHost, ProcessRecord,
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

        fn process(&self, pid: u32) -> Option<ProcessRecord> {
            let kernel_pid = libc::pid_t::try_from(pid).ok()?;
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
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
                return None;
            }
            // SAFETY: the kernel filled the complete zero-initialized buffer.
            let info = unsafe { info.assume_init() };
            (info.pbi_pid == pid && info.pbi_start_tvsec > 0).then_some(ProcessRecord {
                parent: info.pbi_ppid,
                started_unix_seconds: info.pbi_start_tvsec,
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
            let mut descriptors = Vec::<libc::proc_fdinfo>::with_capacity(MAX_FILE_DESCRIPTORS);
            let Ok(bytes) = libc::c_int::try_from(
                MAX_FILE_DESCRIPTORS * std::mem::size_of::<libc::proc_fdinfo>(),
            ) else {
                return incomplete;
            };
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
            let Ok(written) = usize::try_from(written) else {
                return incomplete;
            };
            let count = written / std::mem::size_of::<libc::proc_fdinfo>();
            if count > MAX_FILE_DESCRIPTORS {
                return incomplete;
            }
            // SAFETY: the kernel initialized `count` whole entries.
            unsafe { descriptors.set_len(count) };
            let mut paths = Vec::new();
            for descriptor in descriptors {
                if descriptor.proc_fdtype != libc::PROX_FDTYPE_VNODE as u32 {
                    continue;
                }
                if let Some(path) = vnode_path(kernel_pid, descriptor.proc_fd) {
                    paths.push(path);
                }
            }
            OpenFileList {
                paths,
                complete: count < MAX_FILE_DESCRIPTORS,
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
    }

    fn vnode_path(pid: libc::pid_t, fd: i32) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let mut info = std::mem::MaybeUninit::<VnodeFdInfoWithPath>::zeroed();
        let size = libc::c_int::try_from(std::mem::size_of::<VnodeFdInfoWithPath>()).ok()?;
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
            return None;
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
        let end = raw.iter().position(|value| *value == 0)?;
        (end > 0).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&raw[..end])))
    }
}

crate::heap_layout_bound::fields!(LiveScan; jobs, processes, claude_registries, job_open_files);

crate::heap_layout_bound::fields!(RunningJob; pid, started_unix_seconds);

crate::heap_layout_bound::fields!(ProcessRecord; parent, started_unix_seconds);

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
        processes: BTreeMap<u32, ProcessRecord>,
        children: BTreeMap<u32, Vec<u32>>,
        open_files: BTreeMap<u32, Vec<PathBuf>>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl ProcessHost for FakeHost {
        fn launchd_job_pid(&self, label: &str) -> Option<u32> {
            self.calls.borrow_mut().push("launchctl");
            self.jobs.get(label).copied()
        }
        fn process(&self, pid: u32) -> Option<ProcessRecord> {
            self.calls.borrow_mut().push("process");
            self.processes.get(&pid).copied()
        }
        fn children(&self, pid: u32) -> ChildList {
            self.calls.borrow_mut().push("children");
            ChildList {
                pids: self.children.get(&pid).cloned().unwrap_or_default(),
                complete: true,
            }
        }
        fn open_files(&self, pid: u32) -> OpenFileList {
            self.calls.borrow_mut().push("open_files");
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
    }

    impl FakeHost {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    const JOB: &str = "com.example.scheduled";
    const OTHER_JOB: &str = "com.example.other";
    const JOB_STARTED: u64 = 1_791_989_000;
    const OWNER_STARTED: u64 = 1_791_989_736;

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
            processes: BTreeMap::from([
                (500, record(1, JOB_STARTED)),
                (600, record(500, JOB_STARTED)),
                (700, record(600, OWNER_STARTED)),
            ]),
            children: BTreeMap::from([(500, vec![600]), (600, vec![700])]),
            ..FakeHost::default()
        }
    }

    fn witness() -> String {
        process_start_witness(OWNER_STARTED).expect("witness")
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
    fn claude_registration_whose_pid_was_reused_or_exited_proves_nothing() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness())]);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        // Pid 700 now belongs to a process that started later.
        let mut reused = job_tree();
        reused
            .processes
            .insert(700, record(600, OWNER_STARTED + 60));
        let proven = Mutex::new(ProvenOwners::default());
        assert!(inventory
            .live_owner_labels(&session, &reused, &proven, SystemTime::now())
            .is_empty());
        // Pid 700 is gone; the registration file is stale.
        let mut exited = job_tree();
        exited.processes.remove(&700);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        assert!(inventory
            .live_owner_labels(&session, &exited, &proven, SystemTime::now())
            .is_empty());
    }

    #[test]
    fn two_live_claims_on_one_claude_session_prove_nothing() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness()), (701, &witness())]);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        let mut host = job_tree();
        host.processes.insert(701, record(600, OWNER_STARTED));
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        assert!(inventory
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
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
    fn codex_process_older_than_its_job_is_a_reused_pid() {
        let scratch = crate::test_scratch::private_dir("ottto-live-owner-codex");
        let rollout = scratch.join("rollout.jsonl");
        fs::write(&rollout, "{}\n").expect("rollout");
        let mut host = job_tree();
        host.processes.insert(700, record(600, JOB_STARTED - 1));
        host.open_files
            .insert(700, vec![fs::canonicalize(&rollout).expect("path")]);
        let inventory = scan_inventory(SnapshotSource::Codex, &[JOB]);
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(SnapshotSource::Codex, "rollout", &rollout);
        assert!(inventory
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
            .is_empty());
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn nothing_but_launchctl_runs_while_no_candidate_job_runs() {
        let fixture = ClaudeFixture::new("claude-session", &[(700, &witness())]);
        let inventory = scan_inventory(SnapshotSource::ClaudeCode, &[JOB]);
        let host = FakeHost::default();
        let proven = Mutex::new(ProvenOwners::default());
        let session = session(
            SnapshotSource::ClaudeCode,
            "claude-session",
            &fixture.transcript,
        );
        assert!(inventory
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
            .is_empty());
        assert!(inventory
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
            .is_empty());
        assert_eq!(host.calls(), vec!["launchctl"]);

        // No candidate definition at all: not even launchctl.
        let unrelated = ExternalSchedulerInventory::default();
        let host = FakeHost::default();
        assert!(unrelated
            .live_owner_labels(&session, &host, &proven, SystemTime::now())
            .is_empty());
        assert!(host.calls().is_empty());
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
    fn rollout_open_under_two_equal_jobs_is_ambiguous() {
        let scratch = crate::test_scratch::private_dir("ottto-live-owner-codex");
        let rollout = scratch.join("rollout.jsonl");
        fs::write(&rollout, "{}\n").expect("rollout");
        let path = fs::canonicalize(&rollout).expect("path");
        let host = FakeHost {
            jobs: BTreeMap::from([(JOB.to_string(), 500), (OTHER_JOB.to_string(), 800)]),
            processes: BTreeMap::from([
                (500, record(1, JOB_STARTED)),
                (800, record(1, JOB_STARTED)),
            ]),
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
        let _ = fs::remove_dir_all(scratch);
    }

    fn record(parent: u32, started_unix_seconds: u64) -> ProcessRecord {
        ProcessRecord {
            parent,
            started_unix_seconds,
        }
    }

    #[test]
    fn start_witness_matches_the_claude_registration_format() {
        // Claude writes the registration (startedAt 1791989737005 ms) about a
        // second after the process starts.
        assert_eq!(
            process_start_witness(1_791_989_736).as_deref(),
            Some("Wed Oct 14 14:55:36 2026")
        );
        assert_eq!(
            process_start_witness(1_791_244_800).as_deref(),
            Some("Tue Oct  6 00:00:00 2026")
        );
    }

    #[test]
    fn registry_sits_beside_the_projects_directory_of_the_transcript() {
        assert_eq!(
            claude_registry_dir(Path::new("/h/.claude/projects/-repo/abc.jsonl")),
            Some(PathBuf::from("/h/.claude/sessions"))
        );
        assert_eq!(
            claude_registry_dir(Path::new("/h/config/projects/-repo/abc.jsonl")),
            Some(PathBuf::from("/h/config/sessions"))
        );
        assert_eq!(claude_registry_dir(Path::new("/h/other/abc.jsonl")), None);
    }

    #[test]
    fn a_cut_short_tree_listing_proves_nothing() {
        struct Truncating(FakeHost);
        impl ProcessHost for Truncating {
            fn launchd_job_pid(&self, label: &str) -> Option<u32> {
                self.0.launchd_job_pid(label)
            }
            fn process(&self, pid: u32) -> Option<ProcessRecord> {
                self.0.process(pid)
            }
            fn children(&self, pid: u32) -> ChildList {
                self.0.children(pid)
            }
            fn open_files(&self, pid: u32) -> OpenFileList {
                OpenFileList {
                    complete: false,
                    ..self.0.open_files(pid)
                }
            }
            fn claude_sessions(&self, registry: &Path) -> Vec<ClaudeSessionClaim> {
                self.0.claude_sessions(registry)
            }
        }
        let rollout = PathBuf::from("/h/.codex/sessions/rollout-a.jsonl");
        let host = Truncating(FakeHost {
            jobs: BTreeMap::from([("job".to_string(), 50)]),
            processes: BTreeMap::from([(50, record(1, 100))]),
            open_files: BTreeMap::from([(50, vec![rollout.clone()])]),
            ..FakeHost::default()
        });
        let query = OwnerQuery {
            source: SnapshotSource::Codex,
            source_session_id: "a",
            transcript_path: &rollout,
        };
        assert!(LiveScan::default()
            .owner_labels(&host, &query, &["job"])
            .is_empty());
    }

    #[test]
    fn proven_owners_forget_the_oldest_session_first() {
        let mut proven = ProvenOwners::default();
        let labels = BTreeSet::from(["job".to_string()]);
        for index in 0..=MAX_PROVEN_SESSIONS {
            proven.remember(SnapshotSource::Codex, &format!("s{index}"), &labels);
        }
        assert!(proven.labels(SnapshotSource::Codex, "s0").is_empty());
        assert_eq!(proven.labels(SnapshotSource::Codex, "s1"), labels);
        assert!(proven.labels(SnapshotSource::ClaudeCode, "s1").is_empty());
        assert_eq!(proven.order.len(), MAX_PROVEN_SESSIONS);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_host_reads_this_process_and_its_open_files() {
        let host = NativeHost;
        let pid = std::process::id();
        let own = host.process(pid).expect("own process record");
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
        let open = host.open_files(pid);
        assert!(open.complete);
        assert!(open.paths.contains(&resolved));
        drop(file);

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
