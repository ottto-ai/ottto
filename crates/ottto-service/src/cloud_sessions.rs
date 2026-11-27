//! Supported, metadata-only Codex Cloud task collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, reads OpenAI credentials, or calls provider
//! endpoints directly. It reads only Ottto's relay device credential for
//! Ottto backend authentication. Raw CLI JSON, URLs and cursors are used only
//! in memory. A task's id uploads as its session identifier, the same as a
//! local session id, and is never logged or written to disk; its title and
//! environment name leave the Mac only while the metadata policy that governs
//! local sessions allows them.
//!
//! Each due work slice reads the Codex activity hint once (listing on or off
//! and the metadata policy), lists provider pages and uploads only tasks
//! whose facts changed since their last exact server ACK
//! (`cloud_session_changes.v3`). When it calls the provider is in
//! [`schedule`]; the ACK cache lives in the upload-history SQLite file, keyed
//! by a local digest of each task id.

use crate::hex::{encode as hex, is_uuid};
use crate::local_resource_diagnostics::StageWindow;
use crate::locked_state_dir::FileLock;
use crate::snapshot_client::ActivityHintResponse;
use crate::snapshots::state_v2::upload_history::{CloudAck, CloudAckWrite};
use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use ottto_core::{
    compiled_release_version, default_support_dir, FileAccountStore, FileConnectionStore,
    FileDeviceStore, LocalDeviceBinding,
};
use ottto_protocol::LocalAccountState;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime, UtcOffset};

mod schedule;
mod wire;
use schedule::{
    head_interval, CloudSchedule, Crawl, Due, CRAWL_CONTINUATION_INTERVAL, MAX_SLICE_PAGES,
    OFF_RECHECK_INTERVAL, SUPERVISOR_FALLBACK_WAIT, UNSUPPORTED_RECHECK_INTERVAL,
};
pub use wire::{
    CloudSessionChangeAckV2, CloudSessionChangeOutcome, CloudSessionChangeV2,
    CloudSessionChangesAckV2, CloudSessionChangesV2, CloudUploadPolicyV2,
};
use wire::{Settled, CHANGES_SCHEMA_VERSION, CHANGES_SOURCE, MAX_LABEL_CHARS};

const CONTROL_TOKEN_LEDGER_SCHEMA_VERSION: &str = "cloud_session_control_token_uses.v1";
const MAX_CONTROL_TOKEN_USES: usize = 64;
const PAGE_LIMIT: usize = 20;
/// Command-safety bound for one CLI page's stdout, not an inventory ceiling;
/// a page that reaches it fails visibly instead of dropping its suffix.
const MAX_PAGE_OUTPUT_BYTES: u64 = (PAGE_LIMIT * 256 * 1024) as u64;
/// Pacing per work slice; a crawl continues where it stopped.
const CYCLE_BUDGET: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
const RELAY_IO_TIMEOUT: Duration = COMMAND_TIMEOUT;
/// One page's deadline (its home-lock wait included), then a lingering
/// child's drain, plus a margin.
pub(crate) const COLLECTOR_IO_STOP_TIMEOUT: Duration = COMMAND_TIMEOUT
    .saturating_add(crate::agent_status::CODEX_CHILD_DRAIN)
    .saturating_add(Duration::from_secs(3));
/// A page that waited for its home starts only with this much of its
/// deadline left.
const PAGE_START_FLOOR: Duration = Duration::from_secs(5);
const KILL_SWITCH_ENV: &str = "OTTTO_CODEX_CLOUD_SESSIONS_DISABLED";
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";
/// The task-list contract this build speaks; the hint must name exactly it.
const CODEX_CLOUD_TASKS_CONTRACT: &str = CHANGES_SCHEMA_VERSION;
/// The retired per-Mac grant (which held the old per-Mac task key), its
/// replay ledger and the pre-cache checkpoint. Removed once at startup.
const RETIRED_STATE_FILES: [&str; 5] = [
    "grant.json",
    "grant.lock",
    "control-token-uses.json",
    "control-token-uses.lock",
    "checkpoint.json",
];

static COLLECTOR_SUPERVISOR_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudSessionControlTokenUseLedger {
    schema_version: String,
    entries: Vec<CloudSessionControlTokenUse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudSessionControlTokenUse {
    token_digest: String,
    expires_at_unix: u64,
}

/// Owner-only, bounded replay ledger for device-bound one-time action tokens.
/// Only SHA-256(jti) and expiry are persisted; the signed token and raw jti are
/// never written to disk.
#[derive(Debug, Clone)]
pub struct CloudSessionControlTokenUseStore {
    path: PathBuf,
}

impl CloudSessionControlTokenUseStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn consume(&self, token_id: &str, expires_at_unix: u64, now_unix: u64) -> Result<()> {
        let token_id = token_id.trim();
        if token_id.is_empty()
            || token_id.len() > 128
            || expires_at_unix <= now_unix
            || expires_at_unix > now_unix.saturating_add(300)
        {
            return Err(anyhow!("cloud-session control token lifetime is invalid"));
        }
        let _lock = self.lock()?;
        let mut ledger = if self.path.exists() {
            serde_json::from_slice::<CloudSessionControlTokenUseLedger>(
                &fs::read(&self.path).context("read cloud-session control token ledger")?,
            )
            .context("decode cloud-session control token ledger")?
        } else {
            CloudSessionControlTokenUseLedger {
                schema_version: CONTROL_TOKEN_LEDGER_SCHEMA_VERSION.to_string(),
                entries: Vec::new(),
            }
        };
        if ledger.schema_version != CONTROL_TOKEN_LEDGER_SCHEMA_VERSION {
            return Err(anyhow!("unsupported cloud-session control token ledger"));
        }
        ledger
            .entries
            .retain(|entry| entry.expires_at_unix > now_unix);
        let token_digest = hex(&Sha256::digest(token_id.as_bytes()));
        if ledger
            .entries
            .iter()
            .any(|entry| entry.token_digest == token_digest)
        {
            return Err(anyhow!("cloud-session control token was already used"));
        }
        // Never evict an unexpired digest to make room: that would make its
        // still-valid action token replayable. A full five-minute window fails
        // closed until expiry pruning creates capacity.
        if ledger.entries.len() >= MAX_CONTROL_TOKEN_USES {
            return Err(anyhow!(
                "cloud-session control token replay ledger is at capacity"
            ));
        }
        ledger.entries.push(CloudSessionControlTokenUse {
            token_digest,
            expires_at_unix,
        });
        ledger.entries.sort_by_key(|entry| entry.expires_at_unix);
        atomic_json_write(&self.path, &ledger)
    }

    fn lock(&self) -> Result<FileLock> {
        lock_state_file(&self.path, "control token ledger")
    }
}

/// Waits for an exclusive flock on `<state_path>.lock` (0600) in an owner-only
/// (0700) directory.
pub(crate) fn lock_state_file(state_path: &Path, label: &str) -> Result<FileLock> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let parent = state_path
        .parent()
        .ok_or_else(|| anyhow!("cloud-session {label} path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let path = state_path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("open cloud-session {label} lock"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    FileLock::exclusive(file).map_err(|_| anyhow!("lock cloud-session {label}"))
}

/// Process-local collector state shared with local control: the provider and
/// relay I/O fence, and the support directory whose upload-history file holds
/// the cloud-task ACK cache.
pub struct CloudSessionCheckpointStore {
    state_dir: PathBuf,
    collector_io: Arc<CloudSessionIoFence>,
    #[cfg(test)]
    relay_admission_barrier: Mutex<Option<TestRelayAdmissionBarrier>>,
}

#[derive(Default)]
struct CloudSessionIoFence {
    active_io: Mutex<usize>,
    idle: Condvar,
}

struct CloudSessionIoLease<'a> {
    fence: &'a CloudSessionIoFence,
}

impl Drop for CloudSessionIoLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.fence.active_io.lock() {
            *active = active.saturating_sub(1);
            if *active == 0 {
                self.fence.idle.notify_all();
            }
        }
    }
}

fn default_collector_io_fence() -> Arc<CloudSessionIoFence> {
    static FENCE: OnceLock<Arc<CloudSessionIoFence>> = OnceLock::new();
    FENCE
        .get_or_init(|| Arc::new(CloudSessionIoFence::default()))
        .clone()
}

#[cfg(test)]
struct TestRelayAdmissionBarrier {
    skip: usize,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl CloudSessionCheckpointStore {
    /// `state_dir` is the support directory: the cache is
    /// `<state_dir>/snapshots/upload_history.sqlite`.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            collector_io: Arc::new(CloudSessionIoFence::default()),
            #[cfg(test)]
            relay_admission_barrier: Mutex::new(None),
        }
    }

    fn begin_collector_io<'a>(
        &'a self,
        transport: &dyn CloudSessionTransport,
    ) -> Result<Option<CloudSessionIoLease<'a>>> {
        self.begin_io(|| transport.local_binding_current())
    }

    /// Serialize admission with identity mutation, then release that lock
    /// before I/O. Identity changes close admission and drain these leases.
    fn begin_io(&self, current: impl FnOnce() -> bool) -> Result<Option<CloudSessionIoLease<'_>>> {
        let _identity_lock = crate::control::lock_setup_run_binding();
        if crate::control::identity_mutation_in_progress() || kill_switch_enabled() {
            return Ok(None);
        }
        let mut active = self
            .collector_io
            .active_io
            .lock()
            .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
        // Keep the stop check and lease registration under the same mutex
        // used by the drain, so an identity change cannot return between them.
        if !current() {
            return Ok(None);
        }
        *active = active.saturating_add(1);
        Ok(Some(CloudSessionIoLease {
            fence: &self.collector_io,
        }))
    }

    /// Wait until every provider subprocess, relay read or write, or cache
    /// commit admitted before an identity change has returned. The identity
    /// reservation closes admission; callers complete this wait before
    /// replacing account or device state.
    pub fn wait_for_collector_io_idle(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut active = self
            .collector_io
            .active_io
            .lock()
            .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
        while *active > 0 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow!("cloud-session collector I/O did not stop in time"))?;
            let (next, timeout_result) = self
                .collector_io
                .idle
                .wait_timeout(active, remaining)
                .map_err(|_| anyhow!("cloud-session collector-I/O fence is unavailable"))?;
            active = next;
            if timeout_result.timed_out() && *active > 0 {
                return Err(anyhow!("cloud-session collector I/O did not stop in time"));
            }
        }
        Ok(())
    }

    /// Cached ACKs of the offered task ids, keyed by those raw ids. The file
    /// holds only each id's [`ack_cache_key`].
    fn read_acks(
        &self,
        scope: &[u8; 32],
        ids: &[&str],
        now_unix: i64,
    ) -> Result<HashMap<String, CloudAck>> {
        let mut by_key = ids
            .iter()
            .map(|id| (ack_cache_key(id), *id))
            .collect::<HashMap<_, _>>();
        let keys = by_key.keys().map(String::as_str).collect::<Vec<_>>();
        let found =
            crate::upload_receipts::cloud_read_acks(&self.state_dir, scope, &keys, now_unix)?;
        Ok(found
            .into_iter()
            .filter_map(|(key, ack)| Some((by_key.remove(&key)?.to_string(), ack)))
            .collect())
    }

    fn crawl_completed(&self, scope: &[u8; 32]) -> Result<Option<Date>> {
        Ok(
            crate::upload_receipts::cloud_crawl_completed_date(&self.state_dir, scope)?.and_then(
                |raw| Date::parse(&raw, &time::format_description::well_known::Iso8601::DATE).ok(),
            ),
        )
    }

    /// Commit one slice's settled tasks under an I/O lease, so a commit racing
    /// an identity change either finishes before the change or is refused.
    fn commit(
        &self,
        transport: &dyn CloudSessionTransport,
        scope: &[u8; 32],
        settled: &HashMap<String, ([u8; 32], Option<String>)>,
        crawl_completed: Option<Date>,
        now_unix: i64,
    ) -> Result<()> {
        if settled.is_empty() && crawl_completed.is_none() {
            return Ok(());
        }
        let Some(lease) = self.begin_collector_io(transport)? else {
            return Ok(());
        };
        let keys = settled
            .iter()
            .map(|(id, settled)| (ack_cache_key(id), settled))
            .collect::<Vec<_>>();
        let acks = keys
            .iter()
            .map(|(entity_key, (digest, head_etag))| CloudAckWrite {
                entity_key,
                digest: *digest,
                head_etag: head_etag.as_deref(),
            })
            .collect::<Vec<_>>();
        let date = crawl_completed.map(|date| date.to_string());
        let result = crate::upload_receipts::cloud_commit(
            &self.state_dir,
            scope,
            &acks,
            date.as_deref(),
            now_unix,
        );
        drop(lease);
        result
    }

    #[cfg(test)]
    pub(crate) fn set_collector_io_active_for_test(&self, active_io: usize) {
        let mut active = self.collector_io.active_io.lock().unwrap();
        *active = active_io;
        if active_io == 0 {
            self.collector_io.idle.notify_all();
        }
    }

    #[cfg(test)]
    fn set_relay_admission_barrier_for_test(
        &self,
        skip: usize,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        *self.relay_admission_barrier.lock().unwrap() = Some(TestRelayAdmissionBarrier {
            skip,
            entered,
            release,
        });
    }

    #[cfg(test)]
    fn wait_at_relay_admission_barrier_for_test(&self) {
        let barrier = {
            let mut configured = self.relay_admission_barrier.lock().unwrap();
            let Some(barrier) = configured.as_mut() else {
                return;
            };
            if barrier.skip > 0 {
                barrier.skip -= 1;
                return;
            }
            configured
                .take()
                .map(|barrier| (barrier.entered, barrier.release))
        };
        if let Some((entered, release)) = barrier {
            entered.wait();
            release.wait();
        }
    }

    #[cfg(not(test))]
    fn wait_at_relay_admission_barrier_for_test(&self) {}
}

impl Default for CloudSessionCheckpointStore {
    fn default() -> Self {
        Self {
            state_dir: default_support_dir(),
            collector_io: default_collector_io_fence(),
            #[cfg(test)]
            relay_admission_barrier: Mutex::new(None),
        }
    }
}

pub trait CloudSessionRunner {
    /// `cursor` may only be retained by the caller in memory.
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String>;

    /// Production runners must honor the remaining slice budget. Test runners
    /// may use the default because they perform no blocking I/O.
    fn list_page_bounded(
        &self,
        cursor: Option<&str>,
        limit: usize,
        _timeout: Duration,
    ) -> Result<String> {
        self.list_page(cursor, limit)
    }
}

pub trait CloudSessionTransport {
    /// A backend route must be explicitly wired before collection starts.
    fn is_configured(&self) -> bool {
        true
    }
    /// The connected account, organization, Codex relay device and
    /// destination this transport was composed for are still current.
    /// Checked at every I/O fence.
    fn local_binding_current(&self) -> bool {
        true
    }

    /// One bounded relay-authenticated read of the Codex activity hint. Fails
    /// closed on any network, authentication or parsing error.
    fn read_hint(&self, timeout: Duration) -> Result<ActivityHintResponse>;
    /// Upload one validated request and return its parsed ACK. Matching the
    /// ACK to the offered tasks is the caller's job.
    fn send_changes(
        &self,
        request: &CloudSessionChangesV2,
        timeout: Duration,
    ) -> Result<CloudSessionChangesAckV2>;
}

/// Relay transport for the strict backend routes, composed only for the
/// connected Codex Mac. It acquires through the shared relay-token cache and
/// retries once on 401/403 within the caller's deadline.
pub struct RelayCloudSessionTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    binding: CloudSessionRuntimeBinding,
    device_secret: String,
    gzip_enabled: AtomicBool,
}

impl RelayCloudSessionTransport {
    fn new(binding: CloudSessionRuntimeBinding, device_secret: String) -> Self {
        Self {
            client: crate::snapshot_client::SnapshotApiClient::new(binding.api_base_url.clone()),
            binding,
            device_secret,
            gzip_enabled: AtomicBool::new(true),
        }
    }

    fn token(&self, deadline: Instant) -> Result<String> {
        let timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        self.client.issue_relay_token_with_timeout(
            &self.binding.device,
            &self.device_secret,
            crate::snapshots::SnapshotSource::Codex,
            timeout,
        )
    }

    fn with_relay_retry<T, F>(&self, timeout: Duration, request: F) -> Result<T>
    where
        F: Fn(&crate::snapshot_client::SnapshotApiClient, &str, Duration) -> Result<T>,
    {
        if !self.is_configured() {
            return Err(anyhow!("cloud-session relay transport is not source-bound"));
        }
        let deadline = Instant::now() + timeout;
        let token = self.token(deadline)?;
        let request_timeout = remaining_budget(deadline)
            .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
        match request(&self.client, &token, request_timeout) {
            Err(error)
                if error
                    .downcast_ref::<crate::snapshot_client::CloudSessionAuthorizationRejected>()
                    .is_some() =>
            {
                let refreshed = self.token(deadline)?;
                let retry_timeout = remaining_budget(deadline)
                    .ok_or_else(|| anyhow!("cloud-session cycle budget exhausted"))?;
                request(&self.client, &refreshed, retry_timeout)
            }
            other => other,
        }
    }
}

impl CloudSessionTransport for RelayCloudSessionTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.binding.device.device_id)
            && self
                .binding
                .device
                .sources
                .iter()
                .any(|source| source == "codex")
    }

    fn local_binding_current(&self) -> bool {
        load_cloud_session_runtime_binding(
            &FileAccountStore::default(),
            &FileDeviceStore::default(),
            &FileConnectionStore::default(),
        )
        .ok()
        .flatten()
        .is_some_and(|current| current == self.binding)
    }

    fn read_hint(&self, timeout: Duration) -> Result<ActivityHintResponse> {
        self.with_relay_retry(timeout, |client, token, request_timeout| {
            client.get_activity_hint_with_timeout(token, request_timeout)
        })
    }

    fn send_changes(
        &self,
        request: &CloudSessionChangesV2,
        timeout: Duration,
    ) -> Result<CloudSessionChangesAckV2> {
        request.validate()?;
        let body = serde_json::to_value(request)?;
        let value = self.with_relay_retry(timeout, |client, token, request_timeout| {
            client.upload_cloud_session_changes_with_timeout(
                token,
                &body,
                request_timeout,
                &self.gzip_enabled,
            )
        })?;
        // The decode error can quote ACK values; keep only its category.
        serde_json::from_value(value).map_err(|_| anyhow!("invalid cloud-session changes ACK"))
    }
}

pub struct CodexCloudCliRunner;

/// One Codex CLI child (`codex cloud list`, the limits probe's `codex
/// app-server`), started by `Command::process_group(0)` as the leader of its
/// own group, owned until it is stopped and reaped.
#[cfg(unix)]
pub(crate) struct CodexChild {
    child: Option<crate::local_resource_diagnostics::cli_children::MeasuredChild>,
}

#[cfg(unix)]
impl CodexChild {
    pub(crate) fn new(
        child: crate::local_resource_diagnostics::cli_children::MeasuredChild,
    ) -> Self {
        Self { child: Some(child) }
    }

    /// The child's stdin and stdout pipes.
    pub(crate) fn take_pipes(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>) {
        let child = self.child.as_mut().expect("owned codex child");
        (child.stdin.take(), child.stdout.take())
    }

    pub(crate) fn exited(&self) -> std::io::Result<bool> {
        let child = self.child.as_ref().expect("owned codex child");
        crate::process_guard::exited(child).or_else(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            }
        })
    }

    /// Ends the child without cutting off a login refresh it may be making:
    /// the caller has closed its stdin (or it had none) and its output reader.
    pub(crate) fn stop_and_reap(&mut self) -> std::io::Result<std::process::ExitStatus> {
        crate::process_guard::stop_group_and_reap(
            self.child.take().expect("owned codex child"),
            crate::agent_status::codex_child_drain(),
        )
    }
}

#[cfg(unix)]
impl Drop for CodexChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.stop_and_reap();
        }
    }
}

/// One provider-call log line per `codex cloud list` run that started: at
/// least one OpenAI request.
#[cfg(unix)]
fn record_codex_cloud_list(result: &Result<String>, started: Instant) {
    use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
    let result = match result {
        Ok(_) => CallResult::Ok,
        Err(error) if error.to_string().ends_with("could not be started") => return,
        Err(error) if error.to_string().ends_with("timed out") => CallResult::Timeout,
        Err(error) if error.to_string().ends_with("exited unsuccessfully") => {
            CallResult::Error("exited")
        }
        Err(_) => CallResult::Error("error"),
    };
    crate::provider_calls::record(ProviderCall::subprocess(
        Provider::Openai,
        CallKind::CodexCloudList,
        crate::provider_calls::trigger_or(Trigger::Schedule),
        crate::agent_status::codex_cli_home_claimed_account_hash().as_deref(),
        result,
        started.elapsed(),
        1,
    ));
}

#[cfg(unix)]
fn run_codex_cloud_command(command: &mut Command, deadline: Instant) -> Result<String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    if Instant::now() >= deadline {
        return Err(anyhow!("Codex cloud list timed out"));
    }
    command.process_group(0);
    let mut owned = CodexChild::new(
        crate::local_resource_diagnostics::cli_children::spawn(command)
            .map_err(|_| anyhow!("Codex cloud list could not be started"))?,
    );
    let stdout = owned
        .take_pipes()
        .1
        .ok_or_else(|| anyhow!("Codex cloud list stdout could not be opened"))?;
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(anyhow!("Codex cloud list output could not be read"));
    }
    // Read in this thread, checking the same deadline on every chunk, including
    // continuously readable output. No blocked reader can outlive this call.
    let mut stdout = Some(stdout);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow!("Codex cloud list timed out"))?;
        let mut progressed = false;
        if let Some(pipe) = stdout.as_mut() {
            let available = (MAX_PAGE_OUTPUT_BYTES as usize - bytes.len()).min(buffer.len());
            match pipe.read(&mut buffer[..available]) {
                Ok(0) => stdout = None,
                Ok(read) => {
                    bytes.extend_from_slice(&buffer[..read]);
                    progressed = true;
                    // Preserve take(MAX_PAGE_OUTPUT_BYTES): close the pipe at
                    // the cap and let the child's exit status settle the result.
                    if bytes.len() == MAX_PAGE_OUTPUT_BYTES as usize {
                        stdout = None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(anyhow!("Codex cloud list output could not be read")),
            }
        }
        if owned
            .exited()
            .map_err(|_| anyhow!("Codex cloud list status could not be read"))?
            && stdout.is_none()
        {
            let status = owned
                .stop_and_reap()
                .map_err(|_| anyhow!("Codex cloud list status could not be read"))?;
            if !status.success() {
                return Err(anyhow!("Codex cloud list exited unsuccessfully"));
            }
            return String::from_utf8(bytes)
                .map_err(|_| anyhow!("Codex cloud list returned non-UTF-8 JSON"));
        }
        if !progressed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(pipe) = stdout.as_ref() {
                let mut ready = libc::pollfd {
                    fd: pipe.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let timeout_ms = remaining.as_millis().min(50) as libc::c_int;
                let result = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
                if result < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(anyhow!("Codex cloud list output could not be read"));
                }
            } else {
                thread::sleep(remaining.min(Duration::from_millis(50)));
            }
        }
    }
}

/// A page not started: a limits read of its home held the home past the
/// page's deadline.
#[derive(Debug)]
struct CodexHomeBusy;

impl std::fmt::Display for CodexHomeBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Codex home busy with a limits read")
    }
}

impl std::error::Error for CodexHomeBusy {}

impl CloudSessionRunner for CodexCloudCliRunner {
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
        self.list_page_bounded(cursor, limit, COMMAND_TIMEOUT)
    }

    fn list_page_bounded(
        &self,
        cursor: Option<&str>,
        limit: usize,
        timeout: Duration,
    ) -> Result<String> {
        #[cfg(unix)]
        let deadline = Instant::now() + timeout.min(COMMAND_TIMEOUT);
        let program = crate::command_env::executable_path("codex")
            .ok_or_else(|| anyhow!("Codex CLI is unavailable"))?;
        let mut command = Command::new(program);
        command.args([
            "cloud",
            "list",
            "--json",
            "--limit",
            &limit.min(PAGE_LIMIT).to_string(),
        ]);
        if let Some(cursor) = cursor.filter(|value| !value.is_empty()) {
            command.args(["--cursor", cursor]);
        }
        // Codex authenticates through its own effective-user configuration.
        // Never recover or forward provider API keys from the service or an
        // interactive shell for this metadata-only collector.
        command.env_clear();
        if let Some(path) = crate::command_env::path_env() {
            command.env("PATH", path);
        }
        for key in [
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "CODEX_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        ] {
            if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
                command.env(key, value);
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // One Codex child per home: never beside a limits read of the same
        // home, which may be refreshing its login. A page that has to wait for
        // it starts only with PAGE_START_FLOOR of its deadline left.
        #[cfg(unix)]
        {
            let home = crate::agent_status::codex_cli_home();
            let wait_until = deadline
                .checked_sub(PAGE_START_FLOOR)
                .unwrap_or_else(Instant::now);
            crate::agent_status::with_codex_home_read_lock_until(&home, wait_until, || {
                let started = Instant::now();
                let result = run_codex_cloud_command(&mut command, deadline);
                // A deadline already spent starts nothing.
                if started < deadline {
                    record_codex_cloud_list(&result, started);
                }
                result
            })
            .unwrap_or_else(|| Err(CodexHomeBusy.into()))
        }
        #[cfg(not(unix))]
        {
            let mut child = command
                .spawn()
                .map_err(|_| anyhow!("Codex cloud list could not be started"))?;
            // Drain stdout while the child runs. Waiting to read after process exit
            // would deadlock when a valid JSON page fills the OS pipe buffer.
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Codex cloud list stdout could not be opened"))?;
            let reader = thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout
                    .take(MAX_PAGE_OUTPUT_BYTES)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            });
            let started = Instant::now();
            let timeout = timeout.min(COMMAND_TIMEOUT);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let output = reader
                            .join()
                            .map_err(|_| anyhow!("Codex cloud list output reader panicked"))?
                            .map_err(|_| anyhow!("Codex cloud list output could not be read"))?;
                        if !status.success() {
                            return Err(anyhow!("Codex cloud list exited unsuccessfully"));
                        }
                        return String::from_utf8(output)
                            .map_err(|_| anyhow!("Codex cloud list returned non-UTF-8 JSON"));
                    }
                    Ok(None) if started.elapsed() >= timeout => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = reader.join();
                        return Err(anyhow!("Codex cloud list timed out"));
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(50)),
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = reader.join();
                        return Err(anyhow!("Codex cloud list status could not be read"));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCycleOutcome {
    /// The kill switch, no connected Codex Mac or a local identity change: no
    /// provider or backend call was made.
    Disabled,
    /// Nothing was due yet.
    NotDue,
    /// Listing is off for this user, the server refused it, or the server
    /// lacks the route (or retired this contract). Rechecked later.
    Unsupported,
    /// Work ran and no task changed.
    Noop,
    /// At least one changed task was offered.
    Uploaded,
    /// Provider or transport failed; the cloud-only backoff applies.
    Failed,
}

/// The collector's in-memory state; one per supervisor.
#[derive(Default)]
pub struct CloudCollector {
    schedule: CloudSchedule,
    /// Successful head listings in a row from which the server accepted
    /// nothing new; sets the head interval. Outlives `schedule.clear()`.
    unchanged_heads: u32,
    /// The last state logged, so each transition logs one line.
    reported: Option<&'static str>,
    /// The last nonzero invalid-task-id row count logged, deduplicated the
    /// same way.
    reported_invalid_ids: Option<usize>,
}

/// Everything one work slice uses.
pub struct SliceInputs<'a> {
    pub checkpoints: &'a CloudSessionCheckpointStore,
    pub runner: &'a dyn CloudSessionRunner,
    pub transport: &'a dyn CloudSessionTransport,
    /// The validated backend destination; part of every cache scope.
    pub destination: &'a str,
    /// The connected local organization and user; part of every cache scope.
    pub organization_id: &'a str,
    pub user_id: &'a str,
}

#[derive(Debug)]
struct SliceError {
    category: &'static str,
    kind: SliceErrorKind,
}

#[derive(Debug)]
enum SliceErrorKind {
    /// Retry after the cloud-only backoff (a `Retry-After` when given).
    Backoff(Option<Duration>),
    /// The server does not offer this route or retired this contract.
    Unsupported,
    /// Listing is off, or the server refused the request (any 409); read
    /// the hint again later.
    Off,
    /// A local identity change closed the I/O fence mid-slice.
    Stopped,
    /// The slice budget ran out; the next slice continues.
    Deferred,
}

impl SliceError {
    fn backoff(category: &'static str) -> Self {
        Self {
            category,
            kind: SliceErrorKind::Backoff(None),
        }
    }

    fn from_request(error: &anyhow::Error, deadline: Instant) -> Self {
        if let Some(shed) = error.downcast_ref::<crate::snapshot_client::UploadShed>() {
            return Self {
                category: "backend_shed",
                kind: SliceErrorKind::Backoff(shed.retry_after),
            };
        }
        if error
            .downcast_ref::<crate::snapshot_client::CloudTaskRefused>()
            .is_some()
        {
            return Self {
                category: "server_refused",
                kind: SliceErrorKind::Off,
            };
        }
        if error
            .downcast_ref::<crate::snapshot_client::CloudSessionRouteUnsupported>()
            .is_some()
        {
            return Self {
                category: "server_unsupported",
                kind: SliceErrorKind::Unsupported,
            };
        }
        if remaining_budget(deadline).is_none() {
            return Self {
                category: "budget_exhausted",
                kind: SliceErrorKind::Deferred,
            };
        }
        Self::backoff("transport_unavailable")
    }
}

/// What one listed page contributed.
struct PageFacts {
    next: Option<String>,
    ambiguous: bool,
}

/// One slice's working memory: only ACK metadata of tasks it settled.
struct SliceWork<'a, 'b> {
    inputs: &'a SliceInputs<'b>,
    policy: CloudUploadPolicyV2,
    scope: [u8; 32],
    deadline: Instant,
    wall: OffsetDateTime,
    pages: usize,
    offered: usize,
    /// Tasks the server answered `accepted` (its head moved).
    accepted: usize,
    head_listed: bool,
    /// Listed rows skipped for an invalid task id, across every listing of
    /// this slice. Logged as a count only.
    invalid_ids: usize,
    settled: HashMap<String, ([u8; 32], Option<String>)>,
}

impl CloudCollector {
    /// When the supervisor should next run a slice; `None` waits for a local
    /// wake (or the supervisor's fallback).
    pub fn next_wake(&self, now: Instant, wall: OffsetDateTime) -> Option<Instant> {
        if self.schedule.scope.is_none() {
            return self.schedule.retry_not_before;
        }
        Some(
            self.schedule
                .next_due(now, wall.date(), head_interval(self.unchanged_heads)),
        )
    }

    /// Drop transient work (cursor, backoff, recheck) after collection stops
    /// locally; the next slice starts with an immediate head.
    pub fn reset(&mut self) {
        self.schedule.clear();
    }

    /// One log line per state transition; never task data.
    fn report(&mut self, state: &'static str) {
        if self.reported != Some(state) {
            self.reported = Some(state);
            eprintln!("codex_cloud_tasks state={state}");
        }
    }

    /// One counts-only line when a slice skipped rows for invalid task ids,
    /// deduplicated like [`Self::report`]; never the ids.
    fn report_invalid_ids(&mut self, rows: usize) {
        if rows > 0 && self.reported_invalid_ids != Some(rows) {
            self.reported_invalid_ids = Some(rows);
            eprintln!("codex_cloud_tasks invalid_task_id rows={rows}");
        }
    }

    fn defer_after_local_failure(&mut self, now: Instant) {
        let backoff = crate::snapshot_sync::full_jitter_backoff(self.schedule.consecutive_failures);
        self.schedule.note_failure(now, backoff);
    }

    /// Run whatever is due: one hint read, then the head and/or the next
    /// crawl pages, uploading only changed tasks, then one cache commit.
    pub fn run_slice(
        &mut self,
        inputs: &SliceInputs<'_>,
        now: Instant,
        wall: OffsetDateTime,
    ) -> CloudSessionCycleOutcome {
        let started = Instant::now();
        if kill_switch_enabled() {
            self.schedule.clear();
            self.report("kill_switch");
            return CloudSessionCycleOutcome::Disabled;
        }
        if !inputs.transport.is_configured() {
            self.schedule.clear();
            self.report("transport_unconfigured");
            return CloudSessionCycleOutcome::Disabled;
        }
        self.schedule.reset_for_scope(schedule_scope(inputs));
        let today = wall.date();
        let interval = head_interval(self.unchanged_heads);
        let opportunity = self.schedule.due(now, today, interval);
        if !opportunity.head && !opportunity.crawl {
            return CloudSessionCycleOutcome::NotDue;
        }
        let deadline = Instant::now() + CYCLE_BUDGET;
        let Some(policy) = (match self.preflight(inputs, deadline, now, started) {
            Ok(listing) => listing,
            Err(outcome) => return outcome,
        }) else {
            self.recheck_after(now, OFF_RECHECK_INTERVAL);
            self.report("listing_off");
            return CloudSessionCycleOutcome::Unsupported;
        };
        let scope = cache_scope(inputs);
        if !self.schedule.crawl_completed_loaded {
            let lease = match inputs.checkpoints.begin_collector_io(inputs.transport) {
                Ok(Some(lease)) => lease,
                _ => {
                    self.schedule.clear();
                    return CloudSessionCycleOutcome::Disabled;
                }
            };
            self.schedule.crawl_completed = match inputs.checkpoints.crawl_completed(&scope) {
                Ok(date) => date,
                Err(_) => {
                    return self.settle_failure(
                        SliceError::backoff("ack_cache_unavailable"),
                        now,
                        now + started.elapsed(),
                    );
                }
            };
            self.schedule.crawl_completed_loaded = true;
            drop(lease);
        }
        let due = self.schedule.due(now, today, interval);
        if !due.head && !due.crawl {
            return CloudSessionCycleOutcome::NotDue;
        }
        let mut work = SliceWork {
            inputs,
            policy,
            scope,
            deadline,
            wall,
            pages: 0,
            offered: 0,
            accepted: 0,
            head_listed: false,
            invalid_ids: 0,
            settled: HashMap::new(),
        };
        let mut crawl_completed = None;
        let failure = self.work(&mut work, due, now, today, &mut crawl_completed);
        self.report_invalid_ids(work.invalid_ids);
        let cache_unavailable = inputs
            .checkpoints
            .commit(
                inputs.transport,
                &scope,
                &work.settled,
                crawl_completed,
                wall.unix_timestamp(),
            )
            .is_err();
        // Only an accepted upload (the server head moved) is new work; a
        // noop, a refusal or a failure is not.
        if work.accepted > 0 {
            self.unchanged_heads = 0;
        } else if failure.is_none() && work.head_listed {
            self.unchanged_heads = self.unchanged_heads.saturating_add(1);
        }
        // A cache failure re-offers tasks next time (server no-op).
        match failure {
            None => {
                self.schedule.note_success();
                self.report(if cache_unavailable {
                    "ack_cache_unavailable"
                } else {
                    "ok"
                });
                if work.offered > 0 {
                    CloudSessionCycleOutcome::Uploaded
                } else {
                    CloudSessionCycleOutcome::Noop
                }
            }
            Some(error) => self.settle_failure(error, now, now + started.elapsed()),
        }
    }

    fn settle_failure(
        &mut self,
        error: SliceError,
        now: Instant,
        failed_at: Instant,
    ) -> CloudSessionCycleOutcome {
        match error.kind {
            SliceErrorKind::Backoff(retry_after) => {
                let backoff = match retry_after {
                    Some(_) => crate::snapshot_sync::shed_backoff(retry_after),
                    None => crate::snapshot_sync::full_jitter_backoff(
                        self.schedule.consecutive_failures,
                    ),
                };
                // Retry-After begins at failure receipt. Rechecks below keep
                // their ordinary planned opportunity.
                self.schedule.note_failure(failed_at, backoff);
                self.report(error.category);
                CloudSessionCycleOutcome::Failed
            }
            SliceErrorKind::Unsupported => {
                self.recheck_after(now, UNSUPPORTED_RECHECK_INTERVAL);
                self.report(error.category);
                CloudSessionCycleOutcome::Unsupported
            }
            SliceErrorKind::Off => {
                self.recheck_after(now, OFF_RECHECK_INTERVAL);
                self.report(error.category);
                CloudSessionCycleOutcome::Unsupported
            }
            SliceErrorKind::Stopped => {
                self.schedule.clear();
                CloudSessionCycleOutcome::Disabled
            }
            SliceErrorKind::Deferred => CloudSessionCycleOutcome::Noop,
        }
    }

    /// No provider call before `now + interval`; the next slice reads the
    /// hint again first. The head is owed at that recheck, so a long head
    /// interval cannot postpone it.
    fn recheck_after(&mut self, now: Instant, interval: Duration) {
        self.schedule.crawl = None;
        self.schedule.retry_not_before = None;
        self.schedule.last_head_attempt = None;
        self.schedule.unsupported_until = Some(now + interval);
    }

    /// The one hint read of a due slice: the metadata policy when listing is
    /// on, `None` when it is off.
    fn preflight(
        &mut self,
        inputs: &SliceInputs<'_>,
        deadline: Instant,
        now: Instant,
        started: Instant,
    ) -> std::result::Result<Option<CloudUploadPolicyV2>, CloudSessionCycleOutcome> {
        let Some(timeout) = remaining_relay_budget(deadline) else {
            return Err(CloudSessionCycleOutcome::NotDue);
        };
        let lease = match inputs.checkpoints.begin_collector_io(inputs.transport) {
            Ok(Some(lease)) => lease,
            _ => {
                self.schedule.clear();
                return Err(CloudSessionCycleOutcome::Disabled);
            }
        };
        let result = inputs.transport.read_hint(timeout);
        drop(lease);
        match result {
            Ok(hint) => Ok(codex_cloud_listing(&hint)),
            Err(error) => {
                let error = SliceError::from_request(&error, deadline);
                Err(self.settle_failure(error, now, now + started.elapsed()))
            }
        }
    }

    fn work(
        &mut self,
        work: &mut SliceWork<'_, '_>,
        due: Due,
        now: Instant,
        today: Date,
        crawl_completed: &mut Option<Date>,
    ) -> Option<SliceError> {
        let start_crawl = due.crawl
            && self
                .schedule
                .crawl
                .as_ref()
                .is_none_or(|crawl| crawl.cursor.is_none());
        if due.head || start_crawl {
            self.schedule.last_head_attempt = Some(now);
            let page = match work.page(None) {
                Ok(page) => page,
                Err(error) => {
                    if start_crawl {
                        // Page zero remains owed, paced like any unfinished
                        // crawl. Backoff cannot turn it into an immediate loop.
                        self.schedule.crawl = Some(Crawl {
                            cursor: None,
                            pages_seen: 0,
                            cycle: Default::default(),
                            next_slice: now + CRAWL_CONTINUATION_INTERVAL,
                        });
                    }
                    return Some(error);
                }
            };
            if start_crawl {
                self.schedule.crawl = None;
                match page.next {
                    Some(cursor) if !page.ambiguous => {
                        let mut crawl = Crawl {
                            cursor: Some(cursor.clone()),
                            pages_seen: 1,
                            cycle: Default::default(),
                            next_slice: now,
                        };
                        crawl.cycle.repeats(cursor_digest(&cursor));
                        self.schedule.crawl = Some(crawl);
                    }
                    _ if page.ambiguous => self.schedule.crawl_ended = Some(today),
                    _ => {
                        self.schedule.crawl_completed = Some(today);
                        *crawl_completed = Some(today);
                    }
                }
            }
        }
        if !(due.crawl || start_crawl) {
            return None;
        }
        let mut crawl = self.schedule.crawl.take()?;
        let mut failure = None;
        while work.pages < MAX_SLICE_PAGES && remaining_budget(work.deadline).is_some() {
            let Some(cursor) = crawl.cursor.clone() else {
                break;
            };
            let page = match work.page(Some(&cursor)) {
                Ok(page) => page,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            crawl.pages_seen += 1;
            match page.next {
                None if !page.ambiguous => {
                    // Reached the end: the day's crawl is complete, whatever
                    // day it started.
                    self.schedule.crawl_completed = Some(today);
                    *crawl_completed = Some(today);
                    return failure;
                }
                Some(next)
                    if !page.ambiguous
                        && next != cursor
                        && !crawl.cycle.repeats(cursor_digest(&next)) =>
                {
                    crawl.cursor = Some(next);
                }
                _ => {
                    // An ambiguous, repeating or cycling cursor chain ends
                    // this traversal without claiming completion; valid facts
                    // already uploaded stay. A new crawl starts tomorrow.
                    self.schedule.crawl_ended = Some(today);
                    return failure;
                }
            }
        }
        if matches!(
            failure.as_ref().map(|error| &error.kind),
            Some(SliceErrorKind::Unsupported | SliceErrorKind::Off | SliceErrorKind::Stopped)
        ) {
            return failure;
        }
        crawl.next_slice = now + CRAWL_CONTINUATION_INTERVAL;
        self.schedule.crawl = Some(crawl);
        failure
    }
}

impl SliceWork<'_, '_> {
    fn list(&mut self, cursor: Option<&str>) -> std::result::Result<String, SliceError> {
        let Some(timeout) = remaining_budget(self.deadline) else {
            return Err(SliceError {
                category: "budget_exhausted",
                kind: SliceErrorKind::Deferred,
            });
        };
        let lease = self
            .inputs
            .checkpoints
            .begin_collector_io(self.inputs.transport)
            .map_err(|_| SliceError::backoff("collector_io_fence_unavailable"))?
            .ok_or(SliceError {
                category: "stopped",
                kind: SliceErrorKind::Stopped,
            })?;
        self.pages += 1;
        let result =
            self.inputs
                .runner
                .list_page_bounded(cursor, PAGE_LIMIT, timeout.min(COMMAND_TIMEOUT));
        // The lease covers provider-process activity only.
        drop(lease);
        result.map_err(|error| {
            // A page that never started is retried by the schedule.
            if remaining_budget(self.deadline).is_none() || error.is::<CodexHomeBusy>() {
                SliceError {
                    category: "budget_exhausted",
                    kind: SliceErrorKind::Deferred,
                }
            } else {
                SliceError::backoff("provider_unavailable")
            }
        })
    }

    fn parse(&mut self, raw: &str) -> std::result::Result<ParsedPage, SliceError> {
        let page = parse_cloud_page(raw, self.policy, self.wall)
            .map_err(|_| SliceError::backoff("provider_payload_invalid"))?;
        self.invalid_ids += page.invalid_ids;
        // A nonempty page with no recognizable task is a provider failure,
        // not an empty healthy page. Rows skipped only for an invalid task id
        // are recognizable, so their page's cursor still advances.
        if page.source_item_count > 0 && page.changes.is_empty() && page.invalid_ids == 0 {
            return Err(SliceError::backoff("provider_payload_invalid"));
        }
        Ok(page)
    }

    /// List one page, offer its changed tasks, and retry a head conflict
    /// once with freshly listed facts.
    fn page(&mut self, cursor: Option<&str>) -> std::result::Result<PageFacts, SliceError> {
        let raw = self.list(cursor)?;
        let parsed = self.parse(&raw)?;
        drop(raw);
        if cursor.is_none() {
            self.head_listed = true;
        }
        let facts = PageFacts {
            next: match &parsed.cursor {
                CloudPageCursor::Next(next) => Some(next.clone()),
                _ => None,
            },
            ambiguous: parsed.cursor == CloudPageCursor::Ambiguous,
        };
        let conflicts = self.deliver(parsed.changes)?;
        if conflicts.is_empty()
            || self.pages >= MAX_SLICE_PAGES
            || remaining_budget(self.deadline).is_none()
        {
            return Ok(facts);
        }
        // Fresh re-enumeration before replacing a divergent server head. A
        // second conflict is left for the next visit.
        let Ok(raw) = self.list(cursor) else {
            return Ok(facts);
        };
        let Ok(fresh) = self.parse(&raw) else {
            return Ok(facts);
        };
        drop(raw);
        let retry = fresh
            .changes
            .into_iter()
            .filter_map(|mut change| {
                let hint = conflicts.get(&change.source_session_id)?.clone();
                change.expected_head_etag = Some(hint);
                Some(change)
            })
            .collect::<Vec<_>>();
        self.offer(retry)?;
        Ok(facts)
    }

    /// Offer only tasks whose digest differs from their last settled digest
    /// in this slice or the cache. Returns conflict hints by task.
    fn deliver(
        &mut self,
        changes: Vec<CloudSessionChangeV2>,
    ) -> std::result::Result<HashMap<String, String>, SliceError> {
        let mut unique = Vec::with_capacity(changes.len());
        for change in changes {
            if !unique.iter().any(|seen: &CloudSessionChangeV2| {
                seen.source_session_id == change.source_session_id
            }) {
                unique.push(change);
            }
        }
        if unique.is_empty() {
            return Ok(HashMap::new());
        }
        let ids = unique
            .iter()
            .map(|change| change.source_session_id.as_str())
            .filter(|id| !self.settled.contains_key(*id))
            .collect::<Vec<_>>();
        // A cache failure defers this page through cloud-only backoff.
        // Retain no unbounded in-memory replacement and do not hammer the server.
        let cached = if ids.is_empty() {
            HashMap::new()
        } else {
            let _lease = self
                .inputs
                .checkpoints
                .begin_collector_io(self.inputs.transport)
                .map_err(|_| SliceError::backoff("collector_io_fence_unavailable"))?
                .ok_or(SliceError {
                    category: "stopped",
                    kind: SliceErrorKind::Stopped,
                })?;
            self.inputs
                .checkpoints
                .read_acks(&self.scope, &ids, self.wall.unix_timestamp())
                .map_err(|_| SliceError::backoff("ack_cache_unavailable"))?
        };
        let mut offer = Vec::new();
        for mut change in unique {
            let digest = change.semantic_digest(self.policy);
            let known = self
                .settled
                .get(&change.source_session_id)
                .map(|(digest, etag)| (*digest, etag.clone()))
                .or_else(|| {
                    cached
                        .get(&change.source_session_id)
                        .map(|ack| (ack.digest, ack.head_etag.clone()))
                });
            match known {
                Some((known, _)) if known == digest => continue,
                Some((_, etag)) => change.expected_head_etag = etag,
                None => change.expected_head_etag = None,
            }
            offer.push(change);
        }
        self.offer(offer)
    }

    /// Send changed tasks, packed by count and bytes, and settle each exact
    /// ACK. Only accepted/noop entries carry an etag into the cache; a
    /// refusal or a conflict without a head is remembered with none.
    fn offer(
        &mut self,
        changes: Vec<CloudSessionChangeV2>,
    ) -> std::result::Result<HashMap<String, String>, SliceError> {
        let mut conflicts = HashMap::new();
        for observations in wire::pack(changes) {
            let request = CloudSessionChangesV2 {
                schema_version: CHANGES_SCHEMA_VERSION.to_string(),
                source: CHANGES_SOURCE.to_string(),
                collector_version: compiled_release_version(),
                collected_at: timestamp(self.wall),
                upload_policy: self.policy,
                observations,
            };
            request
                .validate()
                .map_err(|_| SliceError::backoff("request_invalid"))?;
            self.inputs
                .checkpoints
                .wait_at_relay_admission_barrier_for_test();
            let Some(timeout) = remaining_relay_budget(self.deadline) else {
                return Err(SliceError {
                    category: "budget_exhausted",
                    kind: SliceErrorKind::Deferred,
                });
            };
            let lease = self
                .inputs
                .checkpoints
                .begin_collector_io(self.inputs.transport)
                .map_err(|_| SliceError::backoff("collector_io_fence_unavailable"))?
                .ok_or(SliceError {
                    category: "stopped",
                    kind: SliceErrorKind::Stopped,
                })?;
            let result = self.inputs.transport.send_changes(&request, timeout);
            drop(lease);
            let ack = result.map_err(|error| SliceError::from_request(&error, self.deadline))?;
            let settled = request
                .settle(&ack)
                .map_err(|_| SliceError::backoff("ack_invalid"))?;
            self.offered += request.observations.len();
            for change in &request.observations {
                let digest = change.semantic_digest(self.policy);
                match settled.get(&change.source_session_id) {
                    Some(Settled::Acked {
                        head_etag,
                        accepted,
                    }) => {
                        if *accepted {
                            self.accepted += 1;
                        }
                        self.settled.insert(
                            change.source_session_id.clone(),
                            (digest, Some(head_etag.clone())),
                        );
                    }
                    Some(Settled::Refused) => {
                        self.settled
                            .insert(change.source_session_id.clone(), (digest, None));
                    }
                    Some(Settled::Conflict { head_etag }) => {
                        conflicts.insert(change.source_session_id.clone(), head_etag.clone());
                    }
                    None => {}
                }
            }
        }
        Ok(conflicts)
    }
}

/// Listing runs only when the hint turns it on and names exactly the
/// contract this build speaks; anything else (an older server omits both) is
/// off. The policy is the one local session uploads apply, from the same
/// hint.
fn codex_cloud_listing(hint: &ActivityHintResponse) -> Option<CloudUploadPolicyV2> {
    if !hint.codex_cloud_tasks_enabled
        || hint.codex_cloud_tasks_contract.as_deref() != Some(CODEX_CLOUD_TASKS_CONTRACT)
    {
        return None;
    }
    let policy = crate::upload_policy::SnapshotUploadPolicy::from_hint(hint);
    Some(CloudUploadPolicyV2 {
        session_titles_enabled: policy.titles(),
        workspace_labels_enabled: policy.workspace(),
    })
}

fn remaining_budget(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

fn remaining_relay_budget(deadline: Instant) -> Option<Duration> {
    remaining_budget(deadline).map(|remaining| remaining.min(RELAY_IO_TIMEOUT))
}

fn cursor_digest(cursor: &str) -> [u8; 32] {
    Sha256::digest(cursor.as_bytes()).into()
}

/// ACK-cache isolation: the destination, the local organization and user,
/// and the contract. Never a Results identity.
fn cache_scope(inputs: &SliceInputs<'_>) -> [u8; 32] {
    framed_digest(&[
        b"ottto.cloud-session.cache-scope.v2",
        inputs.destination.as_bytes(),
        inputs.organization_id.as_bytes(),
        inputs.user_id.as_bytes(),
        CHANGES_SCHEMA_VERSION.as_bytes(),
    ])
}

/// The ACK cache's row key for one task id: 64 lowercase hex characters, so
/// the upload-history file never holds a raw provider id and every valid id
/// fits its key column.
fn ack_cache_key(id: &str) -> String {
    hex(&framed_digest(&[
        b"ottto.cloud-session.ack-key.v3",
        id.as_bytes(),
    ]))
}

/// Schedule isolation: the destination and the local organization and user.
/// Known before the hint is read.
fn schedule_scope(inputs: &SliceInputs<'_>) -> [u8; 32] {
    framed_digest(&[
        b"ottto.cloud-session.schedule-scope.v2",
        inputs.destination.as_bytes(),
        inputs.organization_id.as_bytes(),
        inputs.user_id.as_bytes(),
    ])
}

fn framed_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut framed = Vec::new();
    for part in parts {
        push_length_framed(&mut framed, part);
    }
    Sha256::digest(&framed).into()
}

struct ParsedPage {
    changes: Vec<CloudSessionChangeV2>,
    cursor: CloudPageCursor,
    source_item_count: usize,
    /// Rows skipped because their `id` is not a valid session id.
    invalid_ids: usize,
}

#[derive(Clone, PartialEq, Eq)]
enum CloudPageCursor {
    OfficialTerminal,
    Next(String),
    Ambiguous,
}

impl std::fmt::Debug for CloudPageCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OfficialTerminal => "OfficialTerminal",
            Self::Next(_) => "Next(redacted)",
            Self::Ambiguous => "Ambiguous",
        })
    }
}

fn parse_cloud_page(
    raw: &str,
    policy: CloudUploadPolicyV2,
    observed_at: OffsetDateTime,
) -> Result<ParsedPage> {
    let root: Value = serde_json::from_str(raw).context("parse Codex cloud list JSON")?;
    let items = if let Some(items) = root.as_array() {
        items
    } else {
        ["tasks", "items", "data"]
            .iter()
            .find_map(|name| root.get(*name).and_then(Value::as_array))
            .ok_or_else(|| anyhow!("Codex cloud list tasks are missing"))?
    };
    // Every returned row is processed, even beyond the requested limit. A
    // malformed row is skipped alone; its valid siblings still count.
    let mut changes = Vec::new();
    let mut invalid_ids = 0;
    let source_item_count = items.len();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        // Only the official `id`, read as is. A row without a string id or a
        // status is malformed. Otherwise an empty, padded, overlong or
        // control-bearing id is skipped and counted, never repaired, so one
        // bad row cannot fail the whole request at the server.
        let Some(provider_id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(provider_status) = string_field(object, &["status", "state"]) else {
            continue;
        };
        if !valid_session_id(provider_id) {
            invalid_ids += 1;
            continue;
        }
        let mut coverage = vec!["identity".to_string(), "status".to_string()];
        let mut created_at = timestamp_field(object, &["created_at", "createdAt"], observed_at);
        if created_at.is_some() {
            coverage.push("timing".to_string());
        }
        let mut started_at = timestamp_field(object, &["started_at", "startedAt"], observed_at);
        if started_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let mut updated_at = timestamp_field(object, &["updated_at", "updatedAt"], observed_at);
        if updated_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let mut completed_at =
            timestamp_field(object, &["completed_at", "completedAt"], observed_at);
        if completed_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let chronology_invalid = [
            (&created_at, &started_at),
            (&started_at, &completed_at),
            (&created_at, &completed_at),
        ]
        .into_iter()
        .any(|(earlier, later)| {
            match (
                earlier
                    .as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok()),
                later
                    .as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok()),
            ) {
                (Some(earlier), Some(later)) => earlier > later,
                _ => false,
            }
        });
        if chronology_invalid {
            created_at = None;
            started_at = None;
            updated_at = None;
            completed_at = None;
            coverage.retain(|field| field != "timing");
        }
        let attempt_count = u64_field(object, &["attempt_total", "attempt_count", "attempts"])
            .filter(|attempts| *attempts <= 100_000);
        if attempt_count.is_some() {
            coverage.push("attempts".to_string());
        }
        coverage.sort();
        // The title and environment name enter the body only while the
        // metadata policy allows them; the server cleans and caps both.
        let label = |names: &[&str], allowed: bool| {
            allowed
                .then(|| string_field(object, names))
                .flatten()
                .map(|value| value.chars().take(MAX_LABEL_CHARS).collect::<String>())
        };
        changes.push(CloudSessionChangeV2 {
            source_session_id: provider_id.to_string(),
            expected_head_etag: None,
            entity_kind: "task".to_string(),
            lifecycle: lifecycle(Some(provider_status)),
            attempt_count,
            environment_kind: environment_kind(string_field(
                object,
                &["environment_kind", "environment"],
            )),
            measurement_basis: "not_itemized".to_string(),
            coverage,
            created_at,
            started_at,
            updated_at,
            completed_at,
            title: label(&["title"], policy.session_titles_enabled),
            environment_label: label(&["environment_label"], policy.workspace_labels_enabled),
        });
    }
    let cursor = if root.is_array() {
        CloudPageCursor::Ambiguous
    } else {
        parse_cloud_cursor(&root)?
    };
    if source_item_count == 0 && cursor == CloudPageCursor::Ambiguous {
        return Err(anyhow!(
            "Codex cloud list empty response lacks official terminal proof"
        ));
    }
    Ok(ParsedPage {
        changes,
        cursor,
        source_item_count,
        invalid_ids,
    })
}

fn parse_cloud_cursor(root: &Value) -> Result<CloudPageCursor> {
    let official = root
        .get("cursor")
        .map(parse_cloud_cursor_value)
        .transpose()?;
    let mut alias = None;
    let mut alias_seen = false;
    for name in ["next_cursor", "nextCursor"] {
        let Some(raw) = root.get(name) else {
            continue;
        };
        let parsed = parse_cloud_cursor_value(raw)?;
        if alias_seen && alias != parsed {
            return Err(anyhow!("Codex cloud list cursor aliases conflict"));
        }
        alias = parsed;
        alias_seen = true;
    }
    if official.is_some() && alias_seen && official != Some(alias.clone()) {
        return Err(anyhow!("Codex cloud list cursor aliases conflict"));
    }
    Ok(match official {
        Some(None) => CloudPageCursor::OfficialTerminal,
        Some(Some(cursor)) => CloudPageCursor::Next(cursor),
        None if alias_seen => alias.map_or(CloudPageCursor::Ambiguous, CloudPageCursor::Next),
        None => CloudPageCursor::Ambiguous,
    })
}

fn parse_cloud_cursor_value(raw: &Value) -> Result<Option<String>> {
    match raw {
        Value::Null => Ok(None),
        Value::String(value) if !value.is_empty() && value.len() <= 4_096 => {
            Ok(Some(value.clone()))
        }
        _ => Err(anyhow!("Codex cloud list cursor is invalid")),
    }
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}
/// A provider time in canonical UTC RFC 3339, or `None` when absent,
/// unparsable or in the future.
fn timestamp_field(
    object: &serde_json::Map<String, Value>,
    names: &[&str],
    observed_at: OffsetDateTime,
) -> Option<String> {
    string_field(object, names)
        .filter(|value| value.len() <= 64)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .filter(|parsed| *parsed <= observed_at)
        .map(|parsed| timestamp(parsed.to_offset(UtcOffset::UTC)))
}
fn u64_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_u64))
}
fn lifecycle(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "queued" => "queued",
        // The official CLI collapses provider `pending` and `in_progress`
        // into this one status, so it cannot truthfully distinguish queued
        // from running work.
        "pending" => "unknown",
        "running" | "in_progress" => "running",
        "ready" | "applied" | "completed" | "succeeded" | "success" => "completed",
        "failed" | "error" => "failed",
        "cancelled" | "canceled" => "cancelled",
        _ => "unknown",
    }
    .to_string()
}
fn environment_kind(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "hosted" | "cloud" | "provider_cloud" => "hosted",
        "container" | "containerized" => "container",
        _ => "unknown",
    }
    .to_string()
}

fn kill_switch_enabled() -> bool {
    truthy_env(KILL_SWITCH_ENV)
}
fn truthy_env(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
fn timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}
fn valid_rfc3339(value: &str) -> bool {
    !value.is_empty() && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}
/// The shared session-id rule (the server applies the same one): 1 to 255
/// code points, no control character, no leading or trailing whitespace.
/// Any other character, `|` and backslash included, is allowed.
fn valid_session_id(value: &str) -> bool {
    (1..=255).contains(&value.chars().count())
        && !value.chars().any(char::is_control)
        && value == value.trim()
}
fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}
fn push_length_framed(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn atomic_json_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("cloud-session state path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::to_vec(value)?;
    let mut nonce = [0_u8; 16];
    random_fill(&mut nonce).map_err(|_| anyhow!("generate cloud-session state nonce"))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("cloud-session state filename is invalid"))?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", hex(&nonce)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .context("create cloud-session temporary state")?;
        file.write_all(&payload)
            .context("write cloud-session temporary state")?;
        file.sync_all()
            .context("sync cloud-session temporary state")?;
        drop(file);
        fs::rename(&temporary, path).context("replace cloud-session state")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync cloud-session state directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCollectorStartup {
    DeferredTransport,
    Started,
}

/// The connected Codex Mac the collector acts for. No secret.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudSessionRuntimeBinding {
    api_base_url: String,
    device: LocalDeviceBinding,
    organization_id: String,
    user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudSessionRuntimeTransportKey {
    binding: CloudSessionRuntimeBinding,
    device_secret_digest: String,
}

type ActiveCloudSessionTransport = Option<(
    CloudSessionRuntimeTransportKey,
    Box<dyn CloudSessionTransport + Send>,
)>;

/// `None` while this Mac has no connected account or no Codex relay device:
/// the collector then stays idle without reading any secret. An inconsistent
/// binding or an untrusted destination is an error.
fn load_cloud_session_runtime_binding(
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    connections: &FileConnectionStore,
) -> Result<Option<CloudSessionRuntimeBinding>> {
    let account = accounts.load()?;
    let user_id = account
        .user
        .as_ref()
        .map(|user| user.id.trim())
        .filter(|value| !value.is_empty());
    let organization_id = account
        .organization
        .as_ref()
        .map(|organization| organization.id.trim())
        .filter(|value| !value.is_empty());
    let (Some(user_id), Some(organization_id)) = (user_id, organization_id) else {
        return Ok(None);
    };
    if account.state != LocalAccountState::Connected {
        return Ok(None);
    }
    let Some(device) = devices
        .load()?
        .filter(|device| device.sources.iter().any(|source| source == "codex"))
    else {
        return Ok(None);
    };
    if !is_uuid(&device.device_id) {
        return Err(anyhow!(
            "cloud-session relay device is not exactly Codex-bound"
        ));
    }
    let connection = connections
        .load()?
        .ok_or_else(|| anyhow!("cloud-session backend connection is unavailable"))?;
    if connection.setup_run_id.trim().is_empty() || connection.machine_id != device.machine_id {
        return Err(anyhow!(
            "cloud-session backend connection does not match the relay device"
        ));
    }
    // Validate the persisted destination before the caller reads the device
    // secret. Loopback is accepted only when the daemon process explicitly
    // carries the exact same developer override.
    let api_base_url = validated_cloud_session_api_base_url(&connection.api_base_url)?;
    Ok(Some(CloudSessionRuntimeBinding {
        api_base_url,
        device,
        organization_id: organization_id.to_string(),
        user_id: user_id.to_string(),
    }))
}

fn validated_cloud_session_api_base_url(raw: &str) -> Result<String> {
    let value = raw.trim().trim_end_matches('/');
    if value.is_empty() || value.contains(['@', '?', '#']) {
        return Err(anyhow!("cloud-session backend destination is untrusted"));
    }
    let production = value == DEFAULT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{DEFAULT_API_BASE_URL}/"))
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"));
    let exact_developer_override = crate::control::developer_loopback_base(
        value,
        std::env::var("OTTTO_API_BASE_URL").ok().as_deref(),
    );
    if !production && !exact_developer_override {
        return Err(anyhow!("cloud-session backend destination is untrusted"));
    }
    Ok(value.to_string())
}

/// The local inputs a composed slice reads before any network call.
struct ComposedSliceInputs<'a, FLoadCredentials, FComposeTransport> {
    checkpoints: &'a CloudSessionCheckpointStore,
    runner: &'a dyn CloudSessionRunner,
    accounts: &'a FileAccountStore,
    devices: &'a FileDeviceStore,
    connections: &'a FileConnectionStore,
    load_credentials: FLoadCredentials,
    compose_transport: FComposeTransport,
}

fn collect_composed_cloud_sessions_once(
    collector: &mut CloudCollector,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    active_transport: &mut ActiveCloudSessionTransport,
    now: Instant,
) -> CloudSessionCycleOutcome {
    let _stage = StageWindow::begin("codex", "offpass_cloud_sessions");
    let wall = OffsetDateTime::now_utc();
    if collector
        .next_wake(now, wall)
        .is_some_and(|wake| wake > now)
    {
        return CloudSessionCycleOutcome::NotDue;
    }
    collect_composed_cloud_sessions_once_with(
        collector,
        active_transport,
        ComposedSliceInputs {
            checkpoints,
            runner,
            accounts: &FileAccountStore::default(),
            devices: &FileDeviceStore::default(),
            connections: &FileConnectionStore::default(),
            load_credentials: crate::snapshot_client::load_snapshot_device_credentials,
            compose_transport: |binding, device_secret| {
                Box::new(RelayCloudSessionTransport::new(binding, device_secret))
                    as Box<dyn CloudSessionTransport + Send>
            },
        },
        now,
        wall,
    )
}

fn collect_composed_cloud_sessions_once_with<FLoadCredentials, FComposeTransport>(
    collector: &mut CloudCollector,
    active_transport: &mut ActiveCloudSessionTransport,
    inputs: ComposedSliceInputs<'_, FLoadCredentials, FComposeTransport>,
    now: Instant,
    wall: OffsetDateTime,
) -> CloudSessionCycleOutcome
where
    FLoadCredentials: FnOnce() -> Result<(LocalDeviceBinding, String)>,
    FComposeTransport:
        FnOnce(CloudSessionRuntimeBinding, String) -> Box<dyn CloudSessionTransport + Send>,
{
    let started = Instant::now();
    if kill_switch_enabled() {
        active_transport.take();
        collector.reset();
        return CloudSessionCycleOutcome::Disabled;
    }
    let binding = match load_cloud_session_runtime_binding(
        inputs.accounts,
        inputs.devices,
        inputs.connections,
    ) {
        Ok(Some(binding)) => binding,
        Ok(None) => {
            active_transport.take();
            collector.reset();
            collector.report("not_connected");
            return CloudSessionCycleOutcome::Disabled;
        }
        Err(_) => {
            active_transport.take();
            collector.report("local_binding_invalid");
            collector.defer_after_local_failure(now + started.elapsed());
            return CloudSessionCycleOutcome::Failed;
        }
    };
    // The destination is validated above, so an on-disk URL cannot receive
    // this long-lived secret. Reloading the device with the secret also closes
    // an identity-change race.
    let (credential_device, device_secret) = match (inputs.load_credentials)() {
        Ok(credentials) => credentials,
        Err(_) => {
            active_transport.take();
            collector.report("relay_credentials_unavailable");
            collector.defer_after_local_failure(now + started.elapsed());
            return CloudSessionCycleOutcome::Failed;
        }
    };
    if credential_device != binding.device || device_secret.trim().is_empty() {
        active_transport.take();
        collector.report("local_binding_changed");
        collector.defer_after_local_failure(now + started.elapsed());
        return CloudSessionCycleOutcome::Failed;
    }
    let key = CloudSessionRuntimeTransportKey {
        binding: binding.clone(),
        device_secret_digest: sha256(device_secret.as_bytes()),
    };
    if active_transport
        .as_ref()
        .is_none_or(|(current, _)| current != &key)
    {
        let transport = (inputs.compose_transport)(binding.clone(), device_secret);
        *active_transport = Some((key, transport));
    }
    let transport = active_transport
        .as_ref()
        .expect("cloud-session transport was just composed")
        .1
        .as_ref();
    let outcome = collector.run_slice(
        &SliceInputs {
            checkpoints: inputs.checkpoints,
            runner: inputs.runner,
            transport,
            destination: &binding.api_base_url,
            organization_id: &binding.organization_id,
            user_id: &binding.user_id,
        },
        now + started.elapsed(),
        wall,
    );
    if kill_switch_enabled() {
        active_transport.take();
    }
    outcome
}

/// Wakes the supervisor when local Codex activity starts, so a Mac that just
/// connected does not wait for the fallback.
struct CollectorWake {
    activity: Mutex<u64>,
    changed: Condvar,
}

static COLLECTOR_WAKE: CollectorWake = CollectorWake {
    activity: Mutex::new(0),
    changed: Condvar::new(),
};
static LAST_CODEX_ACTIVITY: Mutex<Option<Instant>> = Mutex::new(None);

impl CollectorWake {
    fn count(&self) -> u64 {
        *self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn bump(&self) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *activity = activity.wrapping_add(1);
        self.changed.notify_all();
    }

    /// Wait until `until` (at most the fallback wait) or a wake.
    fn wait(&self, until: Option<Instant>, seen: &mut u64) {
        let fallback = Instant::now() + SUPERVISOR_FALLBACK_WAIT;
        let until = until.map_or(fallback, |until| until.min(fallback));
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if *activity != *seen {
                *seen = *activity;
                return;
            }
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return;
            };
            if remaining.is_zero() {
                return;
            }
            activity = self
                .changed
                .wait_timeout(activity, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }
}

/// The file watcher saw a real local Codex transcript event. Only the first
/// event of a warm window wakes the supervisor; later ones keep the window.
pub(crate) fn note_local_codex_activity() {
    let now = Instant::now();
    let was_warm = {
        let mut last = LAST_CODEX_ACTIVITY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let warm = last.is_some_and(|activity| {
            now.saturating_duration_since(activity)
                <= crate::adaptive_collector::CadenceConfig::default().warm_window
        });
        *last = Some(now);
        warm
    };
    if !was_warm {
        COLLECTOR_WAKE.bump();
    }
}

fn reserve_collector_supervisor(started: &AtomicBool) -> bool {
    started
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_ok()
}

/// The per-Mac grant, its replay ledger and the pre-cache checkpoint are no
/// longer used. Remove them before the supervisor starts; touch nothing else
/// (the daily reference keeps its own ledger in its own directory).
fn remove_retired_consent_state(support_dir: &Path) {
    let directory = support_dir.join("cloud_sessions");
    for name in RETIRED_STATE_FILES {
        match fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "codex_cloud_tasks retired_state_not_removed file={name} kind={:?}",
                error.kind()
            ),
        }
    }
}

pub fn spawn_cloud_session_collector() -> Result<CloudSessionCollectorStartup> {
    // The supervisor is always available so listing turned on in the app
    // starts without restarting the daemon. Each slice stays inert until the
    // Codex hint turns listing on for the connected user.
    if !reserve_collector_supervisor(&COLLECTOR_SUPERVISOR_STARTED) {
        return Ok(CloudSessionCollectorStartup::Started);
    }
    remove_retired_consent_state(&default_support_dir());
    let spawned = thread::Builder::new()
        .name("ottto-codex-cloud-sessions".to_string())
        .spawn(|| {
            let checkpoints = CloudSessionCheckpointStore::default();
            let runner = CodexCloudCliRunner;
            let mut active_transport = None;
            let mut collector = CloudCollector::default();
            let mut seen = COLLECTOR_WAKE.count();
            loop {
                collect_composed_cloud_sessions_once(
                    &mut collector,
                    &checkpoints,
                    &runner,
                    &mut active_transport,
                    Instant::now(),
                );
                let wake_at = collector
                    .next_wake(Instant::now(), OffsetDateTime::now_utc())
                    .map(|deadline| {
                        let mut random = [0_u8; 8];
                        let seconds = if random_fill(&mut random).is_ok() {
                            u64::from_ne_bytes(random) % 21
                        } else {
                            0
                        };
                        deadline + Duration::from_secs(seconds)
                    });
                COLLECTOR_WAKE.wait(wake_at, &mut seen);
            }
        });
    if let Err(error) = spawned {
        COLLECTOR_SUPERVISOR_STARTED.store(false, AtomicOrdering::Release);
        return Err(anyhow!("spawn Codex cloud-session collector: {error}"));
    }
    Ok(CloudSessionCollectorStartup::Started)
}

#[cfg(test)]
mod tests;
