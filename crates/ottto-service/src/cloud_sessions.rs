//! Supported, metadata-only Codex Cloud session collector.
//!
//! The collector invokes only `codex cloud list --json` as the effective user.
//! It never opens `auth.json`, touches Keychain credentials, or calls provider
//! endpoints directly. Raw CLI JSON, task titles, URLs, provider ids, and
//! cursors are used only in memory to derive content-free observations.

use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{compiled_release_version, default_support_dir};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const COLLECTOR_ID: &str = "cloud_sessions";
const COLLECTOR_VERSION: &str = "cloud_session_observations.v1";
const GRANT_SCHEMA_VERSION: &str = "cloud_session_grant.v1";
const CHECKPOINT_SCHEMA_VERSION: &str = "cloud_session_checkpoint.v1";
const MAX_PAGES: usize = 3;
const MAX_ITEMS: usize = 60;
const PAGE_LIMIT: usize = 20;
const CYCLE_BUDGET: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_JITTER: Duration = Duration::from_secs(20);
const KILL_SWITCH_ENV: &str = "OTTTO_CODEX_CLOUD_SESSIONS_DISABLED";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionGrantStatus {
    Off,
    ConsentRequired,
    Enabled,
    Paused,
    Revoked,
    PolicyDisabled,
}

/// Operator/UI status for this collector. The service exposes this without
/// starting the provider CLI, so setup and transport readiness can be shown
/// safely before any cloud-session collection is permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionRuntimeState {
    Off,
    ConsentRequired,
    Enabled,
    Paused,
    Revoked,
    PolicyDisabled,
    TransportDeferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionCollectorStatusV1 {
    pub schema_version: String,
    pub collector_id: String,
    pub grant_status: CloudSessionGrantStatus,
    pub runtime_state: CloudSessionRuntimeState,
    pub transport_configured: bool,
    /// This is false while the typed ingest transport is deferred. Consumers
    /// must not imply that enabling a grant will call the Codex CLI.
    pub provider_cli_invocation_permitted: bool,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionGrant {
    pub schema_version: String,
    pub collector_id: String,
    pub collector_version: String,
    pub release_lane: String,
    pub disclosure_version: String,
    pub status: CloudSessionGrantStatus,
    /// Opaque grant-local fingerprint; the raw installation id is never persisted.
    pub installation_fingerprint: String,
    /// Immutable identity for this exact installation/user/collector grant.
    pub grant_scope_id: String,
    pub organization_fingerprint: String,
    pub effective_user_fingerprint: String,
    pub account_fingerprint: String,
    pub granted_at: Option<String>,
    pub paused_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_collector_health: Option<String>,
    pub last_freshness: Option<String>,
    pub last_error_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CloudSessionGrantSetup {
    pub installation_id: String,
    pub organization_scope: String,
    pub effective_user_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedGrant {
    schema_version: String,
    hmac_key_hex: String,
    grant: CloudSessionGrant,
}

/// Upgrade-only representation written before installation scope became
/// content-free. It is never serialized again after a successful read.
#[derive(Debug, Clone, Deserialize)]
struct LegacyPersistedGrantV1 {
    schema_version: String,
    hmac_key_hex: String,
    grant: LegacyCloudSessionGrantV1,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyCloudSessionGrantV1 {
    schema_version: String,
    collector_id: String,
    collector_version: String,
    release_lane: String,
    disclosure_version: String,
    status: CloudSessionGrantStatus,
    installation_id: String,
    organization_fingerprint: String,
    effective_user_fingerprint: String,
    account_fingerprint: String,
    granted_at: Option<String>,
    paused_at: Option<String>,
    revoked_at: Option<String>,
    last_collector_health: Option<String>,
    last_freshness: Option<String>,
    last_error_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CloudSessionGrantStore {
    path: PathBuf,
}

impl CloudSessionGrantStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<CloudSessionGrant>> {
        Ok(self.read()?.map(|state| state.grant))
    }

    /// Explicit local setup. Scope inputs are converted to HMAC fingerprints
    /// before persistence; they are never serialized or uploaded.
    pub fn enable(
        &self,
        setup: &CloudSessionGrantSetup,
        now: OffsetDateTime,
    ) -> Result<CloudSessionGrant> {
        if setup.installation_id.trim().is_empty()
            || setup.organization_scope.trim().is_empty()
            || setup.effective_user_scope.trim().is_empty()
        {
            return Err(anyhow!("cloud-session grant scope is incomplete"));
        }
        let _lock = self.lock()?;
        let key = random_key()?;
        let installation_fingerprint = opaque_key(&key, &setup.installation_id);
        let grant_scope_id = opaque_key(
            &key,
            &format!(
                "{}\u{0}{}\u{0}{}\u{0}{}",
                setup.installation_id,
                setup.organization_scope,
                setup.effective_user_scope,
                COLLECTOR_ID
            ),
        );
        let grant = CloudSessionGrant {
            schema_version: GRANT_SCHEMA_VERSION.to_string(),
            collector_id: COLLECTOR_ID.to_string(),
            collector_version: COLLECTOR_VERSION.to_string(),
            release_lane: "supported".to_string(),
            disclosure_version: "cloud_sessions_disclosure.v1".to_string(),
            status: CloudSessionGrantStatus::Enabled,
            installation_fingerprint,
            grant_scope_id,
            organization_fingerprint: opaque_key(&key, &setup.organization_scope),
            effective_user_fingerprint: opaque_key(&key, &setup.effective_user_scope),
            account_fingerprint: opaque_key(
                &key,
                &format!(
                    "{}\u{0}{}",
                    setup.organization_scope, setup.effective_user_scope
                ),
            ),
            granted_at: Some(timestamp(now)),
            paused_at: None,
            revoked_at: None,
            last_collector_health: Some("enabled".to_string()),
            last_freshness: Some("unavailable".to_string()),
            last_error_category: None,
        };
        self.write(&PersistedGrant {
            schema_version: GRANT_SCHEMA_VERSION.to_string(),
            hmac_key_hex: hex(&key),
            grant: grant.clone(),
        })?;
        Ok(grant)
    }

    pub fn pause(&self, now: OffsetDateTime) -> Result<()> {
        self.change_status(CloudSessionGrantStatus::Paused, now)
    }

    pub fn revoke(&self, now: OffsetDateTime) -> Result<()> {
        self.change_status(CloudSessionGrantStatus::Revoked, now)
    }

    fn change_status(&self, status: CloudSessionGrantStatus, now: OffsetDateTime) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self
            .read_locked()?
            .ok_or_else(|| anyhow!("cloud-session grant is absent"))?;
        state.grant.status = status.clone();
        state.grant.last_collector_health = Some(
            match status {
                CloudSessionGrantStatus::Paused => "paused",
                CloudSessionGrantStatus::Revoked => "revoked",
                _ => "disabled",
            }
            .to_string(),
        );
        state.grant.last_freshness = Some("unavailable".to_string());
        state.grant.last_error_category = None;
        match status {
            CloudSessionGrantStatus::Paused => state.grant.paused_at = Some(timestamp(now)),
            CloudSessionGrantStatus::Revoked => state.grant.revoked_at = Some(timestamp(now)),
            _ => {}
        }
        self.write(&state)
    }

    fn read(&self) -> Result<Option<PersistedGrant>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let _lock = self.lock()?;
        self.read_locked()
    }

    fn read_locked(&self) -> Result<Option<PersistedGrant>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path).context("read cloud-session grant")?;
        let state = match serde_json::from_slice::<PersistedGrant>(&bytes) {
            Ok(state) => state,
            Err(current_error) => {
                let legacy: LegacyPersistedGrantV1 = serde_json::from_slice(&bytes)
                    .with_context(|| format!("decode cloud-session grant: {current_error}"))?;
                self.migrate_legacy_v1(legacy)?
            }
        };
        if state.schema_version != GRANT_SCHEMA_VERSION
            || state.grant.schema_version != GRANT_SCHEMA_VERSION
        {
            return Err(anyhow!("unsupported cloud-session grant version"));
        }
        Ok(Some(state))
    }

    fn migrate_legacy_v1(&self, legacy: LegacyPersistedGrantV1) -> Result<PersistedGrant> {
        if legacy.schema_version != GRANT_SCHEMA_VERSION
            || legacy.grant.schema_version != GRANT_SCHEMA_VERSION
            || legacy.grant.installation_id.trim().is_empty()
        {
            return Err(anyhow!("unsupported cloud-session grant version"));
        }
        let key = decode_hex(&legacy.hmac_key_hex)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| anyhow!("invalid cloud-session HMAC key"))?;
        let installation_fingerprint = opaque_key(&key, &legacy.grant.installation_id);
        let grant_scope_id = opaque_key(
            &key,
            &format!(
                "{}\u{0}{}\u{0}{}\u{0}{}",
                legacy.grant.installation_id,
                legacy.grant.organization_fingerprint,
                legacy.grant.effective_user_fingerprint,
                legacy.grant.collector_id
            ),
        );
        let state = PersistedGrant {
            schema_version: legacy.schema_version,
            hmac_key_hex: legacy.hmac_key_hex,
            grant: CloudSessionGrant {
                schema_version: legacy.grant.schema_version,
                collector_id: legacy.grant.collector_id,
                collector_version: legacy.grant.collector_version,
                release_lane: legacy.grant.release_lane,
                disclosure_version: legacy.grant.disclosure_version,
                status: legacy.grant.status,
                installation_fingerprint,
                grant_scope_id,
                organization_fingerprint: legacy.grant.organization_fingerprint,
                effective_user_fingerprint: legacy.grant.effective_user_fingerprint,
                account_fingerprint: legacy.grant.account_fingerprint,
                granted_at: legacy.grant.granted_at,
                paused_at: legacy.grant.paused_at,
                revoked_at: legacy.grant.revoked_at,
                last_collector_health: legacy.grant.last_collector_health,
                last_freshness: legacy.grant.last_freshness,
                last_error_category: legacy.grant.last_error_category,
            },
        };
        self.write(&state)?;
        Ok(state)
    }

    fn write(&self, state: &PersistedGrant) -> Result<()> {
        atomic_json_write(&self.path, state)
    }

    fn record_health(
        &self,
        health: &str,
        freshness: &str,
        error_category: Option<&str>,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let Some(mut state) = self.read_locked()? else {
            return Ok(());
        };
        if state.grant.status != CloudSessionGrantStatus::Enabled {
            return Ok(());
        }
        state.grant.last_collector_health = Some(health.to_string());
        state.grant.last_freshness = Some(freshness.to_string());
        state.grant.last_error_category = error_category.map(str::to_string);
        self.write(&state)
    }

    fn lock(&self) -> Result<CloudSessionGrantLock> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("cloud-session grant path has no parent"))?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let path = self.path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("open cloud-session grant lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        {
            // The state can be changed by the local UI/control process while
            // the collector thread records health. Hold a process-wide lock so
            // stale read-modify-write health updates cannot restore consent.
            if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } != 0 {
                return Err(anyhow!("lock cloud-session grant"));
            }
        }
        Ok(CloudSessionGrantLock { file })
    }
}

impl Default for CloudSessionGrantStore {
    fn default() -> Self {
        Self::new(
            default_support_dir()
                .join("cloud_sessions")
                .join("grant.json"),
        )
    }
}

struct CloudSessionGrantLock {
    file: File,
}

impl Drop for CloudSessionGrantLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

/// Build the visible collector state without creating a runner or invoking
/// Codex. The default service wiring deliberately passes the deferred
/// transport, which makes provider CLI use impossible in this public slice.
pub fn cloud_session_collector_status(
    grants: &CloudSessionGrantStore,
    transport: &dyn CloudSessionTransport,
) -> CloudSessionCollectorStatusV1 {
    let grant_status = if kill_switch_enabled() {
        CloudSessionGrantStatus::PolicyDisabled
    } else {
        grants
            .load()
            .ok()
            .flatten()
            .map(|grant| grant.status)
            .unwrap_or(CloudSessionGrantStatus::Off)
    };
    let transport_configured = transport.is_configured();
    let provider_cli_invocation_permitted =
        grant_status == CloudSessionGrantStatus::Enabled && transport_configured;
    let (runtime_state, reason_code) = if kill_switch_enabled() {
        (
            CloudSessionRuntimeState::PolicyDisabled,
            "policy_disabled".to_string(),
        )
    } else if grant_status == CloudSessionGrantStatus::Enabled && !transport_configured {
        (
            CloudSessionRuntimeState::TransportDeferred,
            "transport_deferred".to_string(),
        )
    } else {
        let reason_code = match grant_status {
            CloudSessionGrantStatus::Off => "setup_required",
            CloudSessionGrantStatus::ConsentRequired => "consent_required",
            CloudSessionGrantStatus::Enabled => "enabled",
            CloudSessionGrantStatus::Paused => "paused",
            CloudSessionGrantStatus::Revoked => "revoked",
            CloudSessionGrantStatus::PolicyDisabled => "policy_disabled",
        };
        (
            match grant_status {
                CloudSessionGrantStatus::Off => CloudSessionRuntimeState::Off,
                CloudSessionGrantStatus::ConsentRequired => {
                    CloudSessionRuntimeState::ConsentRequired
                }
                CloudSessionGrantStatus::Enabled => CloudSessionRuntimeState::Enabled,
                CloudSessionGrantStatus::Paused => CloudSessionRuntimeState::Paused,
                CloudSessionGrantStatus::Revoked => CloudSessionRuntimeState::Revoked,
                CloudSessionGrantStatus::PolicyDisabled => CloudSessionRuntimeState::PolicyDisabled,
            },
            reason_code.to_string(),
        )
    };
    CloudSessionCollectorStatusV1 {
        schema_version: "cloud_session_collector_status.v1".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        grant_status,
        runtime_state,
        transport_configured,
        provider_cli_invocation_permitted,
        reason_code,
    }
}

pub fn default_cloud_session_collector_status() -> CloudSessionCollectorStatusV1 {
    cloud_session_collector_status(
        &CloudSessionGrantStore::default(),
        &DeferredCloudSessionTransport,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionObservationBatchV1 {
    pub schema_version: String,
    pub collector_id: String,
    pub collector_version: String,
    pub grant_scope_id: String,
    pub account_fingerprint: String,
    pub observed_at: String,
    pub collected_at: String,
    pub semantic_digest: String,
    pub entities: Vec<CloudSessionObservationEntityV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionObservationEntityV1 {
    pub source: String,
    pub opaque_provider_entity_key: String,
    pub entity_kind: String,
    pub execution_location: String,
    pub lifecycle: String,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub updated_at: Option<String>,
    pub completed_at: Option<String>,
    pub attempt_count: Option<u64>,
    pub environment_kind: String,
    pub measurement_basis: String,
    pub field_coverage_mask: Vec<String>,
    pub freshness: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CloudSessionCheckpoint {
    schema_version: String,
    semantic_digest: Option<String>,
    consecutive_failures: u32,
    circuit_open_until: Option<String>,
    last_error_category: Option<String>,
    last_success_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CloudSessionCheckpointStore {
    path: PathBuf,
}

impl CloudSessionCheckpointStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    fn load(&self) -> CloudSessionCheckpoint {
        fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|state: &CloudSessionCheckpoint| {
                state.schema_version == CHECKPOINT_SCHEMA_VERSION
            })
            .unwrap_or_else(|| CloudSessionCheckpoint {
                schema_version: CHECKPOINT_SCHEMA_VERSION.to_string(),
                ..Default::default()
            })
    }
    fn save(&self, state: &CloudSessionCheckpoint) -> Result<()> {
        atomic_json_write(&self.path, state)
    }
}

impl Default for CloudSessionCheckpointStore {
    fn default() -> Self {
        Self::new(
            default_support_dir()
                .join("cloud_sessions")
                .join("checkpoint.json"),
        )
    }
}

pub trait CloudSessionRunner {
    /// `cursor` may only be retained by the caller for this single cycle.
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String>;
}

pub trait CloudSessionTransport {
    /// A backend route must be explicitly wired before collection starts. This
    /// prevents a setup grant from causing provider calls that cannot yield a
    /// permitted upload.
    fn is_configured(&self) -> bool {
        true
    }
    fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()>;
}

/// Deliberately does not guess an ingest endpoint. Private/backend wiring can
/// replace this typed boundary when the `cloud_session_observations.v1` route is available.
pub struct DeferredCloudSessionTransport;
impl CloudSessionTransport for DeferredCloudSessionTransport {
    fn is_configured(&self) -> bool {
        false
    }

    fn send(&self, _batch: &CloudSessionObservationBatchV1) -> Result<()> {
        Err(anyhow!("cloud-session ingest endpoint is not configured"))
    }
}

pub struct CodexCloudCliRunner;
impl CloudSessionRunner for CodexCloudCliRunner {
    fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<String> {
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
                .take((MAX_ITEMS * 256 * 1024) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let started = Instant::now();
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
                Ok(None) if started.elapsed() >= COMMAND_TIMEOUT => {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudSessionCycleOutcome {
    Disabled,
    CircuitOpen,
    Noop,
    Uploaded,
    Failed,
}

pub fn collect_cloud_sessions_once(
    grants: &CloudSessionGrantStore,
    checkpoints: &CloudSessionCheckpointStore,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
) -> CloudSessionCycleOutcome {
    if kill_switch_enabled() || !grant_enabled(grants) {
        return CloudSessionCycleOutcome::Disabled;
    }
    if !transport.is_configured() {
        let _ = grants.record_health("unavailable", "unavailable", Some("transport_unconfigured"));
        return CloudSessionCycleOutcome::Noop;
    }
    let mut checkpoint = checkpoints.load();
    if circuit_open(&checkpoint, now) {
        return CloudSessionCycleOutcome::CircuitOpen;
    }
    let result = collect_enabled_cycle(grants, &checkpoint, runner, transport, now);
    match result {
        Ok(CycleResult::Noop) => {
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Noop
        }
        Ok(CycleResult::Uploaded(digest)) => {
            checkpoint.semantic_digest = Some(digest);
            checkpoint.consecutive_failures = 0;
            checkpoint.circuit_open_until = None;
            checkpoint.last_error_category = None;
            checkpoint.last_success_at = Some(timestamp(now));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("ok", "fresh", None);
            CloudSessionCycleOutcome::Uploaded
        }
        Err(error) => {
            checkpoint.consecutive_failures = checkpoint.consecutive_failures.saturating_add(1);
            checkpoint.last_error_category = Some(error.category.to_string());
            checkpoint.circuit_open_until = Some(timestamp(
                now + TimeDuration::seconds(backoff_seconds(checkpoint.consecutive_failures) as i64),
            ));
            let _ = checkpoints.save(&checkpoint);
            let _ = grants.record_health("failing", "stale", Some(error.category));
            CloudSessionCycleOutcome::Failed
        }
    }
}

enum CycleResult {
    Noop,
    Uploaded(String),
}
struct CycleError {
    category: &'static str,
}

fn collect_enabled_cycle(
    grants: &CloudSessionGrantStore,
    checkpoint: &CloudSessionCheckpoint,
    runner: &dyn CloudSessionRunner,
    transport: &dyn CloudSessionTransport,
    now: OffsetDateTime,
) -> std::result::Result<CycleResult, CycleError> {
    let state = grants
        .read()
        .map_err(|_| CycleError {
            category: "grant_unavailable",
        })?
        .ok_or(CycleError {
            category: "grant_absent",
        })?;
    if state.grant.status != CloudSessionGrantStatus::Enabled || kill_switch_enabled() {
        return Ok(CycleResult::Noop);
    }
    let key = decode_hex(&state.hmac_key_hex).ok_or(CycleError {
        category: "grant_invalid",
    })?;
    let deadline = Instant::now() + CYCLE_BUDGET;
    let mut cursor: Option<String> = None;
    let mut entities = Vec::new();
    for _ in 0..MAX_PAGES {
        if Instant::now() >= deadline || entities.len() >= MAX_ITEMS {
            break;
        }
        // Pause/revoke is a local control boundary, not merely an upload
        // boundary. Check it before every paginated provider call.
        if !grant_enabled(grants) || kill_switch_enabled() {
            return Ok(CycleResult::Noop);
        }
        let raw = runner
            .list_page(cursor.as_deref(), PAGE_LIMIT)
            .map_err(|_| CycleError {
                category: "provider_unavailable",
            })?;
        let page = parse_cloud_page(&raw, &key).map_err(|_| CycleError {
            category: "provider_payload_invalid",
        })?;
        let count = (MAX_ITEMS - entities.len()).min(page.entities.len());
        entities.extend(page.entities.into_iter().take(count));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    entities.sort_by(|left, right| {
        left.opaque_provider_entity_key
            .cmp(&right.opaque_provider_entity_key)
    });
    entities.dedup_by(|left, right| {
        left.opaque_provider_entity_key == right.opaque_provider_entity_key
    });
    let digest = semantic_digest(&entities).map_err(|_| CycleError {
        category: "digest_failed",
    })?;
    if checkpoint.semantic_digest.as_deref() == Some(digest.as_str()) {
        return Ok(CycleResult::Noop);
    }
    // Re-read immediately before transport so a local pause/revoke wins over a
    // concurrent in-flight parse and stops network use before the next upload.
    let current = grants.read().map_err(|_| CycleError {
        category: "grant_unavailable",
    })?;
    if kill_switch_enabled()
        || current.as_ref().map_or(true, |value| {
            value.grant.status != CloudSessionGrantStatus::Enabled
        })
    {
        return Ok(CycleResult::Noop);
    }
    let batch = CloudSessionObservationBatchV1 {
        schema_version: "cloud_session_observations.v1".to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        collector_version: compiled_release_version(),
        grant_scope_id: state.grant.grant_scope_id,
        account_fingerprint: state.grant.account_fingerprint,
        observed_at: timestamp(now),
        collected_at: timestamp(now),
        semantic_digest: digest.clone(),
        entities,
    };
    transport.send(&batch).map_err(|_| CycleError {
        category: "transport_unavailable",
    })?;
    Ok(CycleResult::Uploaded(digest))
}

struct ParsedPage {
    entities: Vec<CloudSessionObservationEntityV1>,
    next_cursor: Option<String>,
}

fn parse_cloud_page(raw: &str, key: &[u8]) -> Result<ParsedPage> {
    let root: Value = serde_json::from_str(raw).context("parse Codex cloud list JSON")?;
    let items = if let Some(items) = root.as_array() {
        items
    } else {
        ["tasks", "items", "data"]
            .iter()
            .find_map(|name| root.get(*name).and_then(Value::as_array))
            .ok_or_else(|| anyhow!("Codex cloud list tasks are missing"))?
    };
    let mut entities = Vec::new();
    for item in items.iter().take(PAGE_LIMIT) {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(provider_id) = string_field(object, &["id", "task_id"]) else {
            continue;
        };
        let mut coverage = vec!["identity".to_string(), "status".to_string()];
        let created_at = timestamp_field(object, &["created_at", "createdAt"]);
        if created_at.is_some() {
            coverage.push("timing".to_string());
        }
        let started_at = timestamp_field(object, &["started_at", "startedAt"]);
        if started_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let updated_at = timestamp_field(object, &["updated_at", "updatedAt"]);
        if updated_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let completed_at = timestamp_field(object, &["completed_at", "completedAt"]);
        if completed_at.is_some() && !coverage.contains(&"timing".to_string()) {
            coverage.push("timing".to_string());
        }
        let attempt_count = u64_field(object, &["attempt_count", "attempts"]);
        if attempt_count.is_some() {
            coverage.push("attempts".to_string());
        }
        entities.push(CloudSessionObservationEntityV1 {
            source: "codex".to_string(),
            opaque_provider_entity_key: opaque_key(key, provider_id),
            entity_kind: "task".to_string(),
            execution_location: "provider_cloud".to_string(),
            lifecycle: lifecycle(string_field(object, &["status", "state"])),
            created_at,
            started_at,
            updated_at,
            completed_at,
            attempt_count,
            environment_kind: environment_kind(string_field(
                object,
                &["environment_kind", "environment"],
            )),
            measurement_basis: "not_itemized".to_string(),
            field_coverage_mask: coverage,
            freshness: "fresh".to_string(),
        });
    }
    Ok(ParsedPage {
        entities,
        next_cursor: string_value(root.get("next_cursor"))
            .or_else(|| string_value(root.get("nextCursor")))
            .map(str::to_string),
    })
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}
fn timestamp_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<String> {
    string_field(object, names)
        .filter(|value| value.len() <= 64 && OffsetDateTime::parse(value, &Rfc3339).is_ok())
        .map(str::to_string)
}
fn u64_field(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_u64))
}
fn lifecycle(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "queued" | "pending" => "queued",
        "running" | "in_progress" => "running",
        "completed" | "succeeded" | "success" => "completed",
        "failed" | "error" => "failed",
        "cancelled" | "canceled" => "cancelled",
        _ => "unknown",
    }
    .to_string()
}
fn environment_kind(value: Option<&str>) -> String {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "development" | "dev" => "development",
        "staging" | "stage" => "staging",
        "production" | "prod" => "production",
        _ => "unknown",
    }
    .to_string()
}

fn semantic_digest(entities: &[CloudSessionObservationEntityV1]) -> Result<String> {
    let payload = serde_json::to_vec(
        &json!({"schema_version":"cloud_session_observations.v1", "entities": entities}),
    )?;
    Ok(sha256(&payload))
}
fn grant_enabled(store: &CloudSessionGrantStore) -> bool {
    store
        .load()
        .ok()
        .flatten()
        .is_some_and(|grant| grant.status == CloudSessionGrantStatus::Enabled)
}
fn circuit_open(checkpoint: &CloudSessionCheckpoint, now: OffsetDateTime) -> bool {
    checkpoint
        .circuit_open_until
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .is_some_and(|until| until > now)
}
fn backoff_seconds(failures: u32) -> u64 {
    60 * (1_u64 << failures.min(6))
}
fn kill_switch_enabled() -> bool {
    std::env::var(KILL_SWITCH_ENV).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
fn timestamp(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}
fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
fn opaque_key(key: &[u8], raw: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(raw.as_bytes());
    format!("hmac-sha256:{}", hex(&mac.finalize().into_bytes()))
}
fn random_key() -> Result<Vec<u8>> {
    let mut key = vec![0_u8; 32];
    random_fill(&mut key).map_err(|_| anyhow!("generate cloud-session HMAC key"))?;
    Ok(key)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    (raw.len() % 2 == 0).then_some(())?;
    (0..raw.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).ok())
        .collect()
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

pub fn spawn_cloud_session_collector() -> Result<CloudSessionCollectorStartup> {
    // Public builds have no ingest endpoint. Do not register a poller that
    // merely looks active: deferred transport means no runner is constructed
    // and no provider CLI process can be started.
    let transport = DeferredCloudSessionTransport;
    if !transport.is_configured() {
        return Ok(CloudSessionCollectorStartup::DeferredTransport);
    }
    thread::Builder::new()
        .name("ottto-codex-cloud-sessions".to_string())
        .spawn(|| {
            let grants = CloudSessionGrantStore::default();
            let checkpoints = CloudSessionCheckpointStore::default();
            let runner = CodexCloudCliRunner;
            let transport = DeferredCloudSessionTransport;
            loop {
                let outcome = collect_cloud_sessions_once(
                    &grants,
                    &checkpoints,
                    &runner,
                    &transport,
                    OffsetDateTime::now_utc(),
                );
                if !matches!(
                    outcome,
                    CloudSessionCycleOutcome::Disabled | CloudSessionCycleOutcome::Noop
                ) {
                    eprintln!("codex_cloud_session_collector outcome={outcome:?}");
                }
                thread::sleep(POLL_INTERVAL + cycle_jitter());
            }
        })
        .map_err(|error| anyhow!("spawn Codex cloud-session collector: {error}"))?;
    Ok(CloudSessionCollectorStartup::Started)
}

fn cycle_jitter() -> Duration {
    // No persisted schedule/cursor: bounded variation prevents synchronized polls.
    let nanos = OffsetDateTime::now_utc().nanosecond() as u64;
    Duration::from_secs(nanos % (MAX_JITTER.as_secs() + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-cloud-sessions-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-21T12:00:00Z", &Rfc3339).unwrap()
    }
    fn stores(name: &str) -> (CloudSessionGrantStore, CloudSessionCheckpointStore) {
        let root = temp_dir(name);
        (
            CloudSessionGrantStore::new(root.join("grant.json")),
            CloudSessionCheckpointStore::new(root.join("checkpoint.json")),
        )
    }
    fn enabled(store: &CloudSessionGrantStore) {
        store
            .enable(
                &CloudSessionGrantSetup {
                    installation_id: "install_fixture".to_string(),
                    organization_scope: "org_fixture".to_string(),
                    effective_user_scope: "user_fixture".to_string(),
                },
                now(),
            )
            .unwrap();
    }
    struct Pages {
        pages: RefCell<Vec<String>>,
        calls: Cell<usize>,
        revoke: Option<CloudSessionGrantStore>,
    }
    impl CloudSessionRunner for Pages {
        fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<String> {
            self.calls.set(self.calls.get() + 1);
            if let Some(store) = &self.revoke {
                store.revoke(now()).unwrap();
            }
            Ok(self.pages.borrow_mut().remove(0))
        }
    }
    struct RecordingTransport {
        calls: Cell<usize>,
        batches: RefCell<Vec<CloudSessionObservationBatchV1>>,
        fail: bool,
    }
    impl CloudSessionTransport for RecordingTransport {
        fn send(&self, batch: &CloudSessionObservationBatchV1) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.batches.borrow_mut().push(batch.clone());
            if self.fail {
                Err(anyhow!("offline"))
            } else {
                Ok(())
            }
        }
    }
    fn page(id: &str, cursor: Option<&str>) -> String {
        json!({"tasks":[{"id":id,"title":"private title","url":"https://example.invalid/private","status":"completed","created_at":"2026-07-21T11:00:00Z","attempt_count":2}], "next_cursor": cursor}).to_string()
    }

    #[test]
    fn emitted_wire_is_content_free_and_opaque() {
        let parsed = parse_cloud_page(
            &page("provider-task-123", Some("private-cursor")),
            b"fixture-key",
        )
        .unwrap();
        let encoded = serde_json::to_string(&parsed.entities).unwrap();
        assert!(!encoded.contains("provider-task-123"));
        assert!(!encoded.contains("private title"));
        assert!(!encoded.contains("example.invalid"));
        assert!(!encoded.contains("private-cursor"));
        assert!(encoded.contains("hmac-sha256:"));
    }

    #[test]
    fn persisted_grant_discards_raw_scope_and_uses_private_atomic_state() {
        let (grants, _checkpoints) = stores("private-grant-state");
        enabled(&grants);

        let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
        assert!(!encoded.contains("install_fixture"));
        assert!(!encoded.contains("org_fixture"));
        assert!(!encoded.contains("user_fixture"));
        assert!(encoded.contains("installation_fingerprint"));
        assert!(encoded.contains("grant_scope_id"));

        let parent = grants.path().parent().unwrap();
        assert!(fs::read_dir(parent).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(parent).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(
                fs::metadata(grants.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(grants.path().with_extension("lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn legacy_v1_grant_is_privately_migrated_and_remains_revocable() {
        let (grants, _checkpoints) = stores("legacy-grant-migration");
        let legacy = json!({
            "schema_version": GRANT_SCHEMA_VERSION,
            "hmac_key_hex": "11".repeat(32),
            "grant": {
                "schema_version": GRANT_SCHEMA_VERSION,
                "collector_id": COLLECTOR_ID,
                "collector_version": COLLECTOR_VERSION,
                "release_lane": "supported",
                "disclosure_version": "cloud_sessions_disclosure.v1",
                "status": CloudSessionGrantStatus::Enabled,
                "installation_id": "legacy-installation-raw",
                "organization_fingerprint": "hmac-sha256:legacy-org",
                "effective_user_fingerprint": "hmac-sha256:legacy-user",
                "account_fingerprint": "hmac-sha256:legacy-account",
                "granted_at": "2026-07-20T12:00:00Z",
                "paused_at": null,
                "revoked_at": null,
                "last_collector_health": "enabled",
                "last_freshness": "unavailable",
                "last_error_category": null
            }
        });
        fs::write(grants.path(), serde_json::to_vec(&legacy).unwrap()).unwrap();

        let migrated = grants.load().unwrap().unwrap();
        assert_eq!(migrated.status, CloudSessionGrantStatus::Enabled);
        assert!(migrated.installation_fingerprint.starts_with("hmac-sha256:"));
        assert!(migrated.grant_scope_id.starts_with("hmac-sha256:"));
        let encoded = String::from_utf8(fs::read(grants.path()).unwrap()).unwrap();
        assert!(!encoded.contains("legacy-installation-raw"));
        assert!(!encoded.contains("installation_id"));

        grants.pause(now()).unwrap();
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Paused
        );
        grants.revoke(now()).unwrap();
        assert_eq!(
            grants.load().unwrap().unwrap().status,
            CloudSessionGrantStatus::Revoked
        );
    }

    #[test]
    fn repeated_semantics_are_a_transport_noop() {
        let (grants, checkpoints) = stores("noop");
        enabled(&grants);
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let first = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &first, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        let second = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &second, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(transport.calls.get(), 1);
        let encoded = serde_json::to_string(&transport.batches.borrow()[0]).unwrap();
        assert!(!encoded.contains("install_fixture"));
        assert!(!encoded.contains("org_fixture"));
        assert!(!encoded.contains("user_fixture"));
        assert!(encoded.contains("grant_scope_id"));
    }

    #[test]
    fn disabled_and_revoked_grants_never_call_provider_or_transport() {
        let (grants, checkpoints) = stores("revoke");
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        enabled(&grants);
        grants.revoke(now()).unwrap();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Disabled
        );
        assert_eq!(runner.calls.get(), 0);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn revocation_between_page_and_send_stops_upload() {
        let (grants, checkpoints) = stores("race");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![
                page("one", Some("cursor-after-revoke")),
                page("two", None),
            ]),
            calls: Cell::new(0),
            revoke: Some(grants.clone()),
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(runner.calls.get(), 1);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn health_update_cannot_restore_a_revoked_grant() {
        let (grants, _checkpoints) = stores("grant-lock");
        enabled(&grants);
        grants.revoke(now()).unwrap();
        grants.record_health("ok", "fresh", None).unwrap();
        let grant = grants.load().unwrap().unwrap();
        assert_eq!(grant.status, CloudSessionGrantStatus::Revoked);
        assert_eq!(grant.last_collector_health.as_deref(), Some("revoked"));
    }

    #[test]
    fn pagination_is_bounded_and_cursors_are_not_checkpointed() {
        let (grants, checkpoints) = stores("pages");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![
                page("one", Some("cursor-1")),
                page("two", Some("cursor-2")),
                page("three", Some("cursor-3")),
                page("four", None),
            ]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert_eq!(runner.calls.get(), MAX_PAGES);
        assert_eq!(transport.batches.borrow()[0].entities.len(), MAX_PAGES);
        assert!(!String::from_utf8(fs::read(&checkpoints.path).unwrap())
            .unwrap()
            .contains("cursor-"));
    }

    #[test]
    fn transport_failures_open_a_bounded_circuit() {
        let (grants, checkpoints) = stores("circuit");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: true,
        };
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Failed
        );
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::CircuitOpen
        );
        assert_eq!(runner.calls.get(), 1);
    }

    #[test]
    fn deferred_transport_does_not_call_the_provider() {
        let (grants, checkpoints) = stores("deferred");
        enabled(&grants);
        let runner = Pages {
            pages: RefCell::new(vec![page("one", None)]),
            calls: Cell::new(0),
            revoke: None,
        };
        assert_eq!(
            collect_cloud_sessions_once(
                &grants,
                &checkpoints,
                &runner,
                &DeferredCloudSessionTransport,
                now(),
            ),
            CloudSessionCycleOutcome::Noop
        );
        assert_eq!(runner.calls.get(), 0);
    }

    #[test]
    fn deferred_transport_is_explicit_and_disallows_cli_invocation() {
        let (grants, _checkpoints) = stores("deferred-status");
        enabled(&grants);
        let status = cloud_session_collector_status(&grants, &DeferredCloudSessionTransport);
        assert_eq!(status.schema_version, "cloud_session_collector_status.v1");
        assert_eq!(
            status.runtime_state,
            CloudSessionRuntimeState::TransportDeferred
        );
        assert_eq!(status.reason_code, "transport_deferred");
        assert!(!status.transport_configured);
        assert!(!status.provider_cli_invocation_permitted);
    }

    #[test]
    fn sixty_item_fixture_stays_inside_page_and_wall_time_caps() {
        let (grants, checkpoints) = stores("load");
        enabled(&grants);
        let batch_page = |start: u32, cursor: Option<&str>| {
            let tasks = (start..start + PAGE_LIMIT as u32)
                .map(|id| {
                    json!({"id":format!("provider-{id}"),"status":"running","updated_at":"2026-07-21T11:00:00Z"})
                })
                .collect::<Vec<_>>();
            json!({"tasks":tasks,"next_cursor":cursor}).to_string()
        };
        let runner = Pages {
            pages: RefCell::new(vec![
                batch_page(0, Some("cursor-1")),
                batch_page(20, Some("cursor-2")),
                batch_page(40, Some("cursor-3")),
            ]),
            calls: Cell::new(0),
            revoke: None,
        };
        let transport = RecordingTransport {
            calls: Cell::new(0),
            batches: RefCell::new(Vec::new()),
            fail: false,
        };
        let started = Instant::now();
        assert_eq!(
            collect_cloud_sessions_once(&grants, &checkpoints, &runner, &transport, now()),
            CloudSessionCycleOutcome::Uploaded
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(runner.calls.get(), MAX_PAGES);
        assert_eq!(transport.batches.borrow()[0].entities.len(), MAX_ITEMS);
    }
}
