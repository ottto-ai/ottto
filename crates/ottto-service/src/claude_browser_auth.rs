//! Explicit provider-owned Claude browser authentication.
//!
//! This module never constructs an OAuth URL or reads browser state. It
//! privately drains provider output only to detect the explicit authorization
//! code prompt, discards it immediately, and supervises the official CLI with
//! one exact managed root before handing identity/quota verification back to
//! the existing collector.

use crate::locked_state_dir::{open_private_lock_file, FileLock};
use ottto_core::{
    default_support_dir, prepare_managed_claude_provisional_root, write_owner_only_file_atomic,
    ClaudeConfigDirSlot, FileClaudeConfigSlotSettingsStore, CLAUDE_MANAGED_ACCOUNTS_DIR_NAME,
};
use ottto_protocol::{
    ClaudeAccountSetupOperationKind, ClaudeAccountSetupOperationState,
    ClaudeAccountSetupOperationV1, ClaudeAccountsStatusV1, ClaudeBrowserAuthCodeErrorV1,
    ClaudeBrowserAuthIdentityMismatchV1, ClaudeBrowserAuthOperationV1, ClaudeBrowserAuthOutcomeV1,
    ClaudeBrowserAuthPhaseV1, SecretString, CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "claude-browser-auth-state.json";
const STATE_LOCK_FILE: &str = ".claude-browser-auth-state.lock";
const OPERATION_LOCK_PREFIX: &str = ".claude-browser-auth-operation-";
const PROVIDER_PROCESS_LOCK_PREFIX: &str = ".claude-browser-auth-provider-";
const ADMISSION_LOCK_FILE: &str = ".claude-browser-auth-admission.lock";
const STATE_SCHEMA_VERSION: u16 = 1;
const MAX_RETAINED_OPERATIONS: usize = 32;
const MAX_QUARANTINED_ROOTS: usize = 9;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(2);
const TERMINAL_STATUS_RETENTION: u64 = 5 * 60;
const TERM_GRACE: Duration = Duration::from_millis(500);
const SUPERVISOR_READY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUTH_CODE_BYTES: usize = 2_048;
const PROVIDER_EVENT_READY: u8 = 1;
const PROVIDER_EVENT_CODE_PROMPT: u8 = 2;
const PROVIDER_EVENT_CODE_INVALID: u8 = 3;

static STATE_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();
static ADMISSION_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();
static CODE_SUBMISSIONS: OnceLock<
    Mutex<std::collections::BTreeMap<String, mpsc::SyncSender<SecretString>>>,
> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedMode {
    Generic,
    Target,
    Reconnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedOperation {
    operation_id: String,
    slot_id: String,
    #[serde(default)]
    config_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ceremony_baseline: Option<String>,
    mode: PersistedMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_organization_identifier_hash: Option<String>,
    phase: ClaudeBrowserAuthPhaseV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<ClaudeBrowserAuthOutcomeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    canonical_slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission_slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_mismatch: Option<ClaudeBrowserAuthIdentityMismatchV1>,
    #[serde(default)]
    cancel_requested: bool,
    started_unix_seconds: u64,
    deadline_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_unix_seconds: Option<u64>,
    #[serde(default)]
    fallback_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QuarantinedRoot {
    root_id: String,
    #[serde(default)]
    config_dir: String,
    #[serde(default)]
    service_alias: String,
    #[serde(default)]
    pending_registry_removal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claimed_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedState {
    schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invalid_code_operation_id: Option<String>,
    #[serde(default)]
    operations: Vec<PersistedOperation>,
    #[serde(default)]
    quarantined_roots: Vec<QuarantinedRoot>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            active_operation_id: None,
            invalid_code_operation_id: None,
            operations: Vec::new(),
            quarantined_roots: Vec::new(),
        }
    }
}

/// Returns `true` only when this call acquired an idle ceremony. Same-id replay
/// returns `false`; callers must never release a claim they did not acquire.
pub(crate) fn claim_ceremony(operation_id: &str) -> Result<bool, String> {
    let acquired = transact(|state| match state.active_operation_id.as_deref() {
        Some(active) if active != operation_id => Err(format!(
            "another Claude authentication ceremony is active ({active})"
        )),
        Some(_) => Ok(false),
        None => {
            state.active_operation_id = Some(operation_id.to_string());
            Ok(true)
        }
    })
    .map_err(|error| error.to_string())??;
    Ok(acquired)
}

pub(crate) fn release_ceremony(operation_id: &str) {
    let _ = transact(|state| {
        if state.active_operation_id.as_deref() == Some(operation_id) {
            state.active_operation_id = None;
        }
    });
}

struct StateGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    file: File,
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

pub(crate) struct OperationGuard {
    _file: FileLock,
}

/// Lifetime evidence for a provider process that survives daemon restart.
/// The supervisor, not the daemon, holds this lock until its Claude child has
/// exited. Recovery may only release/reuse after it can acquire this lock.
struct ProviderProcessGuard {
    file: File,
    unlock_on_drop: bool,
}

#[cfg(unix)]
impl ProviderProcessGuard {
    fn set_inherited_by_exec(&self, inherited: bool) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = self.file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let updated = if inherited {
            flags & !libc::FD_CLOEXEC
        } else {
            flags | libc::FD_CLOEXEC
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn preserve_inherited_lock_on_drop(&mut self) {
        self.unlock_on_drop = false;
    }
}

impl Drop for ProviderProcessGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.unlock_on_drop {
            unsafe {
                use std::os::fd::AsRawFd;
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

struct SupervisedChild {
    child: Child,
    control: Option<File>,
    code: Option<File>,
    events: Option<File>,
    #[cfg(unix)]
    process_group_id: libc::pid_t,
}

impl SupervisedChild {
    fn submit_code(&mut self, code: &SecretString) -> std::io::Result<()> {
        let writer = self.code.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Claude auth code pipe is unavailable",
            )
        })?;
        writer.write_all(code.expose_secret().as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()
    }

    fn provider_events(&mut self) -> std::io::Result<Vec<u8>> {
        let Some(events) = self.events.as_mut() else {
            return Ok(Vec::new());
        };
        let mut observed = Vec::new();
        let mut buffer = [0_u8; 16];
        loop {
            match events.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => observed.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(observed)
    }
}

impl SupervisedChild {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn cancel_and_wait(&mut self, operation_id: &str) -> bool {
        // EOF is the supervisor's authenticated parent-death/cancel signal.
        self.control.take();
        let deadline = Instant::now() + TERM_GRACE + Duration::from_secs(1);
        while Instant::now() < deadline {
            let supervisor_exited = self.child.try_wait().ok().flatten().is_some();
            if supervisor_exited && !provider_process_active(operation_id).unwrap_or(true) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group_id, libc::SIGTERM);
        }
        #[cfg(not(unix))]
        kill_owned_process(&mut self.child);
        let deadline = Instant::now() + TERM_GRACE;
        while Instant::now() < deadline {
            let _ = self.child.try_wait();
            if !provider_process_active(operation_id).unwrap_or(true) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group_id, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        kill_owned_process(&mut self.child);
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let _ = self.child.try_wait();
            if !provider_process_active(operation_id).unwrap_or(true) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

fn cancel_provider_before_terminal(child: &mut SupervisedChild, operation_id: &str) {
    while !child.cancel_and_wait(operation_id) {
        // An inherited provider lock is authoritative even if the supervisor
        // has already exited or a signal/reap attempt failed. Keep the worker,
        // operation guard, and global ceremony alive until no writer can
        // remain on the exact root.
        thread::sleep(RECOVERY_POLL_INTERVAL);
    }
}

struct AdmissionGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    file: File,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

pub(crate) fn annotate_status(mut status: ClaudeAccountsStatusV1) -> ClaudeAccountsStatusV1 {
    status.browser_auth_supported = Some(true);
    status.auth_code_entry_supported = Some(cfg!(unix));
    let state = read_state();
    let retained = state
        .quarantined_roots
        .iter()
        .filter(|root| root.claimed_by.is_none())
        .count();
    status.retained_provisional_login_count =
        u16::try_from(retained).ok().filter(|count| *count > 0);
    let now = unix_seconds();
    let visible = |operation: &&PersistedOperation| {
        operation.outcome.is_none()
            || matches!(
                operation.completed_unix_seconds,
                Some(completed) if now.saturating_sub(completed) <= TERMINAL_STATUS_RETENTION
            )
    };
    let selected = state
        .operations
        .iter()
        .rev()
        .find(|operation| {
            visible(operation)
                && (operation.outcome.is_none()
                    || (operation.outcome
                        == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                        && !operation.fallback_completed))
        })
        .or_else(|| {
            status
                .setup_operation
                .operation_id
                .as_deref()
                .and_then(|id| {
                    state
                        .operations
                        .iter()
                        .find(|operation| operation.operation_id == id)
                        .filter(visible)
                })
        })
        .or_else(|| state.operations.iter().rev().find(visible));
    if let Some(operation) = selected {
        if status.setup_operation.operation_id.as_deref() != Some(&operation.operation_id) {
            status.setup_operation = synthetic_operation_with_state(operation, &state);
        }
        status.setup_operation.browser_auth = Some(public_operation_with_state(operation, &state));
    }
    status
}

/// Registered target roots remain provisional until their exact expected
/// account+organization proof is admitted. Collection, upkeep, and upload
/// paths use this predicate to keep credentials observed during setup out of
/// canonical account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeCollectionSuppression {
    HideProvisionalTarget,
    PreserveCanonicalReconnect,
    PreserveWhileStateUnavailable,
}

pub(crate) fn collection_suppression(slot_id: &str) -> Option<ClaudeCollectionSuppression> {
    let state = match read_state_strict() {
        Ok(state) => state,
        Err(_) => return Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable),
    };
    let mut operation = state.operations.iter().rev().find(|operation| {
        operation.slot_id == slot_id
            && matches!(
                operation.mode,
                PersistedMode::Target | PersistedMode::Reconnect
            )
    });
    if operation.is_none() {
        if let Some(pending_target) = state.operations.iter().rev().find(|operation| {
            operation.mode == PersistedMode::Target
                && operation.slot_id.is_empty()
                && operation.outcome.is_none()
        }) {
            let store = FileClaudeConfigSlotSettingsStore::default();
            match store.setup_operation_if_exists(&pending_target.operation_id) {
                Ok(Some(status)) if status.setup_operation.slot_id.as_deref() == Some(slot_id) => {
                    operation = Some(pending_target);
                }
                Ok(_) => {}
                Err(_) => {
                    return Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable);
                }
            }
        }
    }
    let operation = operation?;
    let admitted = operation.fallback_completed
        || matches!(
            operation.outcome,
            Some(
                ClaudeBrowserAuthOutcomeV1::Complete | ClaudeBrowserAuthOutcomeV1::AlreadyConnected
            )
        );
    if admitted {
        return None;
    }
    if operation.mode == PersistedMode::Reconnect
        && operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
        && FileClaudeConfigSlotSettingsStore::default()
            .expected_slot_binding(slot_id)
            .is_ok_and(|binding| binding.is_some())
    {
        // The reconnect replaced the slot's Claude login with another
        // account. The approved-binding gate now owns the slot: it reports
        // the mismatch and blocks collection, upload and refresh while the
        // other account stays signed in, and resumes as soon as the approved
        // account signs in again by any path (Terminal or a later reconnect).
        return None;
    }
    Some(match operation.mode {
        PersistedMode::Target => ClaudeCollectionSuppression::HideProvisionalTarget,
        PersistedMode::Reconnect => ClaudeCollectionSuppression::PreserveCanonicalReconnect,
        PersistedMode::Generic => unreachable!("generic operations were filtered above"),
    })
}

pub(crate) fn is_provisional_target_slot(slot_id: &str) -> bool {
    collection_suppression(slot_id) == Some(ClaudeCollectionSuppression::HideProvisionalTarget)
}

/// Persist the v23 collection fence before the core registry can expose or
/// refresh credentials. Target setup may not know its random slot id until the
/// core transaction completes; `collection_suppression` resolves that one
/// placeholder through the same operation id until `start` seals the binding.
pub(crate) fn persist_registry_mutation_fence(
    operation_id: &str,
    mode: BrowserLoginMode,
    slot_id: Option<&str>,
    config_dir: Option<&str>,
    target_id: Option<&str>,
    expected_account_identifier_hash: Option<&str>,
    expected_organization_identifier_hash: Option<&str>,
) -> Result<(), String> {
    if !matches!(mode, BrowserLoginMode::Target | BrowserLoginMode::Reconnect) {
        return Err("only registered Claude browser operations need a registry fence".to_string());
    }
    let now = unix_seconds();
    transact(|state| {
        if state.active_operation_id.as_deref() != Some(operation_id) {
            return Err(
                "Claude browser registry fence does not own the active ceremony".to_string(),
            );
        }
        if let Some(existing) = state
            .operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
        {
            let slot_matches = match slot_id {
                Some(slot) => existing.slot_id.is_empty() || existing.slot_id == slot,
                None => true,
            };
            let config_matches = match config_dir {
                Some(path) => existing.config_dir.is_empty() || existing.config_dir == path,
                None => existing.config_dir.is_empty(),
            };
            if existing.mode != mode.persisted()
                || !slot_matches
                || !config_matches
                || existing.target_id.as_deref() != target_id
                || existing.expected_account_identifier_hash.as_deref()
                    != expected_account_identifier_hash
                || existing.expected_organization_identifier_hash.as_deref()
                    != expected_organization_identifier_hash
                || existing.outcome.is_some()
            {
                return Err("Claude browser registry fence changed its binding".to_string());
            }
            return Ok(());
        }
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.unwrap_or_default().to_string(),
            config_dir: config_dir.unwrap_or_default().to_string(),
            ceremony_baseline: None,
            mode: mode.persisted(),
            target_id: target_id.map(str::to_string),
            expected_account_identifier_hash: expected_account_identifier_hash.map(str::to_string),
            expected_organization_identifier_hash: expected_organization_identifier_hash
                .map(str::to_string),
            phase: ClaudeBrowserAuthPhaseV1::Prepared,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now.saturating_add(LOGIN_TIMEOUT.as_secs()),
            completed_unix_seconds: None,
            fallback_completed: false,
        });
        trim_operations(state);
        Ok(())
    })
    .map_err(|error| error.to_string())??;
    Ok(())
}

pub(crate) fn abort_registry_mutation_fence(operation_id: &str) -> Result<(), String> {
    let removed = transact(|state| {
        let removable = state.operations.iter().position(|operation| {
            operation.operation_id == operation_id
                && operation.phase == ClaudeBrowserAuthPhaseV1::Prepared
                && operation.outcome.is_none()
                && operation.admission_slot_id.is_none()
        });
        let Some(index) = removable else { return false };
        state.operations.remove(index);
        if state.active_operation_id.as_deref() == Some(operation_id) {
            state.active_operation_id = None;
        }
        true
    })
    .map_err(|error| error.to_string())?;
    if removed {
        Ok(())
    } else {
        Err("Claude browser registry fence is no longer safely abortable".to_string())
    }
}

pub(crate) fn terminal_replay(
    mut status: ClaudeAccountsStatusV1,
    operation_id: &str,
) -> Option<ClaudeAccountsStatusV1> {
    let operation = read_operation(operation_id)?;
    operation.outcome?;
    if operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        && !operation.fallback_completed
    {
        spawn_fallback_observer(operation_id);
    }
    status.browser_auth_supported = Some(true);
    status.setup_operation = synthetic_operation(&operation);
    Some(status)
}

#[cfg(test)]
fn public_operation(operation: &PersistedOperation) -> ClaudeBrowserAuthOperationV1 {
    let state = read_state();
    public_operation_with_state(operation, &state)
}

fn public_operation_with_state(
    operation: &PersistedOperation,
    state: &PersistedState,
) -> ClaudeBrowserAuthOperationV1 {
    let effective_outcome = if operation.fallback_completed {
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    } else {
        operation.outcome
    };
    ClaudeBrowserAuthOperationV1 {
        phase: if operation.fallback_completed {
            ClaudeBrowserAuthPhaseV1::Complete
        } else {
            operation.phase
        },
        outcome: effective_outcome,
        retryable: matches!(
            effective_outcome,
            Some(
                ClaudeBrowserAuthOutcomeV1::LoginFailed
                    | ClaudeBrowserAuthOutcomeV1::TimedOut
                    | ClaudeBrowserAuthOutcomeV1::IdentityMismatch
            )
        ),
        retry_requires_new_operation_id: matches!(
            effective_outcome,
            Some(
                ClaudeBrowserAuthOutcomeV1::LoginFailed
                    | ClaudeBrowserAuthOutcomeV1::TimedOut
                    | ClaudeBrowserAuthOutcomeV1::IdentityMismatch
            )
        ),
        terminal_fallback_available: false,
        code_error: (state.invalid_code_operation_id.as_deref()
            == Some(operation.operation_id.as_str()))
        .then_some(ClaudeBrowserAuthCodeErrorV1::InvalidCode),
        identity_mismatch: operation.identity_mismatch,
        canonical_slot_id: operation.canonical_slot_id.clone(),
    }
}

fn synthetic_operation(operation: &PersistedOperation) -> ClaudeAccountSetupOperationV1 {
    let state = read_state();
    synthetic_operation_with_state(operation, &state)
}

fn synthetic_operation_with_state(
    operation: &PersistedOperation,
    persisted_state: &PersistedState,
) -> ClaudeAccountSetupOperationV1 {
    let effective_outcome = if operation.fallback_completed {
        Some(ClaudeBrowserAuthOutcomeV1::Complete)
    } else {
        operation.outcome
    };
    let state = match effective_outcome {
        Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch) => {
            ClaudeAccountSetupOperationState::IdentityMismatch
        }
        Some(ClaudeBrowserAuthOutcomeV1::Cancelled) => {
            ClaudeAccountSetupOperationState::SetupStopped
        }
        Some(
            ClaudeBrowserAuthOutcomeV1::Complete | ClaudeBrowserAuthOutcomeV1::AlreadyConnected,
        ) => ClaudeAccountSetupOperationState::Complete,
        Some(_) => ClaudeAccountSetupOperationState::SetupFailed,
        None => match operation.phase {
            ClaudeBrowserAuthPhaseV1::Prepared
            | ClaudeBrowserAuthPhaseV1::Launching
            | ClaudeBrowserAuthPhaseV1::WaitingForProvider
            | ClaudeBrowserAuthPhaseV1::WaitingForCode
            | ClaudeBrowserAuthPhaseV1::SubmittingCode => {
                ClaudeAccountSetupOperationState::WaitingForUserLogin
            }
            ClaudeBrowserAuthPhaseV1::Validating => ClaudeAccountSetupOperationState::Validating,
            ClaudeBrowserAuthPhaseV1::Reading => ClaudeAccountSetupOperationState::Reading,
            ClaudeBrowserAuthPhaseV1::Complete => ClaudeAccountSetupOperationState::Complete,
        },
    };
    ClaudeAccountSetupOperationV1 {
        kind: if operation.mode == PersistedMode::Reconnect {
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
        } else {
            ClaudeAccountSetupOperationKind::ConnectManagedAccount
        },
        state,
        operation_id: Some(operation.operation_id.clone()),
        slot_id: operation
            .canonical_slot_id
            .clone()
            .or_else(|| Some(operation.slot_id.clone())),
        target_id: operation.target_id.clone(),
        expected_account_identifier_hash: operation.expected_account_identifier_hash.clone(),
        expected_organization_identifier_hash: operation
            .expected_organization_identifier_hash
            .clone(),
        account_identifier_hash: None,
        organization_identifier_hash: None,
        launch_command: None,
        browser_auth: Some(public_operation_with_state(operation, persisted_state)),
        message: operation.cancel_requested.then(|| {
            "Stopping Claude authentication; ordered local cleanup is still in progress."
                .to_string()
        }),
    }
}

fn reusable_root_candidate(
    root: &QuarantinedRoot,
    operation_id: &str,
    strict_replay: bool,
) -> Result<Option<String>, String> {
    let reject = |message: String| {
        if strict_replay {
            Err(message)
        } else {
            Ok(None)
        }
    };
    if root.pending_registry_removal {
        return reject("Claude provisional root is pending registry removal".to_string());
    }
    let config_dir = if root.config_dir.is_empty() {
        managed_root()
            .join(&root.root_id)
            .to_string_lossy()
            .into_owned()
    } else {
        root.config_dir.clone()
    };
    if let Err(error) = ottto_core::validate_managed_claude_auth_root(&config_dir) {
        return reject(error.to_string());
    }
    let service_alias = match ClaudeConfigDirSlot::registered(config_dir.clone()) {
        Ok(slot) => slot.service_name(),
        Err(error) => return reject(error.to_string()),
    };
    if !root.service_alias.is_empty() && root.service_alias != service_alias {
        return reject("Claude provisional root service alias changed".to_string());
    }
    let registry = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(|error| error.to_string())?;
    let registered_slot = registry
        .managed_slots
        .iter()
        .chain(registry.external_slots.iter())
        .find(|slot| slot.config_dir.as_deref() == Some(config_dir.as_str()));
    let exact_same_operation_registration = strict_replay
        && registry.setup_operation.operation_id.as_deref() == Some(operation_id)
        && registered_slot.is_some_and(|slot| {
            registry.setup_operation.slot_id.as_deref() == Some(slot.slot_id.as_str())
        });
    if registered_slot.is_some() && !exact_same_operation_registration {
        return reject("registered Claude root cannot be reused as provisional".to_string());
    }
    Ok(Some(config_dir))
}

pub(crate) fn claim_reusable_root(operation_id: &str) -> Result<Option<String>, String> {
    transact(|state| {
        if let Some(root_index) = state
            .quarantined_roots
            .iter()
            .position(|root| root.claimed_by.as_deref() == Some(operation_id))
        {
            let config_dir =
                reusable_root_candidate(&state.quarantined_roots[root_index], operation_id, true)?
                    .ok_or_else(|| "Claude replay root could not be revalidated".to_string())?;
            return Ok(Some(config_dir));
        }

        for root_index in 0..state.quarantined_roots.len() {
            if state.quarantined_roots[root_index].claimed_by.is_some() {
                continue;
            }
            let Some(config_dir) =
                reusable_root_candidate(&state.quarantined_roots[root_index], operation_id, false)?
            else {
                continue;
            };
            state.quarantined_roots[root_index].claimed_by = Some(operation_id.to_string());
            return Ok(Some(config_dir));
        }
        Ok(None)
    })
    .map_err(|error| error.to_string())?
}

pub(crate) fn release_reusable_root_claim(operation_id: &str) {
    let _ = transact(|state| {
        for root in &mut state.quarantined_roots {
            if root.claimed_by.as_deref() == Some(operation_id) {
                root.claimed_by = None;
            }
        }
    });
}

/// Prepare a generic browser login without adding its root to the canonical
/// account registry. The root becomes visible to collectors only after a
/// strong account+organization proof is admitted by `finalize_identity`.
pub(crate) fn prepare_generic(
    mut status: ClaudeAccountsStatusV1,
    operation_id: &str,
) -> Result<ClaudeAccountsStatusV1, String> {
    read_state_strict().map_err(|error| error.to_string())?;
    let acquired = claim_ceremony(operation_id)?;
    if !acquired {
        for _ in 0..20 {
            if let Some(existing) = read_operation(operation_id) {
                if existing.mode != PersistedMode::Generic {
                    return Err("Claude browser login replay changed its original mode".to_string());
                }
                status.setup_operation = synthetic_operation(&existing);
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(25));
        }
        return Err("Claude browser login is still initializing".to_string());
    }
    let result = prepare_generic_claimed(&mut status, operation_id);
    if result.is_err() && acquired {
        release_ceremony(operation_id);
    }
    result
}

pub(crate) fn preflight_browser_binding(
    operation_id: &str,
    mode: BrowserLoginMode,
    slot_id: Option<&str>,
    target_id: Option<&str>,
) -> Result<(), String> {
    let Some(existing) = read_operation(operation_id) else {
        return Ok(());
    };
    if existing.mode != mode.persisted()
        || slot_id.is_some_and(|slot| existing.slot_id != slot)
        || existing.target_id.as_deref() != target_id
    {
        return Err("Claude browser login replay changed its original binding".to_string());
    }
    Ok(())
}

pub(crate) fn preflight_legacy_binding(
    operation_id: &str,
    target_id: Option<&str>,
) -> Result<(), String> {
    let Some(existing) = read_operation(operation_id) else {
        return Ok(());
    };
    if target_id.is_none()
        || existing.mode != PersistedMode::Target
        || existing.target_id.as_deref() != target_id
    {
        return Err("legacy Claude setup replay conflicts with active browser binding".to_string());
    }
    Ok(())
}

fn prepare_generic_claimed(
    status: &mut ClaudeAccountsStatusV1,
    operation_id: &str,
) -> Result<ClaudeAccountsStatusV1, String> {
    if let Some(existing) = read_operation(operation_id) {
        if existing.mode != PersistedMode::Generic {
            return Err("Claude browser login replay changed its original mode".to_string());
        }
        status.setup_operation = synthetic_operation(&existing);
        return Ok(status.clone());
    }
    let config_dir = match claim_reusable_root(operation_id)? {
        Some(config_dir) => config_dir,
        None => {
            reject_fresh_generic_root_collision(operation_id)?;
            prepare_managed_claude_provisional_root(operation_id)
                .map(|(_, config_dir)| config_dir)
                .map_err(|error| error.to_string())?
        }
    };
    if config_dir.is_empty() {
        release_reusable_root_claim(operation_id);
        return Err("Claude provisional authentication root could not be prepared".to_string());
    }
    ottto_core::validate_managed_claude_auth_root(&config_dir)
        .map_err(|error| error.to_string())?;
    let root_id = Path::new(&config_dir)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Claude provisional authentication root has no opaque id".to_string())?
        .to_string();
    let service_alias = ClaudeConfigDirSlot::registered(config_dir.clone())
        .map_err(|error| error.to_string())?
        .service_name();
    let now = unix_seconds();
    let persist_result = transact(|state| {
        if let Some(existing) = state
            .operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
        {
            return if existing.mode == PersistedMode::Generic {
                Ok(false)
            } else {
                Err("Claude browser operation id is already bound".to_string())
            };
        }
        if let Some(root) = state
            .quarantined_roots
            .iter_mut()
            .find(|root| root.root_id == root_id)
        {
            if (!root.config_dir.is_empty() && root.config_dir != config_dir)
                || (!root.service_alias.is_empty() && root.service_alias != service_alias)
                || matches!(root.claimed_by.as_deref(), Some(claim) if claim != operation_id)
            {
                return Err("Claude provisional quarantine binding changed".to_string());
            }
            root.config_dir = config_dir.clone();
            root.service_alias = service_alias.clone();
            root.pending_registry_removal = false;
            root.claimed_by = Some(operation_id.to_string());
        } else {
            if state.quarantined_roots.len() >= MAX_QUARANTINED_ROOTS {
                return Err(
                    "Claude provisional authentication capacity is full; retry after an existing setup is resolved"
                        .to_string(),
                );
            }
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: root_id.clone(),
                config_dir: config_dir.clone(),
                service_alias: service_alias.clone(),
                pending_registry_removal: false,
                claimed_by: Some(operation_id.to_string()),
            });
        }
        state.operations.push(PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: root_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: None,
            mode: PersistedMode::Generic,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::Prepared,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now.saturating_add(LOGIN_TIMEOUT.as_secs()),
            completed_unix_seconds: None,
            fallback_completed: false,
        });
        trim_operations(state);
        Ok::<bool, String>(true)
    });
    match persist_result.map_err(|error| error.to_string())? {
        Ok(true) => {}
        Ok(false) => {
            status.setup_operation =
                synthetic_operation(&read_operation(operation_id).ok_or_else(|| {
                    "concurrent Claude browser operation disappeared".to_string()
                })?);
            return Ok(status.clone());
        }
        Err(error) => {
            release_reusable_root_claim(operation_id);
            // A freshly-created root is still empty before launch. Remove it
            // only if it never entered the durable quarantine journal.
            if !read_state()
                .quarantined_roots
                .iter()
                .any(|root| root.root_id == root_id && root.config_dir == config_dir)
            {
                let _ = fs::remove_dir(&config_dir);
            }
            return Err(error);
        }
    }
    status.setup_operation = synthetic_operation(
        &read_operation(operation_id).ok_or_else(|| "browser operation disappeared".to_string())?,
    );
    Ok(status.clone())
}

fn reject_fresh_generic_root_collision(operation_id: &str) -> Result<(), String> {
    let suffix = operation_id
        .strip_prefix("claude_setup_")
        .ok_or_else(|| "Claude browser operation id has an unsupported shape".to_string())?;
    let root_id = format!("claude_slot_{suffix}");
    let config_dir = managed_root().join(&root_id).to_string_lossy().into_owned();
    let registry = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(|error| error.to_string())?;
    if registry
        .managed_slots
        .iter()
        .chain(registry.external_slots.iter())
        .any(|slot| slot.slot_id == root_id || slot.config_dir.as_deref() == Some(&config_dir))
    {
        return Err("Claude provisional root collides with a canonical registration".to_string());
    }
    if Path::new(&config_dir).exists() {
        return Err("existing Claude root has no exact reusable quarantine ownership".to_string());
    }
    Ok(())
}

/// Exact daemon-owned provisional/retained roots also participate in explicit
/// telemetry opt-out. The settings owner revalidates every path without links.
pub(crate) fn managed_telemetry_roots() -> Vec<String> {
    let state = read_state();
    let mut roots: Vec<_> = state
        .operations
        .into_iter()
        .filter_map(|operation| (!operation.config_dir.is_empty()).then_some(operation.config_dir))
        .collect();
    roots.extend(state.quarantined_roots.into_iter().map(|root| {
        if root.config_dir.is_empty() {
            managed_root()
                .join(root.root_id)
                .to_string_lossy()
                .into_owned()
        } else {
            root.config_dir
        }
    }));
    let parent = managed_root();
    roots.retain(|root| Path::new(root).parent() == Some(parent.as_path()));
    roots.sort();
    roots.dedup();
    roots
}

pub(crate) fn active_provisional_telemetry_root(config_dir: &str) -> bool {
    let state = read_state();
    state.operations.iter().any(|operation| {
        state.active_operation_id.as_deref() == Some(&operation.operation_id)
            && operation.mode == PersistedMode::Generic
            && operation.outcome.is_none()
            && operation.config_dir == config_dir
    })
}

pub(crate) fn start(
    status: ClaudeAccountsStatusV1,
    mode: BrowserLoginMode,
) -> Result<ClaudeAccountsStatusV1, String> {
    let operation_id = status.setup_operation.operation_id.clone();
    let slot_id = status.setup_operation.slot_id.clone();
    let target_id = status.setup_operation.target_id.clone();
    let expected_account_identifier_hash = status
        .setup_operation
        .expected_account_identifier_hash
        .clone();
    let expected_organization_identifier_hash = status
        .setup_operation
        .expected_organization_identifier_hash
        .clone();
    let result = start_inner(status, mode);
    if result.is_err() {
        if let Some(operation_id) = operation_id {
            let owned = read_operation(&operation_id).is_some_and(|operation| {
                operation.outcome.is_none()
                    && operation.mode == mode.persisted()
                    && slot_id.as_deref().is_some_and(|slot| {
                        operation.slot_id.is_empty() || operation.slot_id == slot
                    })
                    && operation.target_id == target_id
                    && operation.expected_account_identifier_hash
                        == expected_account_identifier_hash
                    && operation.expected_organization_identifier_hash
                        == expected_organization_identifier_hash
            });
            if owned && !fail_operation(&operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed) {
                resume_operation_recovery(&operation_id);
            }
        }
    }
    result
}

fn start_inner(
    status: ClaudeAccountsStatusV1,
    mode: BrowserLoginMode,
) -> Result<ClaudeAccountsStatusV1, String> {
    let operation_id = status
        .setup_operation
        .operation_id
        .clone()
        .ok_or_else(|| "Claude browser login has no operation id".to_string())?;
    let slot_id = status
        .setup_operation
        .slot_id
        .clone()
        .ok_or_else(|| "Claude browser login has no slot id".to_string())?;
    let config_dir = if mode == BrowserLoginMode::Generic {
        read_operation(&operation_id)
            .map(|operation| operation.config_dir)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| "Claude provisional authentication root disappeared".to_string())?
    } else {
        status
            .managed_slots
            .iter()
            .chain(status.external_slots.iter())
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .ok_or_else(|| "Claude browser login root disappeared".to_string())?
    };
    if mode != BrowserLoginMode::Generic {
        transact(|state| {
            if let Some(existing) = state
                .operations
                .iter_mut()
                .find(|candidate| candidate.operation_id == operation_id)
            {
                if existing.slot_id.is_empty()
                    && existing.mode == mode.persisted()
                    && existing.phase == ClaudeBrowserAuthPhaseV1::Prepared
                    && existing.outcome.is_none()
                {
                    if !existing.config_dir.is_empty() && existing.config_dir != config_dir {
                        return Err(
                            "Claude browser registry fence changed its exact root".to_string()
                        );
                    }
                    existing.slot_id = slot_id.clone();
                    existing.config_dir = config_dir.clone();
                }
            }
            Ok(())
        })
        .map_err(|error| error.to_string())??;
    }
    let now = unix_seconds();
    let ceremony_baseline = crate::agent_status::claude_auth_ceremony_witness(&config_dir)
        .map_err(|_| "Claude authentication baseline could not be captured".to_string())?;
    let should_spawn = transact(|state| {
        if let Some(existing) = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
        {
            if existing.slot_id.is_empty()
                && existing.mode == mode.persisted()
                && existing.phase == ClaudeBrowserAuthPhaseV1::Prepared
                && existing.outcome.is_none()
            {
                if !existing.config_dir.is_empty() && existing.config_dir != config_dir {
                    return Err("Claude browser registry fence changed its exact root".to_string());
                }
                existing.slot_id = slot_id.clone();
                existing.config_dir = config_dir.clone();
            }
            if existing.slot_id != slot_id || existing.mode != mode.persisted() {
                return Err("Claude browser login replay changed its original binding".to_string());
            }
            if existing.target_id != status.setup_operation.target_id
                || existing.expected_account_identifier_hash
                    != status.setup_operation.expected_account_identifier_hash
                || existing.expected_organization_identifier_hash
                    != status.setup_operation.expected_organization_identifier_hash
            {
                return Err("Claude browser login replay changed its expected binding".to_string());
            }
            if existing.outcome.is_none() && existing.phase != ClaudeBrowserAuthPhaseV1::Prepared {
                return Ok(false);
            }
            if existing.outcome.is_some() {
                return Ok(false);
            }
            if existing.mode == PersistedMode::Generic {
                if let Some(root) = state
                    .quarantined_roots
                    .iter_mut()
                    .find(|root| root.root_id == existing.slot_id)
                {
                    if matches!(root.claimed_by.as_deref(), Some(claim) if claim != operation_id) {
                        return Err(
                            "Claude provisional authentication root is already in use".to_string()
                        );
                    }
                    root.claimed_by = Some(operation_id.clone());
                }
            }
            existing.phase = ClaudeBrowserAuthPhaseV1::Launching;
            existing.ceremony_baseline = Some(ceremony_baseline.clone());
            existing.outcome = None;
            existing.identity_mismatch = None;
            existing.cancel_requested = false;
            existing.started_unix_seconds = now;
            existing.deadline_unix_seconds = now.saturating_add(LOGIN_TIMEOUT.as_secs());
            existing.completed_unix_seconds = None;
            return Ok(true);
        }
        state.operations.push(PersistedOperation {
            operation_id: operation_id.clone(),
            slot_id: slot_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: Some(ceremony_baseline),
            mode: mode.persisted(),
            target_id: status.setup_operation.target_id.clone(),
            expected_account_identifier_hash: status
                .setup_operation
                .expected_account_identifier_hash
                .clone(),
            expected_organization_identifier_hash: status
                .setup_operation
                .expected_organization_identifier_hash
                .clone(),
            phase: ClaudeBrowserAuthPhaseV1::Launching,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now.saturating_add(LOGIN_TIMEOUT.as_secs()),
            completed_unix_seconds: None,
            fallback_completed: false,
        });
        trim_operations(state);
        Ok::<bool, String>(true)
    })
    .map_err(|error| error.to_string())??;

    if !should_spawn {
        return Ok(annotate_status(status));
    }

    // Generic browser roots are provisional until provider-owned admission,
    // so they do not appear in the registry repair pass yet. Extend only the
    // already approved local relay settings before the login child starts.
    if mode == BrowserLoginMode::Generic
        || status.managed_slots.iter().any(|slot| {
            slot.slot_id == slot_id
                && slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
        })
    {
        if let Err(error) = crate::control::provision_managed_claude_relay_settings(&config_dir) {
            eprintln!("managed Claude settings repair skipped: {error}");
        }
    }

    if mode == BrowserLoginMode::Target {
        let operation = read_operation(&operation_id)
            .ok_or_else(|| "Claude browser operation disappeared before launch".to_string())?;
        if let Err(error) = reserve_quarantine_root(&operation, false) {
            let _ = transition_registry_terminal_with_message(
                &operation,
                ClaudeBrowserAuthOutcomeV1::LoginFailed,
                "Claude browser authentication could not start because retained provisional-login capacity is full.",
            );
            finish(&operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed, None);
            return Err(format!(
                "retained provisional-login capacity is full: {error}"
            ));
        }
    }

    let operation_for_thread = operation_id.clone();
    if thread::Builder::new()
        .name("ottto-claude-browser-auth".to_string())
        .spawn(move || run_worker(&operation_for_thread))
        .is_err()
    {
        fail_operation(&operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
    }
    Ok(annotate_status(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrowserLoginMode {
    Generic,
    Target,
    Reconnect,
}

struct CodeSubmissionRegistration {
    operation_id: String,
}

impl Drop for CodeSubmissionRegistration {
    fn drop(&mut self) {
        if let Ok(mut submissions) = CODE_SUBMISSIONS
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
        {
            submissions.remove(&self.operation_id);
        }
    }
}

fn register_code_submissions(
    operation_id: &str,
) -> Result<(CodeSubmissionRegistration, mpsc::Receiver<SecretString>), String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let mut submissions = CODE_SUBMISSIONS
        .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
        .lock()
        .map_err(|_| "Claude auth code channel is unavailable".to_string())?;
    if submissions.contains_key(operation_id) {
        return Err("Claude auth code channel is already registered".to_string());
    }
    submissions.insert(operation_id.to_string(), sender);
    Ok((
        CodeSubmissionRegistration {
            operation_id: operation_id.to_string(),
        },
        receiver,
    ))
}

pub(crate) fn submit_authorization_code(
    operation_id: &str,
    code: SecretString,
) -> Result<(), String> {
    validate_authorization_code(&code)?;
    let sender = CODE_SUBMISSIONS
        .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
        .lock()
        .map_err(|_| "Claude auth code channel is unavailable".to_string())?
        .get(operation_id)
        .cloned()
        .ok_or_else(|| "Claude authorization code is not currently requested".to_string())?;
    transact(|state| {
        if state.active_operation_id.as_deref() != Some(operation_id) {
            return Err(
                "Claude authorization code does not match the active operation".to_string(),
            );
        }
        let operation = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .ok_or_else(|| "Claude authorization operation is unknown".to_string())?;
        if operation.outcome.is_some()
            || operation.cancel_requested
            || operation.phase != ClaudeBrowserAuthPhaseV1::WaitingForCode
        {
            return Err("Claude authorization code is not currently requested".to_string());
        }
        operation.phase = ClaudeBrowserAuthPhaseV1::SubmittingCode;
        if state.invalid_code_operation_id.as_deref() == Some(operation_id) {
            state.invalid_code_operation_id = None;
        }
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;
    if sender.try_send(code).is_err() {
        let _ = transact(|state| {
            if let Some(operation) = state.operations.iter_mut().find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.phase == ClaudeBrowserAuthPhaseV1::SubmittingCode
                    && candidate.outcome.is_none()
            }) {
                operation.phase = ClaudeBrowserAuthPhaseV1::WaitingForCode;
            }
        });
        return Err("Claude auth code channel closed before submission".to_string());
    }
    Ok(())
}

fn validate_authorization_code(code: &SecretString) -> Result<(), String> {
    let value = code.expose_secret();
    if value.is_empty() || value.len() > MAX_AUTH_CODE_BYTES {
        return Err("Claude authorization code must be 1-2048 bytes".to_string());
    }
    if value
        .chars()
        .any(|character| character == '\r' || character == '\n' || character.is_control())
    {
        return Err("Claude authorization code must be a single printable line".to_string());
    }
    if value.trim() != value {
        return Err("Claude authorization code must not have surrounding whitespace".to_string());
    }
    Ok(())
}

fn apply_provider_event(operation_id: &str, event: u8) {
    let _ = transact(|state| {
        let Some(operation) = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
        else {
            return;
        };
        if operation.outcome.is_some() || operation.cancel_requested {
            return;
        }
        match (event, operation.phase) {
            (PROVIDER_EVENT_CODE_PROMPT, ClaudeBrowserAuthPhaseV1::WaitingForProvider) => {
                operation.phase = ClaudeBrowserAuthPhaseV1::WaitingForCode;
                state.invalid_code_operation_id = None;
            }
            (PROVIDER_EVENT_CODE_PROMPT, ClaudeBrowserAuthPhaseV1::SubmittingCode)
            | (PROVIDER_EVENT_CODE_INVALID, ClaudeBrowserAuthPhaseV1::SubmittingCode) => {
                operation.phase = ClaudeBrowserAuthPhaseV1::WaitingForCode;
                state.invalid_code_operation_id = Some(operation_id.to_string());
            }
            _ => {}
        }
    });
}

impl BrowserLoginMode {
    fn persisted(self) -> PersistedMode {
        match self {
            Self::Generic => PersistedMode::Generic,
            Self::Target => PersistedMode::Target,
            Self::Reconnect => PersistedMode::Reconnect,
        }
    }
}

fn run_worker(operation_id: &str) {
    let Ok(Some(_guard)) = operation_guard(operation_id) else {
        return;
    };
    // A terminal cancel intentionally retains the global ceremony claim while
    // this daemon still owns a provider process. Releasing from this guard is
    // therefore required even when `finish` observes an existing terminal CAS.
    let _ceremony = WorkerCeremonyGuard { operation_id };
    let Some(operation) = read_operation(operation_id) else {
        return;
    };
    let config_dir = operation_config_dir(&operation);
    let Ok(pinned_root) = pin_managed_root(&config_dir) else {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    };
    if login_command(&config_dir).is_none() {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    }
    let Ok(mut child) = spawn_supervised_login(operation_id, &config_dir) else {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    };
    let mut sign_in_call = SignInCall::started(&config_dir);
    let Ok((_submission_registration, submissions)) = register_code_submissions(operation_id)
    else {
        cancel_provider_before_terminal(&mut child, operation_id);
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    };
    if !pinned_root.path_matches(&config_dir) {
        cancel_provider_before_terminal(&mut child, operation_id);
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    }
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
    let start = Instant::now();
    let _process_success = loop {
        match child.provider_events() {
            Ok(events) => {
                for event in events {
                    apply_provider_event(operation_id, event);
                }
            }
            Err(_) => {
                cancel_provider_before_terminal(&mut child, operation_id);
                fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
                return;
            }
        }
        loop {
            match submissions.try_recv() {
                Ok(code) => {
                    if child.submit_code(&code).is_err() {
                        cancel_provider_before_terminal(&mut child, operation_id);
                        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
                        return;
                    }
                    sign_in_call.code_submitted = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if !pinned_root.path_matches(&config_dir) {
            cancel_provider_before_terminal(&mut child, operation_id);
            fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
            return;
        }
        if cancel_requested(operation_id) {
            sign_in_call.finish(crate::provider_calls::CallResult::Error("cancelled"));
            cancel_provider_before_terminal(&mut child, operation_id);
            fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled);
            return;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                sign_in_call.finish(crate::provider_calls::exit_result(Some(status), false));
                if !status.success() {
                    cancel_provider_before_terminal(&mut child, operation_id);
                }
                break status.success();
            }
            Ok(None) if start.elapsed() >= LOGIN_TIMEOUT => {
                sign_in_call.finish(crate::provider_calls::CallResult::Timeout);
                cancel_provider_before_terminal(&mut child, operation_id);
                fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::TimedOut);
                return;
            }
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(_) => {
                cancel_provider_before_terminal(&mut child, operation_id);
                fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
                return;
            }
        }
    };
    if cancel_requested(operation_id) {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled);
        return;
    }
    if !pinned_root.path_matches(&config_dir) || !ceremony_witness_changed(&operation, &config_dir)
    {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    }
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Validating);
    let proof = crate::agent_status::verify_claude_local_identity(
        &operation.slot_id,
        &config_dir,
        &observed_at(),
    );
    let Ok(proof) = proof else {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    };
    if cancel_requested(operation_id) {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled);
        return;
    }
    if !pinned_root.path_matches(&config_dir) {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    }
    if finalize_identity(operation_id, proof).is_err()
        && read_operation(operation_id)
            .and_then(|operation| operation.admission_slot_id)
            .is_none()
    {
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
    }
}

/// The provider-call log line of one `claude auth login` run: written when
/// the run ends, or when the worker gives up on it. A run that completed or
/// was given a code sent at least the token exchange, whatever its result; one
/// that never got a code may have sent none.
struct SignInCall<'a> {
    config_dir: &'a str,
    started: Instant,
    pending: bool,
    code_submitted: bool,
}

impl<'a> SignInCall<'a> {
    fn started(config_dir: &'a str) -> Self {
        Self {
            config_dir,
            started: Instant::now(),
            pending: true,
            code_submitted: false,
        }
    }

    fn finish(&mut self, result: crate::provider_calls::CallResult) {
        use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
        if !std::mem::take(&mut self.pending) {
            return;
        }
        let account = ottto_core::claude_cli_account_identifier_hash_at(
            &Path::new(self.config_dir).join(".claude.json"),
        );
        crate::provider_calls::record(ProviderCall::subprocess(
            Provider::Anthropic,
            CallKind::ClaudeSignIn,
            Trigger::Setup,
            (!account.is_empty()).then_some(account.as_str()),
            result,
            self.started.elapsed(),
            u32::from(self.code_submitted || result == CallResult::Ok),
        ));
    }
}

impl Drop for SignInCall<'_> {
    fn drop(&mut self) {
        self.finish(crate::provider_calls::CallResult::Error("abandoned"));
    }
}

struct WorkerCeremonyGuard<'a> {
    operation_id: &'a str,
}

impl Drop for WorkerCeremonyGuard<'_> {
    fn drop(&mut self) {
        let releasable_terminal = read_state_strict().ok().is_some_and(|state| {
            state.operations.iter().any(|operation| {
                operation.operation_id == self.operation_id
                    && operation.outcome.is_some()
                    && (operation.outcome
                        != Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                        || operation.fallback_completed)
                    && !state
                        .quarantined_roots
                        .iter()
                        .any(|root| root.claimed_by.as_deref() == Some(self.operation_id))
            })
        });
        let hold_for_provider = provider_process_active(self.operation_id).unwrap_or(true);
        if releasable_terminal && !hold_for_provider {
            release_ceremony(self.operation_id);
        } else if !releasable_terminal && !hold_for_provider {
            let operation_id = self.operation_id.to_string();
            let _ = thread::Builder::new()
                .name("ottto-claude-browser-auth-recovery".to_string())
                .spawn(move || recover_operation(&operation_id));
        }
    }
}

fn operation_config_dir(operation: &PersistedOperation) -> String {
    if operation.config_dir.is_empty() {
        managed_root()
            .join(&operation.slot_id)
            .to_string_lossy()
            .into_owned()
    } else {
        operation.config_dir.clone()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RootIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct PinnedRoot {
    _support: File,
    _parent: File,
    _child: File,
    support_identity: RootIdentity,
    parent_identity: RootIdentity,
    child_identity: RootIdentity,
}

impl PinnedRoot {
    fn path_matches(&self, config_dir: &str) -> bool {
        let support_matches = Path::new(config_dir)
            .parent()
            .and_then(Path::parent)
            .and_then(|support| root_identity(support).ok())
            .is_some_and(|observed| observed == self.support_identity);
        let child_matches =
            root_identity(config_dir).is_ok_and(|observed| observed == self.child_identity);
        let parent_matches = Path::new(config_dir)
            .parent()
            .and_then(|parent| root_identity(parent).ok())
            .is_some_and(|observed| observed == self.parent_identity);
        support_matches && child_matches && parent_matches
    }
}

fn pin_managed_root(config_dir: &str) -> std::io::Result<PinnedRoot> {
    ottto_core::validate_managed_claude_auth_root(config_dir).map_err(std::io::Error::other)?;
    let path = Path::new(config_dir);
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed root has no parent",
        )
    })?;
    let support = parent.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed root parent has no support root",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "managed root has no name")
    })?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        let support_file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(support)?;
        let parent_file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "managed root contains NUL",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent_file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat returns one newly-owned descriptor.
        let child_file = unsafe { File::from_raw_fd(fd) };
        let support_identity = root_identity_from_file(&support_file)?;
        let parent_identity = root_identity_from_file(&parent_file)?;
        let child_identity = root_identity_from_file(&child_file)?;
        let pinned = PinnedRoot {
            _support: support_file,
            _parent: parent_file,
            _child: child_file,
            support_identity,
            parent_identity,
            child_identity,
        };
        if !pinned.path_matches(config_dir) {
            return Err(std::io::Error::other(
                "managed root changed while descriptors were pinned",
            ));
        }
        Ok(pinned)
    }
    #[cfg(not(unix))]
    {
        let support_file = File::open(support)?;
        let parent_file = File::open(parent)?;
        let child_file = File::open(path)?;
        Ok(PinnedRoot {
            support_identity: root_identity(support)?,
            parent_identity: root_identity(parent)?,
            child_identity: root_identity(path)?,
            _support: support_file,
            _parent: parent_file,
            _child: child_file,
        })
    }
}

fn root_identity_from_file(file: &File) -> std::io::Result<RootIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pinned Claude authentication root is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    Ok(RootIdentity {})
}

fn root_identity(config_dir: impl AsRef<Path>) -> std::io::Result<RootIdentity> {
    let metadata = fs::symlink_metadata(config_dir)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Claude authentication root is not a direct directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    Ok(RootIdentity {})
}

fn ceremony_witness_changed(operation: &PersistedOperation, config_dir: &str) -> bool {
    let Some(baseline) = operation.ceremony_baseline.as_deref() else {
        return false;
    };
    crate::agent_status::claude_auth_ceremony_witness(config_dir)
        .is_ok_and(|observed| observed != baseline)
}

fn finalize_identity(
    operation_id: &str,
    proof: crate::agent_status::ClaudeLocalIdentityProof,
) -> Result<(), String> {
    finalize_identity_mode(operation_id, proof, false)
}

fn finalize_identity_mode(
    operation_id: &str,
    proof: crate::agent_status::ClaudeLocalIdentityProof,
    allow_terminal_fallback: bool,
) -> Result<(), String> {
    let operation =
        read_operation(operation_id).ok_or_else(|| "browser operation disappeared".to_string())?;
    if operation.cancel_requested
        || (operation.outcome.is_some()
            && !(allow_terminal_fallback
                && operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)))
    {
        return Ok(());
    }
    let _admission = admission_guard().map_err(|error| error.to_string())?;
    if read_operation(operation_id).map_or(true, |current| {
        current.cancel_requested
            || (current.outcome.is_some()
                && !(allow_terminal_fallback
                    && current.outcome
                        == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)))
    }) {
        return Ok(());
    }
    let store = FileClaudeConfigSlotSettingsStore::default();
    let mut registry_operation = if operation.mode == PersistedMode::Generic {
        None
    } else {
        Some(
            store
                .setup_operation(operation_id)
                .map_err(|error| error.to_string())?
                .setup_operation,
        )
    };
    let mut mismatch = registry_operation.as_ref().and_then(|expected| {
        identity_mismatch(
            expected.expected_account_identifier_hash.as_deref(),
            expected.expected_organization_identifier_hash.as_deref(),
            &proof.account_identifier_hash,
            &proof.organization_identifier_hash,
        )
    });
    if mismatch.is_some() && operation.mode == PersistedMode::Reconnect {
        // A slot approved only from an observed login (trust on first use)
        // takes the account a completed reconnect proves: signing in through
        // a reconnect is the user's explicit choice. Verified approvals keep
        // refusing another account.
        if let Some(proven) = ottto_core::ClaudeSlotAccountBinding::new(
            &proof.account_identifier_hash,
            &proof.organization_identifier_hash,
        ) {
            if store
                .adopt_reconnect_identity_for_observed_approval(
                    CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    operation_id,
                    &proven,
                )
                .map_err(|error| error.to_string())?
            {
                transact(|state| {
                    if let Some(sidecar) = state
                        .operations
                        .iter_mut()
                        .find(|candidate| candidate.operation_id == operation_id)
                    {
                        sidecar.expected_account_identifier_hash =
                            Some(proven.account_identifier_hash.clone());
                        sidecar.expected_organization_identifier_hash =
                            Some(proven.organization_identifier_hash.clone());
                    }
                })
                .map_err(|error| error.to_string())?;
                registry_operation = Some(
                    store
                        .setup_operation(operation_id)
                        .map_err(|error| error.to_string())?
                        .setup_operation,
                );
                mismatch = None;
            }
        }
    }
    if let Some(mismatch) = mismatch {
        finish_mismatch(operation_id, mismatch, allow_terminal_fallback)?;
        return Ok(());
    }
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Reading);

    if operation.mode == PersistedMode::Generic {
        if read_operation(operation_id).map_or(true, |current| {
            current.cancel_requested
                || (current.outcome.is_some()
                    && !(allow_terminal_fallback
                        && current.outcome
                            == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)))
        }) {
            return Ok(());
        }
        let status = crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(|error| error.to_string())?,
        );
        if let Some(canonical) = status
            .managed_slots
            .iter()
            .chain(status.external_slots.iter())
            .find(|slot| {
                slot.config_dir.as_deref() == Some(operation_config_dir(&operation).as_str())
            })
            .map(|slot| slot.slot_id.clone())
        {
            persist_identity(&canonical, &proof.collection)?;
            collect_allowed_quota(&store, &canonical);
            consume_reusable_root_claim(operation_id)?;
            complete_identity_operation(
                operation_id,
                ClaudeBrowserAuthOutcomeV1::Complete,
                Some(canonical),
                allow_terminal_fallback,
            )?;
            spawn_status_refresh("browser_auth_complete");
            return Ok(());
        }
        if let Some(canonical) = serving_slot_for_binding(
            &status,
            &operation.slot_id,
            &proof.account_identifier_hash,
            &proof.organization_identifier_hash,
        ) {
            quarantine_generic_root(&operation)?;
            complete_identity_operation(
                operation_id,
                ClaudeBrowserAuthOutcomeV1::AlreadyConnected,
                Some(canonical),
                allow_terminal_fallback,
            )?;
            spawn_status_refresh("browser_auth_duplicate");
            return Ok(());
        }
        // Journal and persist strong composite identity while the provisional
        // root is still absent from the registry. Scheduled collectors can
        // only enumerate it after the exact-id registry transaction below.
        let canonical = operation.slot_id.clone();
        set_admission_slot(operation_id, &canonical, allow_terminal_fallback)?;
        if let Err(error) = persist_identity(&canonical, &proof.collection) {
            clear_admission_slot(operation_id);
            return Err(error);
        }
        if read_operation(operation_id).map_or(true, |current| {
            current.cancel_requested
                || (current.outcome.is_some()
                    && !(allow_terminal_fallback
                        && current.outcome
                            == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)))
        }) {
            let _ = crate::agent_status::prune_claude_slot_collection_state(&canonical);
            clear_admission_slot(operation_id);
            return Ok(());
        }
        if let Err(error) = store.register_managed_path_with_slot_id_and_binding(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            canonical.clone(),
            operation_config_dir(&operation),
            ottto_core::ClaudeSlotAccountBinding::new(
                &proof.account_identifier_hash,
                &proof.organization_identifier_hash,
            ),
        ) {
            let _ = crate::agent_status::prune_claude_slot_collection_state(&canonical);
            clear_admission_slot(operation_id);
            return Err(error.to_string());
        }
        collect_allowed_quota(&store, &canonical);
        if let Err(error) = consume_reusable_root_claim(operation_id) {
            crate::control::remove_claude_registration_with_relay_cleanup(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                &canonical,
            )
            .map_err(|error| error.to_string())?;
            let _ = crate::agent_status::prune_claude_slot_collection_state(&canonical);
            clear_admission_slot(operation_id);
            return Err(error);
        }
        complete_identity_operation(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::Complete,
            Some(canonical),
            allow_terminal_fallback,
        )?;
    } else {
        let status = crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(|error| error.to_string())?,
        );
        if operation.mode == PersistedMode::Target {
            if let Some(canonical) = serving_slot_for_binding(
                &status,
                &operation.slot_id,
                &proof.account_identifier_hash,
                &proof.organization_identifier_hash,
            ) {
                reserve_quarantine_root(&operation, true)?;
                crate::control::remove_claude_registration_with_relay_cleanup(
                    CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    &operation.slot_id,
                )
                .map_err(|error| error.to_string())?;
                let _ = crate::agent_status::prune_claude_slot_collection_state(&operation.slot_id);
                let _ = crate::claude_upkeep::prune_slot_upkeep_state(&operation.slot_id);
                make_quarantine_reusable(&operation)?;
                complete_identity_operation(
                    operation_id,
                    ClaudeBrowserAuthOutcomeV1::AlreadyConnected,
                    Some(canonical),
                    allow_terminal_fallback,
                )?;
                return Ok(());
            }
        }
        if operation.mode == PersistedMode::Target {
            persist_identity(&operation.slot_id, &proof.collection)?;
            consume_reusable_root_claim(operation_id)?;
        }
        let expected = registry_operation.expect("registered modes have setup operations");
        if let Err(error) = store.transition_setup_operation_with_binding(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            operation_id,
            expected.expected_account_identifier_hash.as_deref(),
            expected.expected_organization_identifier_hash.as_deref(),
            ClaudeAccountSetupOperationState::Complete,
            Some(&proof.account_identifier_hash),
            Some(&proof.organization_identifier_hash),
            Some("Claude identity is verified; quota refresh continues in the background."),
        ) {
            if operation.mode == PersistedMode::Target {
                let _ = reserve_quarantine_root(&operation, false);
            }
            return Err(error.to_string());
        }
        // Reconnect deliberately retains the previous canonical collection
        // evidence. The exact expected binding is recorded by the terminal
        // core operation above; quota refresh after sidecar completion may
        // replace limits without exposing any in-progress credential state.
        complete_identity_operation(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::Complete,
            None,
            allow_terminal_fallback,
        )?;
        collect_allowed_quota(&store, &operation.slot_id);
    }
    spawn_status_refresh("browser_auth_complete");
    Ok(())
}

fn spawn_status_refresh(reason: &'static str) {
    #[cfg(not(test))]
    crate::snapshot_sync::spawn_claude_agent_status_refresh(reason);
    #[cfg(test)]
    let _ = reason;
}

fn persist_identity(
    slot_id: &str,
    identity: &ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
) -> Result<(), String> {
    crate::agent_status::persist_one_claude_slot_collection_state(slot_id, identity)
        .map_err(|error| error.to_string())
}

pub(crate) fn collect_allowed_quota(store: &FileClaudeConfigSlotSettingsStore, slot_id: &str) {
    let Ok(status) = store.load() else { return };
    if status.consent != ottto_protocol::ClaudeAccountUpkeepConsentState::Granted {
        return;
    }
    let captured_at = observed_at();
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::minutes(15))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| captured_at.clone());
    let quota = crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, || {
        crate::agent_status::request_claude_explicit_refresh();
        crate::agent_status::collect_registered_claude_slot_status(slot_id, captured_at, expires_at)
    });
    // Identity admission is durable independently of quota availability.
    // The collector itself returns typed unavailable/paused state; a local
    // persistence failure must not discard a valid provider connection.
    let _ = crate::agent_status::persist_one_claude_slot_collection_state(slot_id, &quota);
}

fn set_admission_slot(
    operation_id: &str,
    slot_id: &str,
    allow_terminal_fallback: bool,
) -> Result<(), String> {
    transact(|state| {
        let operation = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
            .ok_or_else(|| "browser operation disappeared".to_string())?;
        if operation.outcome.is_some()
            && !(allow_terminal_fallback
                && operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired))
        {
            return Err("browser operation is already terminal".to_string());
        }
        operation.admission_slot_id = Some(slot_id.to_string());
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;
    Ok(())
}

fn clear_admission_slot(operation_id: &str) {
    let _ = transact(|state| {
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            operation.admission_slot_id = None;
        }
    });
}

fn identity_mismatch(
    expected_account: Option<&str>,
    expected_organization: Option<&str>,
    observed_account: &str,
    observed_organization: &str,
) -> Option<ClaudeBrowserAuthIdentityMismatchV1> {
    match (
        matches!(expected_account, Some(value) if value != observed_account),
        matches!(expected_organization, Some(value) if value != observed_organization),
    ) {
        (true, true) => Some(ClaudeBrowserAuthIdentityMismatchV1::AccountAndOrganization),
        (true, false) => Some(ClaudeBrowserAuthIdentityMismatchV1::Account),
        (false, true) => Some(ClaudeBrowserAuthIdentityMismatchV1::Organization),
        (false, false) => None,
    }
}

/// The registered slot whose saved connection already serves this exact
/// account/organization pair, making a fresh login for that pair redundant.
///
/// A matching slot whose saved credential is not usable (signed out, expired
/// with a pending or failed refresh, unreadable, or without a proven identity,
/// as decided by `agent_status::claude_slot_connection_usable`, the same rule
/// canonical selection uses) does not serve the pair. Treating it as "already connected"
/// quarantined the only working login and left the account on a dead
/// connection the user could not repair. Such a login is admitted through the
/// normal registration path instead; canonical selection then prefers the
/// working slot and the dead one is presented as a removable duplicate.
/// Duplicate-labelled slots never serve on their own: canonical selection has
/// already preferred the best slot for the pair.
fn serving_slot_for_binding(
    status: &ClaudeAccountsStatusV1,
    candidate_slot_id: &str,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<String> {
    status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .filter(|slot| slot.slot_id != candidate_slot_id)
        .filter(|slot| {
            slot.collection.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && slot.collection.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
        .find(|slot| claude_saved_connection_serves(&slot.collection))
        .map(|slot| slot.slot_id.clone())
}

fn claude_saved_connection_serves(
    collection: &ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
) -> bool {
    // One usability decision for canonical selection and admission alike.
    collection.state != ottto_protocol::ClaudeConfigSlotCollectionStateV1::DuplicateAccount
        && crate::agent_status::claude_slot_connection_usable(
            collection,
            time::OffsetDateTime::now_utc(),
        )
}

fn login_command(config_dir: &str) -> Option<std::process::Command> {
    ottto_core::validate_managed_claude_auth_root(config_dir).ok()?;
    let slot = ClaudeConfigDirSlot::registered(config_dir.to_string()).ok()?;
    let mut command =
        crate::agent_status::resolved_claude_slot_command(&slot, &["auth", "login", "--claudeai"])?;
    command
        .current_dir(config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Some(command)
}

#[cfg(unix)]
fn spawn_supervised_login(
    operation_id: &str,
    config_dir: &str,
) -> std::io::Result<SupervisedChild> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;

    fn pipe_pair() -> std::io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful pipe returns two newly-owned descriptors.
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }

    fn set_cloexec(fd: i32, enabled: bool) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let updated = if enabled {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    let (control_read, control_write) = pipe_pair()?;
    let (code_read, code_write) = pipe_pair()?;
    let (mut event_read, event_write) = pipe_pair()?;
    set_cloexec(control_read.as_raw_fd(), false)?;
    set_cloexec(code_read.as_raw_fd(), false)?;
    set_cloexec(event_write.as_raw_fd(), false)?;
    set_cloexec(control_write.as_raw_fd(), true)?;
    set_cloexec(code_write.as_raw_fd(), true)?;
    set_cloexec(event_read.as_raw_fd(), true)?;

    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .arg("claude-auth-supervisor")
        .arg("--operation-id")
        .arg(operation_id)
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--control-fd")
        .arg(control_read.as_raw_fd().to_string())
        .arg("--code-fd")
        .arg(code_read.as_raw_fd().to_string())
        .arg("--ready-fd")
        .arg(event_write.as_raw_fd().to_string());
    configure_auth_supervisor_environment(&mut command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn()?;
    drop(control_read);
    drop(code_read);
    drop(event_write);

    let deadline = Instant::now() + SUPERVISOR_READY_TIMEOUT;
    loop {
        let mut poll = libc::pollfd {
            fd: event_read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let result = unsafe { libc::poll(&mut poll, 1, timeout) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            kill_owned_process(&mut child);
            return Err(std::io::Error::last_os_error());
        }
        if result == 0 {
            kill_owned_process(&mut child);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Claude auth supervisor did not become ready",
            ));
        }
        let mut byte = [0_u8; 1];
        if event_read.read_exact(&mut byte).is_ok() && byte == [PROVIDER_EVENT_READY] {
            break;
        }
        kill_owned_process(&mut child);
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Claude auth supervisor exited before readiness",
        ));
    }
    let flags = unsafe { libc::fcntl(event_read.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                event_read.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } != 0
    {
        kill_owned_process(&mut child);
        return Err(std::io::Error::last_os_error());
    }
    let process_group_id = child.id() as libc::pid_t;
    Ok(SupervisedChild {
        child,
        control: Some(control_write),
        code: Some(code_write),
        events: Some(event_read),
        process_group_id,
    })
}

#[cfg(unix)]
fn configure_auth_supervisor_environment(command: &mut std::process::Command) {
    let support_dir = default_support_dir();
    command
        .env_clear()
        // `default_support_dir` normally derives from HOME, but the hardened
        // supervisor deliberately starts from an empty environment. Pass the
        // already-resolved directory explicitly so a production launch (where
        // no test override exists) validates the same operation journal that
        // the parent daemon just wrote instead of falling back to /tmp/Ottto.
        .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support_dir);
    for key in [
        "OTTTO_COMMAND_SEARCH_PATH",
        "OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(not(unix))]
fn spawn_supervised_login(
    _operation_id: &str,
    config_dir: &str,
) -> std::io::Result<SupervisedChild> {
    let child = login_command(config_dir)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Claude unavailable"))?
        .spawn()?;
    Ok(SupervisedChild {
        child,
        control: None,
        code: None,
        events: None,
    })
}

/// Hidden child-process entry point. It acquires durable lifetime evidence
/// before acknowledging readiness, launches only the exact hardened official
/// CLI command, and treats parent-pipe EOF as a bounded TERM/KILL request.
#[doc(hidden)]
pub fn run_auth_supervisor(
    operation_id: &str,
    config_dir: &str,
    control_fd: i32,
    code_fd: i32,
    ready_fd: i32,
) -> Result<i32, String> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        validate_supervisor_binding(operation_id, config_dir)?;
        let pinned_root = pin_managed_root(config_dir).map_err(|error| error.to_string())?;
        validate_supervisor_pipe_fds(control_fd, code_fd, ready_fd)?;
        let mut provider = provider_process_guard(operation_id, false)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Claude provider process is already supervised".to_string())?;
        validate_supervisor_binding(operation_id, config_dir)?;
        // SAFETY: these descriptors are passed exclusively by the parent.
        let mut control = unsafe { File::from_raw_fd(control_fd) };
        let code_input = unsafe { File::from_raw_fd(code_fd) };
        let mut ready = unsafe { File::from_raw_fd(ready_fd) };
        for fd in [control_fd, code_fd, ready_fd] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        ready
            .write_all(&[PROVIDER_EVENT_READY])
            .map_err(|error| error.to_string())?;
        let mut command = login_command(config_dir)
            .ok_or_else(|| "official Claude Code executable is unavailable".to_string())?;
        // Claude Code deliberately suppresses browser launch when its standard
        // streams are ordinary pipes. Give the official CLI a private PTY so
        // it keeps its supported interactive/browser behavior while Ottto
        // still drains all provider bytes locally and exposes only typed
        // prompt events. Echo is disabled before launch so a submitted
        // authorization code is never reflected into the scanner.
        let (provider_io, provider_tty) = private_provider_pty()?;
        command
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("FORCE_COLOR", "0")
            .stdin(Stdio::from(
                provider_tty
                    .try_clone()
                    .map_err(|error| error.to_string())?,
            ))
            .stdout(Stdio::from(
                provider_tty
                    .try_clone()
                    .map_err(|error| error.to_string())?,
            ))
            .stderr(Stdio::from(provider_tty));
        // The provider inherits both the supervisor's owned process group and
        // the provider-lifetime lock. If the supervisor itself crashes, the
        // surviving provider therefore keeps the exact root non-reusable and
        // remains killable by the daemon's recorded group while it is alive.
        provider
            .set_inherited_by_exec(true)
            .map_err(|error| error.to_string())?;
        provider.preserve_inherited_lock_on_drop();
        // Keep this descriptor inheritable in the supervisor too. It performs
        // no later exec, so removing the fallible post-spawn CLOEXEC restore
        // closes the only window that could return while a live child retained
        // credentials but the supervisor explicitly unlocked its evidence.
        let mut child = command.spawn().map_err(|error| error.to_string())?;
        let child_pid = child.id() as libc::pid_t;
        let event_writer = Arc::new(Mutex::new(ready));
        let provider_output = provider_io.try_clone().map_err(|error| error.to_string())?;
        thread::spawn(move || scan_provider_output(provider_output, event_writer));
        thread::spawn(move || forward_authorization_codes(code_input, provider_io));
        thread::spawn(move || {
            let mut byte = [0_u8; 1];
            while control.read(&mut byte).is_ok_and(|count| count > 0) {}
            unsafe {
                libc::kill(child_pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + TERM_GRACE;
            while Instant::now() < deadline {
                if unsafe { libc::kill(child_pid, 0) } != 0 {
                    return;
                }
                thread::sleep(Duration::from_millis(25));
            }
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
            }
        });
        loop {
            if !pinned_root.path_matches(config_dir) {
                unsafe {
                    libc::kill(child_pid, libc::SIGTERM);
                }
                thread::sleep(TERM_GRACE);
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err("managed Claude root changed while provider was active".to_string());
            }
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => return Ok(status.code().unwrap_or(1)),
                None => thread::sleep(Duration::from_millis(25)),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (operation_id, config_dir, control_fd, code_fd, ready_fd);
        Err("Claude auth supervision is unsupported on this platform".to_string())
    }
}

#[cfg(unix)]
fn private_provider_pty() -> Result<(File, File), String> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut master_fd = -1;
    let mut slave_fd = -1;
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful openpty returns two newly-owned descriptors.
    let master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };

    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }

    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(slave.as_raw_fd(), attributes.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: tcgetattr initialized the structure on success.
    let mut attributes = unsafe { attributes.assume_init() };
    attributes.c_lflag &= !(libc::ECHO | libc::ECHONL);
    if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &attributes) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((master, slave))
}

#[cfg(unix)]
fn validate_supervisor_pipe_fds(
    control_fd: i32,
    code_fd: i32,
    ready_fd: i32,
) -> Result<(), String> {
    if control_fd < 0
        || code_fd < 0
        || ready_fd < 0
        || control_fd == code_fd
        || control_fd == ready_fd
        || code_fd == ready_fd
    {
        return Err("Claude auth supervisor requires distinct live pipe descriptors".to_string());
    }
    for (fd, expected_access) in [
        (control_fd, libc::O_RDONLY),
        (code_fd, libc::O_RDONLY),
        (ready_fd, libc::O_WRONLY),
    ] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != expected_access {
            return Err("Claude auth supervisor pipe direction is invalid".to_string());
        }
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
            return Err("Claude auth supervisor pipe descriptor is not live".to_string());
        }
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err("Claude auth supervisor descriptor is not a pipe".to_string());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn scan_provider_output<R: Read>(mut stream: R, events: Arc<Mutex<File>>) {
    use zeroize::Zeroize;
    // Claude Code 2.1.263 uses these exact strings. Including the prompt's
    // trailing delimiter and the rejection's complete sentence prevents
    // nearby prose from opening or resetting the secret-input path.
    const PROMPT: &[u8] = b"paste code here if prompted >";
    const INVALID: &[u8] = b"invalid code. please make sure the full code was copied.";
    const MAX_SENTINEL_LEN: usize = INVALID.len();
    let mut tail = Vec::with_capacity(MAX_SENTINEL_LEN);
    let mut buffer = [0_u8; 512];
    loop {
        let count = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        for byte in &buffer[..count] {
            tail.push(byte.to_ascii_lowercase());
            if tail.len() > MAX_SENTINEL_LEN {
                tail.remove(0);
            }
            let event = if tail.ends_with(PROMPT) {
                Some(PROVIDER_EVENT_CODE_PROMPT)
            } else if tail.ends_with(INVALID) {
                Some(PROVIDER_EVENT_CODE_INVALID)
            } else {
                None
            };
            if let Some(event) = event {
                if let Ok(mut writer) = events.lock() {
                    let _ = writer.write_all(&[event]);
                    let _ = writer.flush();
                }
                tail.clear();
            }
        }
        buffer[..count].zeroize();
    }
    tail.zeroize();
    buffer.zeroize();
}

#[cfg(unix)]
fn forward_authorization_codes<R: Read, W: Write>(mut source: R, mut provider: W) {
    use zeroize::Zeroize;
    let mut code = Vec::with_capacity(MAX_AUTH_CODE_BYTES);
    let mut buffer = [0_u8; 256];
    let mut overflow = false;
    loop {
        let count = match source.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                if !overflow
                    && !code.is_empty()
                    && (provider.write_all(&code).is_err()
                        || provider.write_all(b"\n").is_err()
                        || provider.flush().is_err())
                {
                    code.zeroize();
                    buffer[..count].zeroize();
                    return;
                }
                code.zeroize();
                code.clear();
                overflow = false;
            } else if code.len() < MAX_AUTH_CODE_BYTES {
                code.push(*byte);
            } else {
                overflow = true;
            }
        }
        buffer[..count].zeroize();
    }
    code.zeroize();
    buffer.zeroize();
}

fn validate_supervisor_binding(operation_id: &str, config_dir: &str) -> Result<(), String> {
    let state = read_state_strict().map_err(|error| error.to_string())?;
    let operation = state
        .operations
        .iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or_else(|| "Claude auth supervisor operation is unknown".to_string())?;
    if state.active_operation_id.as_deref() != Some(operation_id) {
        return Err(
            "Claude auth supervisor operation does not own the active ceremony".to_string(),
        );
    }
    if operation.config_dir != config_dir {
        return Err("Claude auth supervisor config binding changed".to_string());
    }
    if operation.outcome.is_some()
        || !matches!(
            operation.phase,
            ClaudeBrowserAuthPhaseV1::Launching | ClaudeBrowserAuthPhaseV1::WaitingForProvider
        )
    {
        return Err("Claude auth supervisor operation is not launchable".to_string());
    }
    ottto_core::validate_managed_claude_auth_root(config_dir).map_err(|error| error.to_string())?;
    Ok(())
}

fn reserve_quarantine_root(
    operation: &PersistedOperation,
    pending_registry_removal: bool,
) -> Result<(), String> {
    if operation.mode == PersistedMode::Reconnect {
        return Err("a reconnect root may never be quarantined".to_string());
    }
    let config_dir = operation_config_dir(operation);
    let root_id = Path::new(&config_dir)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Claude provisional root has no exact alias".to_string())?
        .to_string();
    let service_alias = ClaudeConfigDirSlot::registered(config_dir.clone())
        .map_err(|error| error.to_string())?
        .service_name();
    transact(|state| {
        if let Some(existing) = state
            .quarantined_roots
            .iter_mut()
            .find(|root| root.root_id == root_id)
        {
            if (!existing.config_dir.is_empty() && existing.config_dir != config_dir)
                || (!existing.service_alias.is_empty() && existing.service_alias != service_alias)
            {
                return Err("Claude provisional quarantine binding changed".to_string());
            }
            existing.config_dir = config_dir;
            existing.service_alias = service_alias;
            existing.pending_registry_removal = pending_registry_removal;
            existing.claimed_by = Some(operation.operation_id.clone());
        } else {
            if state.quarantined_roots.len() >= MAX_QUARANTINED_ROOTS {
                return Err("Claude provisional root quarantine is full".to_string());
            }
            state.quarantined_roots.push(QuarantinedRoot {
                root_id,
                config_dir,
                service_alias,
                pending_registry_removal,
                claimed_by: Some(operation.operation_id.clone()),
            });
        }
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;
    Ok(())
}

fn make_quarantine_reusable(operation: &PersistedOperation) -> Result<(), String> {
    let config_dir = operation_config_dir(operation);
    let root_id = Path::new(&config_dir)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Claude provisional root has no exact alias".to_string())?;
    let registry = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(|error| error.to_string())?;
    if registry
        .managed_slots
        .iter()
        .chain(registry.external_slots.iter())
        .any(|slot| slot.config_dir.as_deref() == Some(config_dir.as_str()))
    {
        return Err("registered Claude root cannot become reusable".to_string());
    }
    transact(|state| {
        let root = state
            .quarantined_roots
            .iter_mut()
            .find(|root| root.root_id == root_id)
            .ok_or_else(|| "Claude provisional quarantine reservation disappeared".to_string())?;
        if root.claimed_by.as_deref() != Some(operation.operation_id.as_str()) {
            return Err("Claude provisional quarantine claim changed".to_string());
        }
        root.pending_registry_removal = false;
        root.claimed_by = None;
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;
    Ok(())
}

fn quarantine_generic_root(operation: &PersistedOperation) -> Result<(), String> {
    reserve_quarantine_root(operation, false)?;
    make_quarantine_reusable(operation)
}

fn retire_target_candidate(
    operation: &PersistedOperation,
    make_reusable: bool,
) -> Result<(), String> {
    if operation.mode != PersistedMode::Target {
        return Err("only a target candidate may be retired".to_string());
    }
    reserve_quarantine_root(operation, true)?;
    let store = FileClaudeConfigSlotSettingsStore::default();
    let registered = store.load().map_err(|error| error.to_string())?;
    if registered
        .managed_slots
        .iter()
        .chain(registered.external_slots.iter())
        .any(|slot| slot.slot_id == operation.slot_id)
    {
        crate::control::remove_claude_registration_with_relay_cleanup(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            &operation.slot_id,
        )
        .map_err(|error| error.to_string())?;
        let _ = crate::agent_status::prune_claude_slot_collection_state(&operation.slot_id);
        let _ = crate::claude_upkeep::prune_slot_upkeep_state(&operation.slot_id);
    }
    if make_reusable {
        make_quarantine_reusable(operation)?;
    }
    Ok(())
}

pub(crate) fn request_cancel(operation_id: &str) -> Result<bool, String> {
    let admission = admission_guard().map_err(|error| error.to_string())?;
    let Some(operation) = read_operation(operation_id) else {
        return Ok(false);
    };
    if operation.outcome.is_some()
        && (operation.outcome != Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
            || operation.fallback_completed)
    {
        return Ok(true);
    }
    transact(|state| {
        let current = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .ok_or_else(|| {
                "Claude browser operation disappeared during cancellation".to_string()
            })?;
        if current.outcome.is_none()
            || (current.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                && !current.fallback_completed)
        {
            current.cancel_requested = true;
        }
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;

    if operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired) {
        let terminalized =
            terminalize_fallback_operation(&operation, ClaudeBrowserAuthOutcomeV1::Cancelled);
        drop(admission);
        if terminalized.is_ok() && !provider_process_active(operation_id).unwrap_or(true) {
            release_ceremony(operation_id);
            return Ok(true);
        }
        spawn_fallback_observer(operation_id);
        return terminalized.map(|_| true);
    }

    let worker_may_be_running = operation.phase != ClaudeBrowserAuthPhaseV1::Prepared;
    drop(admission);
    if worker_may_be_running {
        resume_operation_recovery(operation_id);
        return Ok(true);
    }
    if !fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled) {
        resume_operation_recovery(operation_id);
    }
    Ok(true)
}

pub fn recover_at_startup() {
    let state = read_state();
    let active_operation_id = state.active_operation_id.clone();
    let operations = state
        .operations
        .into_iter()
        .filter(|operation| {
            operation.outcome.is_none()
                || (operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                    && !operation.fallback_completed)
                || active_operation_id.as_deref() == Some(&operation.operation_id)
        })
        .map(|operation| {
            (
                operation.operation_id,
                operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired),
            )
        })
        .collect::<Vec<_>>();
    for (operation_id, fallback) in operations {
        if fallback {
            spawn_fallback_observer(&operation_id);
        } else {
            let _ = thread::Builder::new()
                .name("ottto-claude-browser-auth-recovery".to_string())
                .spawn(move || recover_operation(&operation_id));
        }
    }
}

pub(crate) fn resume_operation_recovery(operation_id: &str) {
    let operation_id = operation_id.to_string();
    let _ = thread::Builder::new()
        .name("ottto-claude-browser-auth-recovery".to_string())
        .spawn(move || recover_operation(&operation_id));
}

fn spawn_fallback_observer(operation_id: &str) {
    let operation_id = operation_id.to_string();
    let _ = thread::Builder::new()
        .name("ottto-claude-browser-auth-fallback-observer".to_string())
        .spawn(move || observe_fallback(&operation_id));
}

fn observe_fallback(operation_id: &str) {
    let mut guard = None;
    for _ in 0..20 {
        match operation_guard(operation_id) {
            Ok(Some(acquired)) => {
                guard = Some(acquired);
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => return,
        }
    }
    let Some(_guard) = guard else { return };
    loop {
        let Some(operation) = read_operation(operation_id) else {
            return;
        };
        if operation.fallback_completed
            || operation.outcome != Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        {
            if !provider_process_active(operation_id).unwrap_or(true) {
                release_ceremony(operation_id);
            }
            return;
        }
        if operation.cancel_requested {
            let terminalized = if let Ok(_admission) = admission_guard() {
                terminalize_fallback_operation(&operation, ClaudeBrowserAuthOutcomeV1::Cancelled)
                    .is_ok()
            } else {
                false
            };
            if terminalized && !provider_process_active(operation_id).unwrap_or(true) {
                release_ceremony(operation_id);
                return;
            }
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        }
        let observer_deadline = operation
            .completed_unix_seconds
            .unwrap_or(operation.started_unix_seconds)
            .saturating_add(LOGIN_TIMEOUT.as_secs());
        if unix_seconds() >= observer_deadline {
            let terminalized = if let Ok(_admission) = admission_guard() {
                terminalize_fallback_operation(&operation, ClaudeBrowserAuthOutcomeV1::TimedOut)
                    .is_ok()
            } else {
                false
            };
            if terminalized {
                release_ceremony(operation_id);
                return;
            }
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        }
        let config_dir = operation_config_dir(&operation);
        if ceremony_witness_changed(&operation, &config_dir) {
            let Ok(pinned_root) = pin_managed_root(&config_dir) else {
                let terminalized = if let Ok(_admission) = admission_guard() {
                    terminalize_fallback_operation(
                        &operation,
                        ClaudeBrowserAuthOutcomeV1::LoginFailed,
                    )
                    .is_ok()
                } else {
                    false
                };
                if terminalized {
                    release_ceremony(operation_id);
                    return;
                }
                thread::sleep(RECOVERY_POLL_INTERVAL);
                continue;
            };
            if let Ok(proof) = crate::agent_status::verify_claude_local_identity(
                &operation.slot_id,
                &config_dir,
                &observed_at(),
            ) {
                if pinned_root.path_matches(&config_dir)
                    && finalize_observed_fallback_identity(operation_id, proof)
                {
                    release_ceremony(operation_id);
                    return;
                }
            }
        }
        thread::sleep(RECOVERY_POLL_INTERVAL);
    }
}

fn finalize_observed_fallback_identity(
    operation_id: &str,
    proof: crate::agent_status::ClaudeLocalIdentityProof,
) -> bool {
    if finalize_identity_mode(operation_id, proof, true).is_err() {
        return false;
    }
    let durably_complete = read_operation(operation_id).is_some_and(|operation| {
        operation.fallback_completed
            || operation.outcome.is_some_and(|outcome| {
                outcome != ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
            })
    });
    durably_complete && !provider_process_active(operation_id).unwrap_or(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreCoreFenceRecovery {
    NotApplicable,
    Sealed,
    Aborted,
}

/// A registry fence is deliberately durable before the core registry mutation.
/// After a daemon restart, reconcile that narrow crash window before deriving
/// or inspecting any path from the sidecar. In particular, an empty target
/// placeholder is never interpreted as the managed-account parent directory.
fn reconcile_pre_core_fence(
    operation: &PersistedOperation,
) -> Result<PreCoreFenceRecovery, String> {
    if operation.outcome.is_some()
        || operation.phase != ClaudeBrowserAuthPhaseV1::Prepared
        || operation.ceremony_baseline.is_some()
        || !matches!(
            operation.mode,
            PersistedMode::Target | PersistedMode::Reconnect
        )
    {
        return Ok(PreCoreFenceRecovery::NotApplicable);
    }

    let store = FileClaudeConfigSlotSettingsStore::default();
    let Some(core) = store
        .setup_operation_if_exists(&operation.operation_id)
        .map_err(|error| error.to_string())?
    else {
        let operation_id = operation.operation_id.clone();
        let mode = operation.mode;
        let config_dir = operation.config_dir.clone();
        transact(|state| {
            let Some(index) = state.operations.iter().position(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.mode == mode
                    && candidate.phase == ClaudeBrowserAuthPhaseV1::Prepared
                    && candidate.ceremony_baseline.is_none()
                    && candidate.outcome.is_none()
            }) else {
                return Err("Claude browser registry fence changed during recovery".to_string());
            };
            if mode == PersistedMode::Target && !config_dir.is_empty() {
                let root = state
                    .quarantined_roots
                    .iter_mut()
                    .find(|root| {
                        root.config_dir == config_dir
                            && root.claimed_by.as_deref() == Some(operation_id.as_str())
                    })
                    .ok_or_else(|| {
                        "Claude reusable root claim disappeared during fence recovery".to_string()
                    })?;
                root.claimed_by = None;
            }
            state.operations.remove(index);
            if state.active_operation_id.as_deref() == Some(operation_id.as_str()) {
                state.active_operation_id = None;
            }
            Ok::<(), String>(())
        })
        .map_err(|error| error.to_string())??;
        return Ok(PreCoreFenceRecovery::Aborted);
    };

    let expected_kind = match operation.mode {
        PersistedMode::Target => ClaudeAccountSetupOperationKind::ConnectManagedAccount,
        PersistedMode::Reconnect => ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot,
        PersistedMode::Generic => unreachable!("generic operations were filtered above"),
    };
    if core.setup_operation.kind != expected_kind
        || core.setup_operation.target_id != operation.target_id
        || core.setup_operation.expected_account_identifier_hash
            != operation.expected_account_identifier_hash
        || core.setup_operation.expected_organization_identifier_hash
            != operation.expected_organization_identifier_hash
    {
        return Err("Claude core registry fence changed its expected binding".to_string());
    }
    let slot_id = core
        .setup_operation
        .slot_id
        .as_deref()
        .filter(|slot| !slot.is_empty())
        .ok_or_else(|| "Claude core registry fence has no exact slot".to_string())?;
    let config_dir = core
        .managed_slots
        .iter()
        .chain(core.external_slots.iter())
        .find(|slot| slot.slot_id == slot_id)
        .and_then(|slot| slot.config_dir.as_deref())
        .filter(|path| !path.is_empty())
        .ok_or_else(|| "Claude core registry fence has no exact root".to_string())?;
    if operation.slot_id == slot_id && operation.config_dir == config_dir {
        return Ok(PreCoreFenceRecovery::NotApplicable);
    }
    let operation_id = operation.operation_id.clone();
    transact(|state| {
        let current = state
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .ok_or_else(|| "Claude browser registry fence disappeared".to_string())?;
        if current.mode != operation.mode
            || current.phase != ClaudeBrowserAuthPhaseV1::Prepared
            || current.ceremony_baseline.is_some()
            || current.outcome.is_some()
            || (!current.slot_id.is_empty() && current.slot_id != slot_id)
            || (!current.config_dir.is_empty() && current.config_dir != config_dir)
        {
            return Err("Claude browser registry fence changed during recovery".to_string());
        }
        current.slot_id = slot_id.to_string();
        current.config_dir = config_dir.to_string();
        Ok::<(), String>(())
    })
    .map_err(|error| error.to_string())??;
    Ok(PreCoreFenceRecovery::Sealed)
}

fn recover_operation(operation_id: &str) {
    loop {
        let Some(operation) = read_operation(operation_id) else {
            return;
        };
        let reconciliation_guard = match operation_guard(operation_id) {
            Ok(Some(guard)) => guard,
            Ok(None) | Err(_) => {
                thread::sleep(PROCESS_POLL_INTERVAL);
                continue;
            }
        };
        match reconcile_pre_core_fence(&operation) {
            Ok(PreCoreFenceRecovery::Aborted) => return,
            Ok(PreCoreFenceRecovery::Sealed) => continue,
            Ok(PreCoreFenceRecovery::NotApplicable) => {}
            Err(_) => {
                thread::sleep(RECOVERY_POLL_INTERVAL);
                continue;
            }
        }
        drop(reconciliation_guard);
        if operation.outcome.is_some() {
            if operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                && !operation.fallback_completed
            {
                spawn_fallback_observer(operation_id);
                return;
            }
            if provider_process_active(operation_id).unwrap_or(true) {
                thread::sleep(PROCESS_POLL_INTERVAL);
                continue;
            }
            if operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::Cancelled) {
                let cleanup = match operation.mode {
                    PersistedMode::Generic => quarantine_generic_root(&operation),
                    PersistedMode::Target => retire_target_candidate(&operation, true),
                    PersistedMode::Reconnect => Ok(()),
                };
                if cleanup.is_err() {
                    thread::sleep(RECOVERY_POLL_INTERVAL);
                    continue;
                }
            }
            release_ceremony(operation_id);
            return;
        }
        if provider_process_active(operation_id).unwrap_or(true) {
            thread::sleep(PROCESS_POLL_INTERVAL);
            continue;
        }
        if operation.cancel_requested {
            if fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled) {
                return;
            }
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        }
        if unix_seconds() >= operation.deadline_unix_seconds {
            if provider_process_active(operation_id).unwrap_or(true) {
                thread::sleep(PROCESS_POLL_INTERVAL);
                continue;
            }
            if fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::TimedOut) {
                return;
            }
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        }
        // Never relaunch and never reuse a persisted PID. Recovery only
        // observes the exact local identity until the original deadline.
        set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Validating);
        let config_dir = operation_config_dir(&operation);
        if !ceremony_witness_changed(&operation, &config_dir) {
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        }
        let Ok(pinned_root) = pin_managed_root(&config_dir) else {
            if fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed) {
                return;
            }
            thread::sleep(RECOVERY_POLL_INTERVAL);
            continue;
        };
        if let Ok(proof) = crate::agent_status::verify_claude_local_identity(
            &operation.slot_id,
            &config_dir,
            &observed_at(),
        ) {
            if !pinned_root.path_matches(&config_dir) {
                if fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed) {
                    return;
                }
                thread::sleep(RECOVERY_POLL_INTERVAL);
                continue;
            }
            if finalize_identity(operation_id, proof).is_err()
                && !fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed)
            {
                thread::sleep(RECOVERY_POLL_INTERVAL);
                continue;
            }
            return;
        }
        thread::sleep(RECOVERY_POLL_INTERVAL);
    }
}

fn fail_operation(operation_id: &str, outcome: ClaudeBrowserAuthOutcomeV1) -> bool {
    let Ok(_admission) = admission_guard() else {
        return false;
    };
    if let Some(operation) = read_operation(operation_id) {
        if operation.mode != PersistedMode::Generic
            && outcome != ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
            && transition_registry_terminal(&operation, outcome).is_err()
        {
            return false;
        }
        if operation.mode == PersistedMode::Generic
            && (if outcome == ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired {
                reserve_quarantine_root(&operation, false)
            } else {
                quarantine_generic_root(&operation)
            })
            .is_err()
        {
            // Preserve the root and a nonterminal journal rather than
            // silently evicting or corrupt-resetting capacity.
            return false;
        }
        if operation.mode == PersistedMode::Target
            && outcome != ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
            && retire_target_candidate(&operation, true).is_err()
        {
            return false;
        }
    }
    finish(operation_id, outcome, None);
    read_state_strict().ok().is_some_and(|state| {
        state.operations.iter().any(|operation| {
            operation.operation_id == operation_id && operation.outcome == Some(outcome)
        })
    })
}

fn finish_mismatch(
    operation_id: &str,
    mismatch: ClaudeBrowserAuthIdentityMismatchV1,
    allow_terminal_fallback: bool,
) -> Result<(), String> {
    if let Some(operation) = read_operation(operation_id) {
        let eligible = !operation.cancel_requested
            && (operation.outcome.is_none()
                || (allow_terminal_fallback
                    && operation.outcome
                        == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                    && !operation.fallback_completed));
        if !eligible {
            return Ok(());
        }
        let message = if operation.mode == PersistedMode::Reconnect {
            // Claude's own login ran in this slot's directory, so the Claude
            // login saved there now belongs to the other account.
            "Claude signed in to a different account, which replaced the Claude login saved in this connection. Ottto kept this connection set up for its original account and assigned no usage to the other account. Sign in again with the original account to resume."
        } else {
            "Claude signed in to a different account than the one requested. Ottto did not save that login or assign it any usage."
        };
        if operation.mode != PersistedMode::Generic
            && transition_registry_terminal_with_message(
                &operation,
                ClaudeBrowserAuthOutcomeV1::IdentityMismatch,
                message,
            )
            .is_err()
        {
            return Err("Claude mismatch could not terminalize the core operation".to_string());
        }
        if operation.mode == PersistedMode::Generic && quarantine_generic_root(&operation).is_err()
        {
            return Err("Claude mismatch could not retain its provisional root".to_string());
        }
        if operation.mode == PersistedMode::Target
            && retire_target_candidate(&operation, true).is_err()
        {
            return Err("Claude mismatch could not retire its target root".to_string());
        }
    }
    let terminalized = transact(|state| {
        let mut terminalized = false;
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            if !operation.cancel_requested
                && (operation.outcome.is_none()
                    || (allow_terminal_fallback
                        && operation.outcome
                            == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                        && !operation.fallback_completed))
            {
                operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
                operation.outcome = Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch);
                operation.identity_mismatch = Some(mismatch);
                operation.cancel_requested = false;
                operation.completed_unix_seconds = Some(unix_seconds());
                terminalized = true;
            }
        }
        if terminalized && state.active_operation_id.as_deref() == Some(operation_id) {
            state.active_operation_id = None;
        }
        terminalized
    })
    .map_err(|error| error.to_string())?;
    if terminalized {
        Ok(())
    } else {
        Err("Claude mismatch terminalization lost its sidecar binding".to_string())
    }
}

fn transition_registry_terminal(
    operation: &PersistedOperation,
    outcome: ClaudeBrowserAuthOutcomeV1,
) -> Result<(), String> {
    transition_registry_terminal_with_message(
        operation,
        outcome,
        "Claude browser authentication ended before identity admission.",
    )
}

fn transition_registry_terminal_with_message(
    operation: &PersistedOperation,
    outcome: ClaudeBrowserAuthOutcomeV1,
    message: &str,
) -> Result<(), String> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if store.setup_operation(&operation.operation_id).is_err()
        && operation.mode == PersistedMode::Target
    {
        let status = store.load().map_err(|error| error.to_string())?;
        if !status
            .managed_slots
            .iter()
            .chain(status.external_slots.iter())
            .any(|slot| slot.slot_id == operation.slot_id)
        {
            return Ok(());
        }
    }
    let state = match outcome {
        ClaudeBrowserAuthOutcomeV1::Cancelled => ClaudeAccountSetupOperationState::SetupStopped,
        ClaudeBrowserAuthOutcomeV1::IdentityMismatch => {
            ClaudeAccountSetupOperationState::IdentityMismatch
        }
        _ => ClaudeAccountSetupOperationState::SetupFailed,
    };
    store
        .transition_setup_operation_with_binding(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            &operation.operation_id,
            operation.expected_account_identifier_hash.as_deref(),
            operation.expected_organization_identifier_hash.as_deref(),
            state,
            None,
            None,
            Some(message),
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn finish(
    operation_id: &str,
    outcome: ClaudeBrowserAuthOutcomeV1,
    canonical_slot_id: Option<String>,
) {
    let terminalized = transact(|state| {
        let mut terminalized = false;
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            if operation.outcome.is_none()
                && (!operation.cancel_requested || outcome == ClaudeBrowserAuthOutcomeV1::Cancelled)
            {
                operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
                operation.outcome = Some(outcome);
                operation.canonical_slot_id = canonical_slot_id;
                operation.cancel_requested = false;
                operation.completed_unix_seconds = Some(unix_seconds());
                terminalized = true;
            }
        }
        if terminalized
            && outcome != ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
            && state.active_operation_id.as_deref() == Some(operation_id)
        {
            state.active_operation_id = None;
        }
        if terminalized && state.invalid_code_operation_id.as_deref() == Some(operation_id) {
            state.invalid_code_operation_id = None;
        }
        terminalized
    });
    if terminalized.ok() == Some(true)
        && outcome == ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
    {
        spawn_fallback_observer(operation_id);
    }
}

fn terminalize_fallback_operation(
    operation: &PersistedOperation,
    outcome: ClaudeBrowserAuthOutcomeV1,
) -> Result<(), String> {
    if operation.mode != PersistedMode::Generic {
        transition_registry_terminal(operation, outcome)?;
    }
    match operation.mode {
        PersistedMode::Generic => {
            make_quarantine_reusable(operation)?;
        }
        PersistedMode::Target => {
            retire_target_candidate(operation, true)?;
        }
        PersistedMode::Reconnect => {}
    }
    finish_fallback_failure(&operation.operation_id, outcome)
}

fn finish_fallback_failure(
    operation_id: &str,
    outcome: ClaudeBrowserAuthOutcomeV1,
) -> Result<(), String> {
    let terminalized = transact(|state| {
        let mut terminalized = false;
        if let Some(operation) = state.operations.iter_mut().find(|operation| {
            operation.operation_id == operation_id
                && operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                && !operation.fallback_completed
        }) {
            operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
            operation.outcome = Some(outcome);
            operation.cancel_requested = false;
            operation.completed_unix_seconds = Some(unix_seconds());
            terminalized = true;
        }
        if terminalized && state.active_operation_id.as_deref() == Some(operation_id) {
            state.active_operation_id = None;
        }
        terminalized
    })
    .map_err(|error| error.to_string())?;
    if terminalized {
        Ok(())
    } else {
        Err("Claude fallback terminalization did not match an active operation".to_string())
    }
}

fn complete_identity_operation(
    operation_id: &str,
    outcome: ClaudeBrowserAuthOutcomeV1,
    canonical_slot_id: Option<String>,
    allow_terminal_fallback: bool,
) -> Result<(), String> {
    if !allow_terminal_fallback {
        finish(operation_id, outcome, canonical_slot_id);
        return read_operation(operation_id)
            .filter(|operation| operation.outcome == Some(outcome))
            .map(|_| ())
            .ok_or_else(|| "Claude browser completion could not be persisted".to_string());
    }
    transact(|state| {
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            if operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
                && !operation.cancel_requested
            {
                operation.fallback_completed = true;
                operation.canonical_slot_id = canonical_slot_id;
            }
        }
    })
    .map_err(|error| error.to_string())?;
    read_operation(operation_id)
        .filter(|operation| operation.fallback_completed)
        .map(|_| ())
        .ok_or_else(|| "Claude fallback completion could not be persisted".to_string())
}

fn consume_reusable_root_claim(operation_id: &str) -> Result<(), String> {
    transact(|state| {
        state
            .quarantined_roots
            .retain(|root| root.claimed_by.as_deref() != Some(operation_id));
    })
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn set_phase(operation_id: &str, phase: ClaudeBrowserAuthPhaseV1) {
    let _ = transact(|state| {
        let mut changed = false;
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            if operation.outcome.is_none() {
                operation.phase = phase;
                changed = true;
            }
        }
        if changed
            && phase != ClaudeBrowserAuthPhaseV1::WaitingForCode
            && state.invalid_code_operation_id.as_deref() == Some(operation_id)
        {
            state.invalid_code_operation_id = None;
        }
    });
}

fn cancel_requested(operation_id: &str) -> bool {
    read_operation(operation_id).map_or(true, |operation| {
        operation.cancel_requested
            || operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
    })
}

fn read_operation(operation_id: &str) -> Option<PersistedOperation> {
    read_state()
        .operations
        .into_iter()
        .find(|operation| operation.operation_id == operation_id)
}

pub(crate) fn has_browser_operation(operation_id: &str) -> bool {
    read_operation(operation_id).is_some()
}

pub(crate) fn active_replay_is_sealed(
    status: &ClaudeAccountsStatusV1,
    operation_id: &str,
    mode: BrowserLoginMode,
) -> bool {
    if !matches!(mode, BrowserLoginMode::Target | BrowserLoginMode::Reconnect) {
        return false;
    }
    let Ok(state) = read_state_strict() else {
        return false;
    };
    if state.active_operation_id.as_deref() != Some(operation_id) {
        return false;
    }
    let mut matching = state
        .operations
        .iter()
        .filter(|operation| operation.operation_id == operation_id);
    let Some(operation) = matching.next() else {
        return false;
    };
    if matching.next().is_some()
        || operation.mode != mode.persisted()
        || operation.slot_id.is_empty()
        || operation.config_dir.is_empty()
        || operation.ceremony_baseline.is_none()
        || operation.cancel_requested
        || operation.outcome.is_some()
        || operation.fallback_completed
        || operation.completed_unix_seconds.is_some()
        || operation.deadline_unix_seconds <= unix_seconds()
        || !matches!(
            operation.phase,
            ClaudeBrowserAuthPhaseV1::Launching
                | ClaudeBrowserAuthPhaseV1::WaitingForProvider
                | ClaudeBrowserAuthPhaseV1::WaitingForCode
                | ClaudeBrowserAuthPhaseV1::SubmittingCode
                | ClaudeBrowserAuthPhaseV1::Validating
                | ClaudeBrowserAuthPhaseV1::Reading
        )
    {
        return false;
    }
    let expected_kind = match mode {
        BrowserLoginMode::Target => ClaudeAccountSetupOperationKind::ConnectManagedAccount,
        BrowserLoginMode::Reconnect => ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot,
        BrowserLoginMode::Generic => unreachable!("generic replay was rejected above"),
    };
    let core = &status.setup_operation;
    if core.operation_id.as_deref() != Some(operation_id)
        || core.kind != expected_kind
        || core.slot_id.as_deref() != Some(operation.slot_id.as_str())
        || core.target_id != operation.target_id
        || core.expected_account_identifier_hash != operation.expected_account_identifier_hash
        || core.expected_organization_identifier_hash
            != operation.expected_organization_identifier_hash
        || !matches!(
            core.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
                | ClaudeAccountSetupOperationState::Validating
                | ClaudeAccountSetupOperationState::Reading
        )
    {
        return false;
    }
    status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .filter(|slot| slot.slot_id == operation.slot_id)
        .map(|slot| slot.config_dir.as_deref())
        .eq(std::iter::once(Some(operation.config_dir.as_str())))
}

fn kill_owned_process(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGTERM);
    }
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
}

fn trim_operations(state: &mut PersistedState) {
    while state.operations.len() > MAX_RETAINED_OPERATIONS {
        let protected_reconnects = state
            .operations
            .iter()
            .rev()
            .filter(|operation| operation.mode == PersistedMode::Reconnect)
            .filter(|operation| {
                !operation.fallback_completed
                    && !matches!(
                        operation.outcome,
                        Some(
                            ClaudeBrowserAuthOutcomeV1::Complete
                                | ClaudeBrowserAuthOutcomeV1::AlreadyConnected
                        )
                    )
            })
            .map(|operation| operation.slot_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let removable = state.operations.iter().position(|operation| {
            state.active_operation_id.as_deref() != Some(&operation.operation_id)
                && !(operation.mode == PersistedMode::Reconnect
                    && protected_reconnects.contains(&operation.slot_id)
                    && state
                        .operations
                        .iter()
                        .rev()
                        .find(|candidate| {
                            candidate.mode == PersistedMode::Reconnect
                                && candidate.slot_id == operation.slot_id
                        })
                        .is_some_and(|latest| latest.operation_id == operation.operation_id))
        });
        let Some(removable) = removable else { break };
        state.operations.remove(removable);
    }
}

fn managed_root() -> PathBuf {
    default_support_dir().join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
}

fn state_path() -> PathBuf {
    default_support_dir().join(STATE_FILE)
}

fn read_state() -> PersistedState {
    read_state_strict().unwrap_or_default()
}

fn read_state_strict() -> std::io::Result<PersistedState> {
    let body = match fs::read(state_path()) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistedState::default());
        }
        Err(error) => return Err(error),
    };
    let state = serde_json::from_slice::<PersistedState>(&body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported Claude browser auth state schema",
        ));
    }
    Ok(state)
}

fn transact<T>(mutation: impl FnOnce(&mut PersistedState) -> T) -> Result<T, std::io::Error> {
    let _guard = state_guard()?;
    // Never replace malformed or unknown state with defaults. Refusing the
    // mutation preserves every exact root and service alias for recovery.
    let mut state = read_state_strict()?;
    let result = mutation(&mut state);
    let body = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&state_path(), &body)?;
    Ok(result)
}

fn state_guard() -> std::io::Result<StateGuard> {
    use std::os::fd::AsRawFd;
    let process = STATE_TRANSACTION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    let file = open_private_lock_file(&default_support_dir().join(STATE_LOCK_FILE))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(StateGuard {
        _process: process,
        file,
    })
}

fn operation_guard(operation_id: &str) -> std::io::Result<Option<OperationGuard>> {
    fs::create_dir_all(default_support_dir())?;
    let path = default_support_dir().join(format!("{OPERATION_LOCK_PREFIX}{operation_id}.lock"));
    match FileLock::try_exclusive(open_private_lock_file(&path)?) {
        Ok(lock) => Ok(Some(OperationGuard { _file: lock })),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn registry_mutation_guard(operation_id: &str) -> Result<OperationGuard, String> {
    let Some(suffix) = operation_id.strip_prefix("claude_setup_") else {
        return Err("Claude browser operation id has an unsupported shape".to_string());
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Claude browser operation id has an unsupported shape".to_string());
    }
    loop {
        match operation_guard(operation_id).map_err(|error| error.to_string())? {
            Some(guard) => return Ok(guard),
            None => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    }
}

fn provider_process_guard(
    operation_id: &str,
    nonblocking: bool,
) -> std::io::Result<Option<ProviderProcessGuard>> {
    use std::os::fd::AsRawFd;
    fs::create_dir_all(default_support_dir())?;
    let path =
        default_support_dir().join(format!("{PROVIDER_PROCESS_LOCK_PREFIX}{operation_id}.lock"));
    let file = open_private_lock_file(&path)?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    let result = unsafe { libc::flock(file.as_raw_fd(), flags) };
    if result != 0 {
        return if nonblocking
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
        {
            Ok(None)
        } else {
            Err(std::io::Error::last_os_error())
        };
    }
    Ok(Some(ProviderProcessGuard {
        file,
        unlock_on_drop: true,
    }))
}

fn provider_process_active(operation_id: &str) -> std::io::Result<bool> {
    match provider_process_guard(operation_id, true)? {
        Some(_available) => Ok(false),
        None => Ok(true),
    }
}

fn admission_guard() -> std::io::Result<AdmissionGuard> {
    use std::os::fd::AsRawFd;
    let process = ADMISSION_TRANSACTION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    let file = open_private_lock_file(&default_support_dir().join(ADMISSION_LOCK_FILE))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(AdmissionGuard {
        _process: process,
        file,
    })
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn observed_at() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests;
