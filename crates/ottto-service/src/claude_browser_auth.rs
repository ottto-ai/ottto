//! Explicit provider-owned Claude browser authentication.
//!
//! This module never constructs an OAuth URL, reads browser state, or captures
//! provider output. It supervises the official CLI with one exact managed
//! root, then hands identity/quota verification back to the existing collector.

use ottto_core::{
    default_support_dir, prepare_managed_claude_provisional_root, write_owner_only_file_atomic,
    ClaudeConfigDirSlot, FileClaudeConfigSlotSettingsStore, CLAUDE_MANAGED_ACCOUNTS_DIR_NAME,
};
use ottto_protocol::{
    ClaudeAccountSetupOperationKind, ClaudeAccountSetupOperationState,
    ClaudeAccountSetupOperationV1, ClaudeAccountsStatusV1, ClaudeBrowserAuthIdentityMismatchV1,
    ClaudeBrowserAuthOperationV1, ClaudeBrowserAuthOutcomeV1, ClaudeBrowserAuthPhaseV1,
    CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock};
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

static STATE_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();
static ADMISSION_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();

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
    file: File,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
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
    #[cfg(unix)]
    process_group_id: libc::pid_t,
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
            status.setup_operation = synthetic_operation(operation);
        }
        status.setup_operation.browser_auth = Some(public_operation(operation));
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

fn public_operation(operation: &PersistedOperation) -> ClaudeBrowserAuthOperationV1 {
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
        terminal_fallback_available: effective_outcome
            == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
            && resolved_legacy_fallback_command(operation).is_some(),
        identity_mismatch: operation.identity_mismatch,
        canonical_slot_id: operation.canonical_slot_id.clone(),
    }
}

fn synthetic_operation(operation: &PersistedOperation) -> ClaudeAccountSetupOperationV1 {
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
            | ClaudeBrowserAuthPhaseV1::WaitingForProvider => {
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
        launch_command: matches!(
            operation.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        )
        .then(|| resolved_legacy_fallback_command(operation))
        .flatten(),
        browser_auth: Some(public_operation(operation)),
        message: operation.cancel_requested.then(|| {
            "Stopping Claude authentication; ordered local cleanup is still in progress."
                .to_string()
        }),
    }
}

pub(crate) fn claim_reusable_root(operation_id: &str) -> Result<Option<String>, String> {
    transact(|state| {
        let same_operation_root = state
            .quarantined_roots
            .iter()
            .position(|root| root.claimed_by.as_deref() == Some(operation_id));
        let root_index = same_operation_root.or_else(|| {
            state
                .quarantined_roots
                .iter()
                .position(|root| root.claimed_by.is_none())
        });
        let Some(root_index) = root_index else {
            return Ok(None);
        };
        let root = &mut state.quarantined_roots[root_index];
        let config_dir = if root.config_dir.is_empty() {
            managed_root()
                .join(&root.root_id)
                .to_string_lossy()
                .into_owned()
        } else {
            root.config_dir.clone()
        };
        ottto_core::validate_managed_claude_auth_root(&config_dir)
            .map_err(|error| error.to_string())?;
        let service_alias = ClaudeConfigDirSlot::registered(config_dir.clone())
            .map_err(|error| error.to_string())?
            .service_name();
        if !root.service_alias.is_empty() && root.service_alias != service_alias {
            return Err("Claude provisional root service alias changed".to_string());
        }
        let registry = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .map_err(|error| error.to_string())?;
        let registered_slot = registry
            .managed_slots
            .iter()
            .chain(registry.external_slots.iter())
            .find(|slot| slot.config_dir.as_deref() == Some(config_dir.as_str()));
        let exact_same_operation_registration = same_operation_root.is_some()
            && registry.setup_operation.operation_id.as_deref() == Some(operation_id)
            && registered_slot.is_some_and(|slot| {
                registry.setup_operation.slot_id.as_deref() == Some(slot.slot_id.as_str())
            });
        if registered_slot.is_some() && !exact_same_operation_registration {
            return Err("registered Claude root cannot be reused as provisional".to_string());
        }
        root.claimed_by = Some(operation_id.to_string());
        Ok(Some(config_dir))
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
        fail_operation(operation_id, fallback_outcome(&operation));
        return;
    };
    if !pinned_root.path_matches(&config_dir) {
        cancel_provider_before_terminal(&mut child, operation_id);
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        return;
    }
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
    let start = Instant::now();
    let process_success = loop {
        if !pinned_root.path_matches(&config_dir) {
            cancel_provider_before_terminal(&mut child, operation_id);
            fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
            return;
        }
        if cancel_requested(operation_id) {
            cancel_provider_before_terminal(&mut child, operation_id);
            fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled);
            return;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    cancel_provider_before_terminal(&mut child, operation_id);
                }
                break status.success();
            }
            Ok(None) if start.elapsed() >= LOGIN_TIMEOUT => {
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
        fail_operation(operation_id, fallback_outcome(&operation));
        return;
    }
    set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Validating);
    let proof = crate::agent_status::verify_claude_local_identity(
        &operation.slot_id,
        &config_dir,
        &observed_at(),
    );
    let Ok(proof) = proof else {
        fail_operation(
            operation_id,
            if process_success {
                ClaudeBrowserAuthOutcomeV1::LoginFailed
            } else {
                fallback_outcome(&operation)
            },
        );
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
    let registry_operation = if operation.mode == PersistedMode::Generic {
        None
    } else {
        Some(
            store
                .setup_operation(operation_id)
                .map_err(|error| error.to_string())?
                .setup_operation,
        )
    };
    let mismatch = registry_operation.as_ref().and_then(|expected| {
        identity_mismatch(
            expected.expected_account_identifier_hash.as_deref(),
            expected.expected_organization_identifier_hash.as_deref(),
            &proof.account_identifier_hash,
            &proof.organization_identifier_hash,
        )
    });
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
        if let Some(canonical) = duplicate_slot_for_binding(
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
        if let Err(error) = store.register_managed_path_with_slot_id(
            CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            canonical.clone(),
            operation_config_dir(&operation),
        ) {
            let _ = crate::agent_status::prune_claude_slot_collection_state(&canonical);
            clear_admission_slot(operation_id);
            return Err(error.to_string());
        }
        collect_allowed_quota(&store, &canonical);
        if let Err(error) = consume_reusable_root_claim(operation_id) {
            let _ = store.remove(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, &canonical);
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
            if let Some(canonical) = duplicate_slot_for_binding(
                &status,
                &operation.slot_id,
                &proof.account_identifier_hash,
                &proof.organization_identifier_hash,
            ) {
                reserve_quarantine_root(&operation, true)?;
                store
                    .remove(
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

fn collect_allowed_quota(store: &FileClaudeConfigSlotSettingsStore, slot_id: &str) {
    let Ok(status) = store.load() else { return };
    if status.consent != ottto_protocol::ClaudeAccountUpkeepConsentState::Granted {
        return;
    }
    let captured_at = observed_at();
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::minutes(15))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| captured_at.clone());
    let quota = crate::agent_status::collect_registered_claude_slot_status(
        slot_id,
        captured_at,
        expires_at,
    );
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

fn duplicate_slot_for_binding(
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
        .find(|slot| {
            slot.collection.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && slot.collection.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
        .map(|slot| slot.slot_id.clone())
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

fn resolved_legacy_fallback_command(operation: &PersistedOperation) -> Option<String> {
    let config_dir = operation_config_dir(operation);
    login_command(&config_dir)?;
    ottto_core::claude_legacy_launch_command(&config_dir).ok()
}

fn fallback_outcome(operation: &PersistedOperation) -> ClaudeBrowserAuthOutcomeV1 {
    if resolved_legacy_fallback_command(operation).is_some() {
        ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired
    } else {
        ClaudeBrowserAuthOutcomeV1::LoginFailed
    }
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
    let (mut ready_read, ready_write) = pipe_pair()?;
    set_cloexec(control_read.as_raw_fd(), false)?;
    set_cloexec(ready_write.as_raw_fd(), false)?;
    set_cloexec(control_write.as_raw_fd(), true)?;
    set_cloexec(ready_read.as_raw_fd(), true)?;

    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .arg("claude-auth-supervisor")
        .arg("--operation-id")
        .arg(operation_id)
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--control-fd")
        .arg(control_read.as_raw_fd().to_string())
        .arg("--ready-fd")
        .arg(ready_write.as_raw_fd().to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    for key in [
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
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
    let mut child = command.spawn()?;
    drop(control_read);
    drop(ready_write);

    let deadline = Instant::now() + SUPERVISOR_READY_TIMEOUT;
    loop {
        let mut poll = libc::pollfd {
            fd: ready_read.as_raw_fd(),
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
        if ready_read.read_exact(&mut byte).is_ok() && byte == [1] {
            break;
        }
        kill_owned_process(&mut child);
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Claude auth supervisor exited before readiness",
        ));
    }
    let process_group_id = child.id() as libc::pid_t;
    Ok(SupervisedChild {
        child,
        control: Some(control_write),
        process_group_id,
    })
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
    ready_fd: i32,
) -> Result<i32, String> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        validate_supervisor_binding(operation_id, config_dir)?;
        let pinned_root = pin_managed_root(config_dir).map_err(|error| error.to_string())?;
        validate_supervisor_pipe_fds(control_fd, ready_fd)?;
        let mut provider = provider_process_guard(operation_id, false)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Claude provider process is already supervised".to_string())?;
        validate_supervisor_binding(operation_id, config_dir)?;
        // SAFETY: these descriptors are passed exclusively by the parent.
        let mut control = unsafe { File::from_raw_fd(control_fd) };
        let mut ready = unsafe { File::from_raw_fd(ready_fd) };
        let control_flags = unsafe { libc::fcntl(control_fd, libc::F_GETFD) };
        if control_flags < 0
            || unsafe { libc::fcntl(control_fd, libc::F_SETFD, control_flags | libc::FD_CLOEXEC) }
                != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        ready.write_all(&[1]).map_err(|error| error.to_string())?;
        drop(ready);
        let mut command = login_command(config_dir)
            .ok_or_else(|| "official Claude Code executable is unavailable".to_string())?;
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
        let _ = (operation_id, config_dir, control_fd, ready_fd);
        Err("Claude auth supervision is unsupported on this platform".to_string())
    }
}

#[cfg(unix)]
fn validate_supervisor_pipe_fds(control_fd: i32, ready_fd: i32) -> Result<(), String> {
    if control_fd < 0 || ready_fd < 0 || control_fd == ready_fd {
        return Err("Claude auth supervisor requires distinct live pipe descriptors".to_string());
    }
    for (fd, expected_access) in [(control_fd, libc::O_RDONLY), (ready_fd, libc::O_WRONLY)] {
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
        store
            .remove(
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
        if operation.mode != PersistedMode::Generic
            && transition_registry_terminal(
                &operation,
                ClaudeBrowserAuthOutcomeV1::IdentityMismatch,
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
        if let Some(operation) = state
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
        {
            if operation.outcome.is_none() {
                operation.phase = phase;
            }
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
    let process = STATE_TRANSACTION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    #[cfg(unix)]
    let file = {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(default_support_dir().join(STATE_LOCK_FILE))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        file
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(default_support_dir().join(STATE_LOCK_FILE))?;
    Ok(StateGuard {
        _process: process,
        file,
    })
}

fn operation_guard(operation_id: &str) -> std::io::Result<Option<OperationGuard>> {
    fs::create_dir_all(default_support_dir())?;
    let path = default_support_dir().join(format!("{OPERATION_LOCK_PREFIX}{operation_id}.lock"));
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(std::io::Error::last_os_error())
            };
        }
        Ok(Some(OperationGuard { file }))
    }
    #[cfg(not(unix))]
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Ok(Some(OperationGuard { file }))
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
    fs::create_dir_all(default_support_dir())?;
    let path =
        default_support_dir().join(format!("{PROVIDER_PROCESS_LOCK_PREFIX}{operation_id}.lock"));
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
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
    #[cfg(not(unix))]
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Ok(Some(ProviderProcessGuard {
            file,
            unlock_on_drop: true,
        }))
    }
}

fn provider_process_active(operation_id: &str) -> std::io::Result<bool> {
    match provider_process_guard(operation_id, true)? {
        Some(_available) => Ok(false),
        None => Ok(true),
    }
}

fn admission_guard() -> std::io::Result<AdmissionGuard> {
    let process = ADMISSION_TRANSACTION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(default_support_dir().join(ADMISSION_LOCK_FILE))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(AdmissionGuard {
            _process: process,
            file,
        })
    }
    #[cfg(not(unix))]
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(default_support_dir().join(ADMISSION_LOCK_FILE))?;
        Ok(AdmissionGuard {
            _process: process,
            file,
        })
    }
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
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ottto-claude-browser-auth-{label}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn public_metadata_contains_no_path_or_identity() {
        let operation = PersistedOperation {
            operation_id: "claude_setup_0123456789abcdef0123456789abcdef".to_string(),
            slot_id: "claude_slot_0123456789abcdef0123456789abcdef".to_string(),
            config_dir: "/private/provisional".to_string(),
            ceremony_baseline: None,
            mode: PersistedMode::Generic,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::Complete,
            outcome: Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected),
            canonical_slot_id: Some("claude_slot_fedcba9876543210fedcba9876543210".to_string()),
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: 2,
            completed_unix_seconds: Some(2),
            fallback_completed: false,
        };
        let wire = serde_json::to_string(&public_operation(&operation)).expect("serialize");
        for forbidden in [
            "config_dir",
            "/Users/",
            "account_identifier",
            "organization_identifier",
        ] {
            assert!(!wire.contains(forbidden));
        }
    }

    #[test]
    #[serial]
    fn active_replay_shortcut_requires_exact_sealed_core_sidecar_binding() {
        let root = temp_dir("active-replay-sealed-binding");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_03030303030303030303030303030303";
        let target_id = "claude_anchor_target_03030303030303030303030303030303";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let core = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some(target_id.to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("target core");
        let slot_id = core.setup_operation.slot_id.clone().expect("slot");
        let config_dir = core
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("config root");
        let base = PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: Some("baseline".to_string()),
            mode: PersistedMode::Target,
            target_id: Some(target_id.to_string()),
            expected_account_identifier_hash: Some(account),
            expected_organization_identifier_hash: Some(organization),
            phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        };
        let install = |operations: Vec<PersistedOperation>, active: Option<&str>| {
            transact(|state| {
                state.operations = operations;
                state.active_operation_id = active.map(str::to_string);
            })
            .expect("install replay case");
        };
        install(vec![base.clone()], Some(operation_id));
        assert!(active_replay_is_sealed(
            &core,
            operation_id,
            BrowserLoginMode::Target
        ));

        let mut cases = Vec::new();
        let mut changed = base.clone();
        changed.mode = PersistedMode::Reconnect;
        cases.push(("sidecar kind", core.clone(), changed, Some(operation_id)));
        let mut changed_core = core.clone();
        changed_core.setup_operation.kind =
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot;
        cases.push(("core kind", changed_core, base.clone(), Some(operation_id)));
        let mut changed = base.clone();
        changed.target_id =
            Some("claude_anchor_target_ffffffffffffffffffffffffffffffff".to_string());
        cases.push(("target", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.expected_account_identifier_hash = Some("c".repeat(64));
        cases.push(("account hash", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.expected_organization_identifier_hash = Some("d".repeat(64));
        cases.push((
            "organization hash",
            core.clone(),
            changed,
            Some(operation_id),
        ));
        let mut changed = base.clone();
        changed.slot_id = "claude_slot_ffffffffffffffffffffffffffffffff".to_string();
        cases.push(("slot", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.config_dir = format!("{config_dir}-changed");
        cases.push(("raw config root", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.ceremony_baseline = None;
        cases.push(("unsealed", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.cancel_requested = true;
        cases.push(("cancel pending", core.clone(), changed, Some(operation_id)));
        let mut changed = base.clone();
        changed.deadline_unix_seconds = 0;
        cases.push(("expired", core.clone(), changed, Some(operation_id)));
        let mut placeholder = base.clone();
        placeholder.slot_id.clear();
        placeholder.config_dir.clear();
        placeholder.ceremony_baseline = None;
        placeholder.phase = ClaudeBrowserAuthPhaseV1::Prepared;
        cases.push((
            "pre-core placeholder",
            core.clone(),
            placeholder,
            Some(operation_id),
        ));
        let mut terminal = base.clone();
        terminal.phase = ClaudeBrowserAuthPhaseV1::Complete;
        terminal.outcome = Some(ClaudeBrowserAuthOutcomeV1::LoginFailed);
        terminal.completed_unix_seconds = Some(unix_seconds());
        cases.push((
            "terminal sidecar",
            core.clone(),
            terminal,
            Some(operation_id),
        ));
        let mut terminal_core = core.clone();
        terminal_core.setup_operation.state = ClaudeAccountSetupOperationState::SetupFailed;
        cases.push((
            "terminal core",
            terminal_core,
            base.clone(),
            Some(operation_id),
        ));
        let mut wrong_operation = core.clone();
        wrong_operation.setup_operation.operation_id =
            Some("claude_setup_ffffffffffffffffffffffffffffffff".to_string());
        cases.push((
            "core operation id",
            wrong_operation,
            base.clone(),
            Some(operation_id),
        ));
        cases.push(("inactive ceremony", core.clone(), base.clone(), None));
        cases.push((
            "wrong ceremony owner",
            core.clone(),
            base.clone(),
            Some("claude_setup_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ));

        for (label, status, operation, active) in cases {
            install(vec![operation], active);
            assert!(
                !active_replay_is_sealed(&status, operation_id, BrowserLoginMode::Target),
                "{label} must not use the active replay shortcut"
            );
        }
        install(vec![base.clone(), base], Some(operation_id));
        assert!(!active_replay_is_sealed(
            &core,
            operation_id,
            BrowserLoginMode::Target
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn fallback_is_not_advertised_without_a_resolved_claude_executable() {
        let root = temp_dir("fallback-missing-executable");
        let support = root.join("support");
        let empty_bin = root.join("empty-bin");
        let home = root.join("home");
        fs::create_dir_all(&support).expect("support");
        fs::create_dir_all(&empty_bin).expect("empty bin");
        fs::create_dir_all(&home).expect("home");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &empty_bin);
        let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
        let operation_id = "claude_setup_02020202020202020202020202020202";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        let prepared = prepare_generic(status, operation_id).expect("prepare");
        start(prepared, BrowserLoginMode::Generic).expect("start worker");
        let deadline = Instant::now() + Duration::from_secs(2);
        let operation = loop {
            let operation = read_operation(operation_id).expect("operation");
            if operation.outcome.is_some() || Instant::now() >= deadline {
                break operation;
            }
            thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(
            operation.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
        );
        let public = public_operation(&operation);
        assert!(public.retryable);
        assert!(public.retry_requires_new_operation_id);
        assert!(!public.terminal_fallback_available);
        assert!(synthetic_operation(&operation).launch_command.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn retained_provisional_count_is_identifier_free_and_omitted_at_zero() {
        let root = temp_dir("retained-count-privacy");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let empty = annotate_status(
            FileClaudeConfigSlotSettingsStore::default()
                .load()
                .expect("registry"),
        );
        assert_eq!(empty.retained_provisional_login_count, None);
        assert!(!serde_json::to_string(&empty)
            .expect("empty wire")
            .contains("retained_provisional_login_count"));

        transact(|state| {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: "claude_slot_deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                config_dir: "/private/secret/customer-root".to_string(),
                service_alias: "Claude Code-credentials-deadbeef".to_string(),
                pending_registry_removal: false,
                claimed_by: None,
            });
        })
        .expect("retained root");
        let annotated = annotate_status(
            FileClaudeConfigSlotSettingsStore::default()
                .load()
                .expect("registry"),
        );
        assert_eq!(annotated.retained_provisional_login_count, Some(1));
        let wire = serde_json::to_string(&annotated).expect("wire");
        assert!(wire.contains("\"retained_provisional_login_count\":1"));
        for forbidden in [
            "deadbeef",
            "customer-root",
            "Claude Code-credentials-deadbeef",
        ] {
            assert!(!wire.contains(forbidden));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn active_browser_operation_overrides_unrelated_historical_core_status() {
        let root = temp_dir("active-sidecar-over-historical-core");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let historical_id = "claude_setup_03030303030303030303030303030303";
        let historical = store
            .prepare_managed_account_target(
                1,
                historical_id.to_string(),
                Some("claude_anchor_target_03030303030303030303030303030303".to_string()),
                Some("a".repeat(64)),
                Some("b".repeat(64)),
            )
            .expect("historical core");
        store
            .transition_setup_operation_with_binding(
                1,
                historical_id,
                historical
                    .setup_operation
                    .expected_account_identifier_hash
                    .as_deref(),
                historical
                    .setup_operation
                    .expected_organization_identifier_hash
                    .as_deref(),
                ClaudeAccountSetupOperationState::SetupFailed,
                None,
                None,
                Some("historical"),
            )
            .expect("terminal historical core");
        let historical_slot = historical
            .setup_operation
            .slot_id
            .clone()
            .expect("historical slot");
        let historical_root = historical
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == historical_slot)
            .and_then(|slot| slot.config_dir.clone())
            .expect("historical root");
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: historical_id.to_string(),
                slot_id: historical_slot,
                config_dir: historical_root,
                ceremony_baseline: None,
                mode: PersistedMode::Target,
                target_id: historical.setup_operation.target_id.clone(),
                expected_account_identifier_hash: historical
                    .setup_operation
                    .expected_account_identifier_hash
                    .clone(),
                expected_organization_identifier_hash: historical
                    .setup_operation
                    .expected_organization_identifier_hash
                    .clone(),
                phase: ClaudeBrowserAuthPhaseV1::Complete,
                outcome: Some(ClaudeBrowserAuthOutcomeV1::LoginFailed),
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: unix_seconds(),
                deadline_unix_seconds: unix_seconds(),
                completed_unix_seconds: Some(unix_seconds()),
                fallback_completed: false,
            });
        })
        .expect("matching terminal browser sidecar");
        let active_id = "claude_setup_04040404040404040404040404040404";
        prepare_generic(store.load().expect("registry"), active_id).expect("active generic");

        let annotated = annotate_status(store.load().expect("status"));
        assert_eq!(
            annotated.setup_operation.operation_id.as_deref(),
            Some(active_id)
        );
        assert!(annotated.setup_operation.browser_auth.is_some());
        assert!(request_cancel(active_id).expect("cancel request"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn pre_core_target_placeholder_with_matching_core_seals_exact_root() {
        let root = temp_dir("pre-core-target-seal");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_05050505050505050505050505050505";
        let target_id = "claude_anchor_target_05050505050505050505050505050505";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Target,
            None,
            None,
            Some(target_id),
            Some(&account),
            Some(&organization),
        )
        .expect("placeholder fence");
        let core = FileClaudeConfigSlotSettingsStore::default()
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some(target_id.to_string()),
                Some(account),
                Some(organization),
            )
            .expect("core target");
        let placeholder = read_operation(operation_id).expect("placeholder");
        assert!(placeholder.slot_id.is_empty());
        assert!(placeholder.config_dir.is_empty());

        assert_eq!(
            reconcile_pre_core_fence(&placeholder).expect("reconcile"),
            PreCoreFenceRecovery::Sealed
        );
        let sealed = read_operation(operation_id).expect("sealed fence");
        let expected_slot = core.setup_operation.slot_id.expect("core slot");
        let expected_root = core
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == expected_slot)
            .and_then(|slot| slot.config_dir.clone())
            .expect("core root");
        assert_eq!(sealed.slot_id, expected_slot);
        assert_eq!(sealed.config_dir, expected_root);
        assert!(fail_operation(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::LoginFailed
        ));
        release_ceremony(operation_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn registry_mutation_guard_prevents_recovery_from_deleting_a_committed_target() {
        let root = temp_dir("pre-core-target-serialized-replay");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_14141414141414141414141414141414";
        let target_id = "claude_anchor_target_14141414141414141414141414141414";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        let guard = registry_mutation_guard(operation_id).expect("mutation guard");
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Target,
            None,
            None,
            Some(target_id),
            Some(&account),
            Some(&organization),
        )
        .expect("placeholder fence");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let recovery_barrier = std::sync::Arc::clone(&barrier);
        let recovery_operation = operation_id.to_string();
        let recovery = thread::spawn(move || {
            recovery_barrier.wait();
            recover_operation(&recovery_operation);
        });
        barrier.wait();
        thread::sleep(PROCESS_POLL_INTERVAL + Duration::from_millis(25));
        let core = FileClaudeConfigSlotSettingsStore::default()
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some(target_id.to_string()),
                Some(account),
                Some(organization),
            )
            .expect("core commit while recovery is excluded");
        let slot_id = core.setup_operation.slot_id.clone().expect("slot");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::HideProvisionalTarget)
        );
        assert!(read_operation(operation_id).is_some());
        drop(guard);

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| operation.slot_id.is_empty())
        {
            thread::sleep(Duration::from_millis(25));
        }
        let sealed = read_operation(operation_id).expect("sealed operation");
        assert_eq!(sealed.slot_id, slot_id);
        assert!(!sealed.config_dir.is_empty());
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::HideProvisionalTarget)
        );
        assert!(request_cancel(operation_id).expect("cancel request"));
        recovery.join().expect("recovery joins after cancel");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn pre_core_target_placeholder_releases_exact_reusable_claim_without_quarantining_parent() {
        let root = temp_dir("pre-core-target-abort");
        let support = root.join("support");
        let reusable = support
            .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
            .join("claude_slot_06060606060606060606060606060606");
        fs::create_dir_all(&reusable).expect("reusable root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(
                support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
                fs::Permissions::from_mode(0o700),
            )
            .expect("managed mode");
            fs::set_permissions(&reusable, fs::Permissions::from_mode(0o700)).expect("root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_06060606060606060606060606060606";
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        transact(|state| {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: "claude_slot_06060606060606060606060606060606".to_string(),
                config_dir: reusable.to_string_lossy().into_owned(),
                service_alias: ClaudeConfigDirSlot::registered(
                    reusable.to_string_lossy().into_owned(),
                )
                .expect("slot")
                .service_name(),
                pending_registry_removal: false,
                claimed_by: Some(operation_id.to_string()),
            });
        })
        .expect("reusable journal");
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Target,
            None,
            Some(reusable.to_string_lossy().as_ref()),
            Some("claude_anchor_target_06060606060606060606060606060606"),
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
        )
        .expect("pre-core target fence");

        recover_operation(operation_id);
        let state = read_state_strict().expect("recovered state");
        assert!(state
            .operations
            .iter()
            .all(|operation| operation.operation_id != operation_id));
        assert!(state.active_operation_id.is_none());
        assert_eq!(state.quarantined_roots.len(), 1);
        assert_eq!(
            state.quarantined_roots[0].config_dir,
            reusable.to_string_lossy()
        );
        assert!(state.quarantined_roots[0].claimed_by.is_none());
        assert!(state
            .quarantined_roots
            .iter()
            .all(|candidate| { candidate.config_dir != managed_root().to_string_lossy() }));
        let retry_id = "claude_setup_07070707070707070707070707070707";
        assert!(claim_ceremony(retry_id).expect("retry claim"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn pre_core_reconnect_without_core_operation_aborts_fence_and_preserves_slot() {
        let root = temp_dir("pre-core-reconnect-abort");
        let support = root.join("support");
        let managed = support
            .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
            .join("claude_slot_08080808080808080808080808080808");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(
                support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
                fs::Permissions::from_mode(0o700),
            )
            .expect("managed mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("registered slot");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let operation_id = "claude_setup_08080808080808080808080808080808";
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Reconnect,
            Some(&slot_id),
            Some(managed.to_string_lossy().as_ref()),
            None,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
        )
        .expect("pre-core reconnect fence");

        recover_operation(operation_id);
        assert!(read_operation(operation_id).is_none());
        assert!(read_state().active_operation_id.is_none());
        let after = store.load().expect("registry after recovery");
        assert!(after
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id
                && slot.config_dir.as_deref() == Some(managed.to_string_lossy().as_ref())));
        let retry_id = "claude_setup_09090909090909090909090909090909";
        assert!(claim_ceremony(retry_id).expect("retry claim"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn failed_pre_spawn_terminalization_starts_recovery_and_releases_claim() {
        let root = temp_dir("pre-spawn-terminalization-recovery");
        let support = root.join("support");
        let managed = support
            .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
            .join("claude_slot_10101010101010101010101010101010");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(
                support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
                fs::Permissions::from_mode(0o700),
            )
            .expect("managed mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let mut status = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("registered slot");
        let slot_id = status.managed_slots[0].slot_id.clone();
        let operation_id = "claude_setup_10101010101010101010101010101010";
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Reconnect,
            Some(&slot_id),
            Some(managed.to_string_lossy().as_ref()),
            None,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
        )
        .expect("pre-core reconnect fence");
        status.setup_operation = synthetic_operation(
            &read_operation(operation_id).expect("browser reconnect operation"),
        );
        fs::remove_dir(&managed).expect("force baseline capture failure");

        assert!(start(status, BrowserLoginMode::Reconnect).is_err());
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && read_operation(operation_id).is_some() {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(read_operation(operation_id).is_none());
        assert!(read_state().active_operation_id.is_none());
        let retry_id = "claude_setup_11111111111111111111111111111111";
        assert!(claim_ceremony(retry_id).expect("recovery released ceremony"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn login_command_uses_exact_argv_cleared_env_closed_streams_and_managed_cwd() {
        let root = temp_dir("process-contract");
        let support = root.join("support");
        let managed = support
            .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
            .join("claude_slot_0123456789abcdef0123456789abcdef");
        let bin = root.join("bin");
        let effective_home = root.join("home");
        fs::create_dir_all(&managed).expect("managed root");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&effective_home).expect("home");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(
            support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
            fs::Permissions::from_mode(0o700),
        )
        .expect("managed parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("slot mode");
        let capture = root.join("capture.txt");
        let script = format!(
            "#!/bin/sh\n{{\nprintf 'argc=%s\\n' \"$#\"\nprintf 'argv=%s\\n' \"$*\"\nprintf 'config=%s\\n' \"$CLAUDE_CONFIG_DIR\"\nprintf 'home=%s\\n' \"$HOME\"\nprintf 'cwd=%s\\n' \"$PWD\"\nprintf 'provider=%s\\n' \"${{ANTHROPIC_API_KEY-unset}}\"\nprintf 'poison=%s\\n' \"${{OTTTO_SECRET_PROBE-unset}}\"\nif IFS= read -r ignored; then printf 'stdin=open\\n'; else printf 'stdin=closed\\n'; fi\n}} >> \"{}\"\n",
            capture.display()
        );
        let executable = bin.join("claude");
        fs::write(&executable, script).expect("fake claude");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("executable");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
        let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &effective_home);
        let _provider = EnvGuard::set("ANTHROPIC_API_KEY", "must-not-survive");
        let _poison = EnvGuard::set("OTTTO_SECRET_PROBE", "must-not-survive");

        let mut child = login_command(managed.to_str().expect("utf8"))
            .expect("hardened login command")
            .spawn()
            .expect("spawn");
        assert!(child.wait().expect("wait").success());
        let observed = fs::read_to_string(&capture).expect("capture");
        assert!(observed.contains("argc=3\n"));
        assert!(observed.contains("argv=auth login --claudeai\n"));
        assert!(observed.contains(&format!("config={}\n", managed.display())));
        assert!(observed.contains(&format!("home={}\n", effective_home.display())));
        let canonical_managed = fs::canonicalize(&managed).expect("canonical managed root");
        assert!(observed.contains(&format!("cwd={}\n", canonical_managed.display())));
        assert!(observed.contains("provider=unset\n"));
        assert!(observed.contains("poison=unset\n"));
        assert!(observed.contains("stdin=closed\n"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn duplicate_quarantine_never_registers_candidate_and_reuses_exact_root() {
        let root = temp_dir("duplicate-quarantine");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        fs::create_dir_all(&managed_parent).expect("managed parent");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let canonical_root = managed_parent.join("canonical");
        fs::create_dir_all(&canonical_root).expect("canonical root");
        #[cfg(unix)]
        fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700))
            .expect("canonical mode");
        let canonical = store
            .register_managed_path(1, canonical_root.to_string_lossy().into_owned())
            .expect("canonical registration");
        let canonical_slot = canonical.managed_slots[0].slot_id.clone();
        let operation_id = "claude_setup_30303030303030303030303030303030";
        let (candidate_slot, candidate_root) =
            prepare_managed_claude_provisional_root(operation_id).expect("candidate");
        let before = store.load().expect("registry before duplicate");
        assert_eq!(before.capacity.used_slots, 2);
        assert!(!before
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == candidate_slot));
        let now = unix_seconds();
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: candidate_slot.clone(),
                config_dir: candidate_root.clone(),
                ceremony_baseline: None,
                mode: PersistedMode::Generic,
                target_id: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                phase: ClaudeBrowserAuthPhaseV1::Validating,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: now,
                deadline_unix_seconds: now + 60,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("browser state");

        let operation = read_operation(operation_id).expect("operation");
        quarantine_generic_root(&operation).expect("quarantine duplicate");
        finish(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::AlreadyConnected,
            Some(canonical_slot),
        );
        let after = store.load().expect("registry after duplicate");
        assert_eq!(after.capacity.used_slots, 2);
        assert!(!after
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == candidate_slot));
        assert!(Path::new(&candidate_root).is_dir());
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::AlreadyConnected)
        );
        let reused = claim_reusable_root("claude_setup_40404040404040404040404040404040")
            .expect("claim succeeds")
            .expect("quarantined root is reusable");
        assert_eq!(reused, candidate_root);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_requires_the_same_account_and_organization() {
        let mut status = ClaudeAccountsStatusV1 {
            schema_version: 1,
            consent: ottto_protocol::ClaudeAccountUpkeepConsentState::ConsentRequired,
            setup_operation: synthetic_operation(&PersistedOperation {
                operation_id: "claude_setup_50505050505050505050505050505050".to_string(),
                slot_id: "claude_slot_50505050505050505050505050505050".to_string(),
                config_dir: "/tmp/candidate".to_string(),
                ceremony_baseline: None,
                mode: PersistedMode::Generic,
                target_id: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                phase: ClaudeBrowserAuthPhaseV1::Validating,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: 2,
                completed_unix_seconds: None,
                fallback_completed: false,
            }),
            default_slot: ClaudeConfigDirSlot::Default.descriptor(
                "default",
                ottto_protocol::ClaudeConfigSlotOwnership::External,
            ),
            managed_slots: Vec::new(),
            external_slots: Vec::new(),
            unresolved_accounts: Vec::new(),
            anchor_coverage: Default::default(),
            anchor_transitions: Vec::new(),
            capacity: ottto_protocol::ClaudeAccountCapacityV1 {
                max_slots: 10,
                used_slots: 1,
                remaining_slots: 9,
            },
            browser_auth_supported: Some(true),
            retained_provisional_login_count: None,
        };
        let mut existing = ClaudeConfigDirSlot::registered("/tmp/existing".to_string())
            .expect("descriptor")
            .descriptor(
                "claude_slot_60606060606060606060606060606060",
                ottto_protocol::ClaudeConfigSlotOwnership::Managed,
            );
        existing.collection.account_identifier_hash = Some("a".repeat(64));
        existing.collection.organization_identifier_hash = Some("b".repeat(64));
        status.managed_slots.push(existing);
        assert!(duplicate_slot_for_binding(
            &status,
            "claude_slot_50505050505050505050505050505050",
            &"a".repeat(64),
            &"b".repeat(64)
        )
        .is_some());
        assert!(duplicate_slot_for_binding(
            &status,
            "claude_slot_50505050505050505050505050505050",
            &"a".repeat(64),
            &"c".repeat(64)
        )
        .is_none());
    }

    #[test]
    #[serial]
    fn cancelled_outcome_wins_late_worker_completion() {
        let root = temp_dir("cancel-wins");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_70707070707070707070707070707070";
        let now = unix_seconds();
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: "claude_slot_70707070707070707070707070707070".to_string(),
                config_dir: support
                    .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
                    .join("claude_slot_70707070707070707070707070707070")
                    .to_string_lossy()
                    .into_owned(),
                ceremony_baseline: None,
                mode: PersistedMode::Generic,
                target_id: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: now,
                deadline_unix_seconds: now + 60,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("state");
        request_cancel(operation_id).expect("cancel request");
        finish(operation_id, ClaudeBrowserAuthOutcomeV1::Complete, None);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
        {
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn generic_prepare_is_provisional_and_does_not_consume_registry_capacity() {
        let root = temp_dir("generic-provisional");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let before = store.load().expect("before");
        let operation_id = "claude_setup_80808080808080808080808080808080";
        let prepared = prepare_generic(before.clone(), operation_id).expect("prepare generic");
        let after = store.load().expect("after");
        assert_eq!(after.capacity.used_slots, before.capacity.used_slots);
        assert!(after.managed_slots.is_empty());
        assert!(after.external_slots.is_empty());
        assert_eq!(
            prepared
                .setup_operation
                .browser_auth
                .expect("browser")
                .phase,
            ClaudeBrowserAuthPhaseV1::Prepared
        );
        let operation = read_operation(operation_id).expect("operation");
        assert_eq!(
            Path::new(&operation.config_dir)
                .file_name()
                .and_then(|name| name.to_str()),
            Some(operation.slot_id.as_str())
        );
        assert!(Path::new(&operation.config_dir).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn generic_registry_exposure_already_has_strong_composite_identity() {
        let root = temp_dir("generic-admission-order");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
        prepare_generic(store.load().expect("registry"), operation_id).expect("prepare");
        assert!(store
            .load()
            .expect("still provisional")
            .managed_slots
            .is_empty());
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let collection = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        finalize_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: account.clone(),
                organization_identifier_hash: organization.clone(),
                collection,
            },
        )
        .expect("admit");
        let exposed = crate::agent_status::annotate_claude_accounts_status(
            store.load().expect("registered status"),
        );
        assert_eq!(exposed.managed_slots.len(), 1);
        assert_eq!(
            exposed.managed_slots[0]
                .collection
                .account_identifier_hash
                .as_deref(),
            Some(account.as_str())
        );
        assert_eq!(
            exposed.managed_slots[0]
                .collection
                .organization_identifier_hash
                .as_deref(),
            Some(organization.as_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mismatch_type_distinguishes_account_organization_and_both() {
        assert_eq!(
            identity_mismatch(Some("a"), Some("o"), "b", "o"),
            Some(ClaudeBrowserAuthIdentityMismatchV1::Account)
        );
        assert_eq!(
            identity_mismatch(Some("a"), Some("o"), "a", "p"),
            Some(ClaudeBrowserAuthIdentityMismatchV1::Organization)
        );
        assert_eq!(
            identity_mismatch(Some("a"), Some("o"), "b", "p"),
            Some(ClaudeBrowserAuthIdentityMismatchV1::AccountAndOrganization)
        );
        assert_eq!(identity_mismatch(None, None, "b", "p"), None);
    }

    #[test]
    #[serial]
    fn terminal_completion_wins_late_cancel() {
        let root = temp_dir("complete-wins");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_90909090909090909090909090909090";
        let now = unix_seconds();
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: "claude_slot_90909090909090909090909090909090".to_string(),
                config_dir: "/tmp/registered".to_string(),
                ceremony_baseline: None,
                mode: PersistedMode::Reconnect,
                target_id: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                phase: ClaudeBrowserAuthPhaseV1::Reading,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: now,
                deadline_unix_seconds: now + 60,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("state");
        finish(operation_id, ClaudeBrowserAuthOutcomeV1::Complete, None);
        request_cancel(operation_id).expect("cancel request");
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::Complete)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn corrupt_state_is_never_reset_by_a_mutation() {
        let root = temp_dir("corrupt-state");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        fs::write(state_path(), b"{not-json").expect("corrupt state");
        assert!(transact(|state| state.operations.clear()).is_err());
        assert_eq!(fs::read(state_path()).expect("preserved"), b"{not-json");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn corrupt_state_prevents_provisional_root_creation() {
        let root = temp_dir("corrupt-before-root");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        fs::write(state_path(), b"{not-json").expect("corrupt state");
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        assert!(prepare_generic(status, "claude_setup_c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0").is_err());
        assert!(!managed_root().exists());
        assert_eq!(fs::read(state_path()).expect("preserved"), b"{not-json");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn ceremony_singleflight_is_idempotent_and_releases_only_owner() {
        let root = temp_dir("singleflight");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let first = "claude_setup_d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
        let second = "claude_setup_e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0";
        assert!(claim_ceremony(first).expect("first claim"));
        assert!(!claim_ceremony(first).expect("same-operation replay"));
        assert!(claim_ceremony(second).is_err());
        release_ceremony(second);
        assert!(claim_ceremony(second).is_err());
        release_ceremony(first);
        claim_ceremony(second).expect("released claim");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn same_id_cross_mode_replay_never_mutates_or_releases_original_claim() {
        let root = temp_dir("cross-mode-replay");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_25252525252525252525252525252525";
        let other_id = "claude_setup_26262626262626262626262626262626";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("generic prepare");
        assert!(preflight_browser_binding(
            operation_id,
            BrowserLoginMode::Target,
            Some("claude_slot_other"),
            Some("claude_anchor_target_other")
        )
        .is_err());
        assert!(claim_ceremony(other_id).is_err());
        let state = read_state();
        assert_eq!(state.active_operation_id.as_deref(), Some(operation_id));
        assert_eq!(
            state
                .operations
                .iter()
                .filter(|operation| operation.operation_id == operation_id)
                .count(),
            1
        );
        assert_eq!(
            read_operation(operation_id).map(|operation| operation.mode),
            Some(PersistedMode::Generic)
        );
        release_ceremony(operation_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn terminal_same_id_replay_is_read_only() {
        let root = temp_dir("terminal-replay-read-only");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        let prepared = prepare_generic(status, operation_id).expect("prepare");
        finish(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed, None);
        let before = fs::read(state_path()).expect("before replay");
        assert!(terminal_replay(prepared, operation_id).is_some());
        assert_eq!(fs::read(state_path()).expect("after replay"), before);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn quarantine_capacity_rejects_generic_before_launch_without_leaking_claim() {
        let root = temp_dir("generic-capacity-prelaunch");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        transact(|state| {
            for index in 0..MAX_QUARANTINED_ROOTS {
                state.quarantined_roots.push(QuarantinedRoot {
                    root_id: format!("claude_slot_{index:032x}"),
                    config_dir: format!("/private/provisional/{index}"),
                    service_alias: format!("service-{index}"),
                    pending_registry_removal: false,
                    claimed_by: None,
                });
            }
        })
        .expect("full quarantine");
        let operation_id = "claude_setup_a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        assert!(prepare_generic(status, operation_id).is_err());
        assert!(read_operation(operation_id).is_none());
        assert!(claim_ceremony("claude_setup_a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3").is_ok());
        assert!(!managed_root()
            .join("claude_slot_a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2")
            .exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn generic_derived_root_collision_with_canonical_registry_fails_before_creation() {
        let root = temp_dir("generic-canonical-collision");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        fs::create_dir_all(&managed_parent).expect("managed parent");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_27272727272727272727272727272727";
        let slot_id = "claude_slot_27272727272727272727272727272727";
        let exact = managed_parent.join(slot_id);
        fs::create_dir(&exact).expect("canonical root");
        #[cfg(unix)]
        fs::set_permissions(&exact, fs::Permissions::from_mode(0o700)).expect("canonical mode");
        FileClaudeConfigSlotSettingsStore::default()
            .register_managed_path_with_slot_id(
                1,
                slot_id.to_string(),
                exact.to_string_lossy().into_owned(),
            )
            .expect("canonical registration");
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        assert!(prepare_generic(status, operation_id).is_err());
        assert!(read_operation(operation_id).is_none());
        assert!(read_state().quarantined_roots.is_empty());
        assert!(
            claim_ceremony("claude_setup_28282828282828282828282828282828")
                .expect("collision released ceremony")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn concurrent_same_id_generic_prepare_persists_one_operation_and_one_root() {
        let root = temp_dir("generic-same-id-race");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_29292929292929292929292929292929";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        let first_status = status.clone();
        let second_status = status;
        let first = thread::spawn(move || prepare_generic(first_status, operation_id));
        let second = thread::spawn(move || prepare_generic(second_status, operation_id));
        assert!(first.join().expect("first thread").is_ok());
        assert!(second.join().expect("second thread").is_ok());
        let state = read_state();
        assert_eq!(
            state
                .operations
                .iter()
                .filter(|operation| operation.operation_id == operation_id)
                .count(),
            1
        );
        assert_eq!(state.quarantined_roots.len(), 1);
        assert_eq!(
            state.quarantined_roots[0].claimed_by.as_deref(),
            Some(operation_id)
        );
        release_ceremony(operation_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn recovery_retains_ceremony_while_orphan_supervisor_lock_is_held() {
        let root = temp_dir("orphan-supervisor-lock");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4";
        let retry_id = "claude_setup_a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        transact(|state| {
            let operation = state
                .operations
                .iter_mut()
                .find(|operation| operation.operation_id == operation_id)
                .expect("operation");
            operation.phase = ClaudeBrowserAuthPhaseV1::WaitingForProvider;
            operation.deadline_unix_seconds = 0;
        })
        .expect("expire operation");
        let provider = provider_process_guard(operation_id, false)
            .expect("provider lock")
            .expect("provider ownership");
        let operation = operation_id.to_string();
        let recovery = thread::spawn(move || recover_operation(&operation));
        thread::sleep(Duration::from_millis(250));
        assert!(claim_ceremony(retry_id).is_err());
        let retained = read_operation(operation_id).expect("operation retained");
        assert!(retained.outcome.is_none());
        assert_eq!(retained.phase, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
        drop(provider);
        recovery.join().expect("recovery");
        claim_ceremony(retry_id).expect("released only after provider teardown");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn failed_provider_reap_keeps_operation_and_ceremony_nonterminal() {
        use std::os::unix::process::CommandExt;

        let root = temp_dir("failed-provider-reap");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
        let retry_id = "claude_setup_afafafafafafafafafafafafafafafaf";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
        let provider = provider_process_guard(operation_id, false)
            .expect("provider lock")
            .expect("provider ownership");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exit 0")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("exited supervisor fixture");
        let process_group_id = child.id() as libc::pid_t;
        let mut supervised = SupervisedChild {
            child,
            control: None,
            process_group_id,
        };

        assert!(!supervised.cancel_and_wait(operation_id));
        assert!(read_operation(operation_id)
            .expect("operation")
            .outcome
            .is_none());
        assert!(claim_ceremony(retry_id).is_err());
        drop(provider);
        assert!(request_cancel(operation_id).expect("cancel request"));
        release_ceremony(operation_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn supervisor_entry_rejects_unbound_or_terminal_requests_before_fd_use() {
        use std::os::fd::{AsRawFd, FromRawFd};

        let root = temp_dir("supervisor-binding");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        assert!(run_auth_supervisor("../escape", "/tmp/arbitrary", -1, -1).is_err());
        assert!(run_auth_supervisor(
            "claude_setup_a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
            "/tmp/arbitrary",
            -1,
            -1,
        )
        .is_err());

        let operation_id = "claude_setup_a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Launching);
        let exact = read_operation(operation_id).expect("operation").config_dir;
        assert!(run_auth_supervisor(operation_id, "/tmp/wrong", -1, -1).is_err());
        assert!(run_auth_supervisor(operation_id, &exact, -1, -1).is_err());
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned newly-owned descriptors.
        let pipe_read = unsafe { File::from_raw_fd(pipe_fds[0]) };
        let pipe_write = unsafe { File::from_raw_fd(pipe_fds[1]) };
        assert!(run_auth_supervisor(
            operation_id,
            &exact,
            pipe_read.as_raw_fd(),
            pipe_read.as_raw_fd(),
        )
        .is_err());
        let unrelated = File::open(&exact).expect("unrelated directory descriptor");
        assert!(run_auth_supervisor(
            operation_id,
            &exact,
            unrelated.as_raw_fd(),
            pipe_write.as_raw_fd(),
        )
        .is_err());
        finish(operation_id, ClaudeBrowserAuthOutcomeV1::LoginFailed, None);
        assert!(run_auth_supervisor(operation_id, &exact, -1, -1).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn supervisor_parent_eof_kills_provider_before_releasing_lifetime_lock() {
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

        let root = temp_dir("supervisor-parent-eof");
        let support = root.join("support");
        let bin = root.join("bin");
        let home = root.join("home");
        fs::create_dir_all(&support).expect("support");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&home).expect("home");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let executable = bin.join("claude");
        fs::write(&executable, "#!/bin/sh\nexec sleep 30\n").expect("fake claude");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("fake executable mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
        let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
        let operation_id = "claude_setup_a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        set_phase(operation_id, ClaudeBrowserAuthPhaseV1::Launching);
        let config_dir = read_operation(operation_id).expect("operation").config_dir;

        let mut control_fds = [-1; 2];
        let mut ready_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(control_fds.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(ready_fds.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe calls returned newly-owned descriptors.
        let control_read = unsafe { File::from_raw_fd(control_fds[0]) };
        let control_write = unsafe { File::from_raw_fd(control_fds[1]) };
        let mut ready_read = unsafe { File::from_raw_fd(ready_fds[0]) };
        let ready_write = unsafe { File::from_raw_fd(ready_fds[1]) };
        let operation = operation_id.to_string();
        let supervisor_root = config_dir.clone();
        let supervisor = thread::spawn(move || {
            run_auth_supervisor(
                &operation,
                &supervisor_root,
                control_read.into_raw_fd(),
                ready_write.into_raw_fd(),
            )
        });
        let mut ready = [0_u8; 1];
        ready_read.read_exact(&mut ready).expect("ready");
        assert_eq!(ready, [1]);
        assert!(provider_process_active(operation_id).expect("lock state"));
        drop(control_write);
        let result = supervisor.join().expect("supervisor thread");
        assert!(result.is_ok(), "supervisor result: {result:?}");
        assert!(!provider_process_active(operation_id).expect("released lock"));
        assert!(ready_read.as_raw_fd() >= 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn provider_child_retains_lifetime_lock_after_supervisor_guard_is_gone() {
        use std::os::unix::process::CommandExt;

        let root = temp_dir("provider-inherited-lock");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9";
        let mut provider = provider_process_guard(operation_id, false)
            .expect("provider lock")
            .expect("available");
        provider
            .set_inherited_by_exec(true)
            .expect("make lock inheritable");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec sleep 30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("provider child");
        provider
            .set_inherited_by_exec(false)
            .expect("restore supervisor fd");
        provider.preserve_inherited_lock_on_drop();
        drop(provider);
        assert!(provider_process_active(operation_id).expect("child retains lock"));
        kill_owned_process(&mut child);
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline
            && provider_process_active(operation_id).expect("lock state")
        {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(!provider_process_active(operation_id).expect("released with provider exit"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn pinned_root_detects_child_and_ancestor_swaps() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("root-swap");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");
        fs::create_dir_all(&managed).expect("root");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let pinned = pin_managed_root(managed.to_str().expect("utf8")).expect("pinned root");
        let parked_support = root.join("parked-support-root");
        fs::rename(&support, &parked_support).expect("park support root");
        symlink(&parked_support, &support)
            .expect("symlink original support name to pinned ancestor inode");
        assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
        fs::remove_file(&support).expect("remove support symlink");
        fs::rename(&parked_support, &support).expect("restore support root");
        let parked = managed_parent.join("parked");
        fs::rename(&managed, &parked).expect("park old root");
        symlink(&parked, &managed).expect("symlink original child name to pinned inode");
        assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
        fs::remove_file(&managed).expect("remove child symlink");
        fs::create_dir(&managed).expect("replacement");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
        let parked_parent = support.join("parked-managed-parent");
        fs::rename(&managed_parent, &parked_parent).expect("park ancestor");
        symlink(&parked_parent, &managed_parent)
            .expect("symlink original parent name to pinned ancestor inode");
        assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
        fs::remove_file(&managed_parent).expect("remove parent symlink");
        fs::create_dir(&managed_parent).expect("replacement ancestor");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("replacement ancestor mode");
        fs::create_dir(&managed).expect("replacement child under swapped ancestor");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
            .expect("replacement child mode");
        assert!(!pinned.path_matches(managed.to_str().expect("utf8")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn unchanged_witness_cannot_finalize_recovery() {
        let root = temp_dir("witness-change");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        fs::create_dir_all(&managed).expect("root");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
            .expect("parent mode");
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let baseline =
            crate::agent_status::claude_auth_ceremony_witness(managed.to_str().expect("utf8"))
                .expect("baseline");
        let operation = PersistedOperation {
            operation_id: "claude_setup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            slot_id: "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            config_dir: managed.to_string_lossy().into_owned(),
            ceremony_baseline: Some(baseline),
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        };
        assert!(!ceremony_witness_changed(
            &operation,
            managed.to_str().expect("utf8")
        ));
        fs::write(managed.join(".claude.json"), br#"{"oauthAccount":{}}"#)
            .expect("provider identity write");
        assert!(ceremony_witness_changed(
            &operation,
            managed.to_str().expect("utf8")
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn active_cancel_reserves_root_until_worker_teardown() {
        let root = temp_dir("cancel-retry-overlap");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_12121212121212121212121212121212";
        let retry_id = "claude_setup_13131313131313131313131313131313";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        set_phase(operation_id, ClaudeBrowserAuthPhaseV1::WaitingForProvider);
        let exact = operation_config_dir(&read_operation(operation_id).expect("operation"));
        assert!(request_cancel(operation_id).expect("cancel request"));
        assert!(claim_ceremony(retry_id).is_err());
        assert!(claim_reusable_root(retry_id)
            .expect("claim check")
            .is_none());
        fail_operation(operation_id, ClaudeBrowserAuthOutcomeV1::Cancelled);
        // `fail_operation` preserves the earlier terminal CAS. Only verified
        // worker teardown releases the process-wide ceremony claim.
        release_ceremony(operation_id);
        claim_ceremony(retry_id).expect("ceremony released after teardown");
        let reused = claim_reusable_root("claude_setup_14141414141414141414141414141414")
            .expect("claim")
            .expect("released after teardown");
        assert_eq!(reused, exact);
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn cancel_intent_survives_provider_and_quarantine_cleanup_failure_until_recovery() {
        let root = temp_dir("cancel-intent-cleanup-recovery");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_15151515151515151515151515151515";
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_15151515151515151515151515151515".to_string()),
                Some("a".repeat(64)),
                Some("b".repeat(64)),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("root");
        assert!(claim_ceremony(operation_id).expect("claim ceremony"));
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.clone(),
                config_dir: config_dir.clone(),
                ceremony_baseline: Some("baseline".to_string()),
                mode: PersistedMode::Target,
                target_id: prepared.setup_operation.target_id.clone(),
                expected_account_identifier_hash: prepared
                    .setup_operation
                    .expected_account_identifier_hash
                    .clone(),
                expected_organization_identifier_hash: prepared
                    .setup_operation
                    .expected_organization_identifier_hash
                    .clone(),
                phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: u64::MAX,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
            for index in 0..MAX_QUARANTINED_ROOTS {
                state.quarantined_roots.push(QuarantinedRoot {
                    root_id: format!("claude_slot_{index:032x}"),
                    config_dir: managed_root()
                        .join(format!("claude_slot_{index:032x}"))
                        .to_string_lossy()
                        .into_owned(),
                    service_alias: format!("Claude Code-credentials-{index:032x}"),
                    pending_registry_removal: false,
                    claimed_by: None,
                });
            }
        })
        .expect("active sidecar and full quarantine");
        let provider = provider_process_guard(operation_id, false)
            .expect("provider guard")
            .expect("provider lock");

        assert!(request_cancel(operation_id).expect("cancel intent"));
        let stopping = read_operation(operation_id).expect("stopping operation");
        assert!(stopping.cancel_requested);
        assert!(stopping.outcome.is_none());
        assert!(synthetic_operation(&stopping)
            .message
            .as_deref()
            .is_some_and(|message| message.contains("Stopping Claude authentication")));
        let retry_id = "claude_setup_16161616161616161616161616161616";
        assert!(claim_ceremony(retry_id).is_err());

        drop(provider);
        thread::sleep(Duration::from_millis(300));
        let failed_cleanup = read_operation(operation_id).expect("retained cancel intent");
        assert!(failed_cleanup.cancel_requested);
        assert!(failed_cleanup.outcome.is_none());
        transact(|state| {
            state.quarantined_roots.pop();
        })
        .expect("free quarantine capacity");
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
        {
            thread::sleep(Duration::from_millis(25));
        }
        let cancelled = read_operation(operation_id).expect("cancelled operation");
        assert_eq!(
            cancelled.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
        );
        assert!(!store
            .load()
            .expect("registry")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        assert!(claim_ceremony(retry_id).expect("fresh retry after cleanup"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn browser_reconnect_cancel_never_falls_through_and_releases_after_teardown() {
        let root = temp_dir("reconnect-cancel-browser-owned");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
                .expect("managed root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("register");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let operation_id = "claude_setup_b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
        let retry_id = "claude_setup_b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3";
        let account = "a".repeat(64);
        claim_ceremony(operation_id).expect("claim");
        store
            .begin_registered_slot_reconnect(1, operation_id.to_string(), &slot_id, account.clone())
            .expect("core reconnect");
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.clone(),
                config_dir: managed.to_string_lossy().into_owned(),
                ceremony_baseline: None,
                mode: PersistedMode::Reconnect,
                target_id: None,
                expected_account_identifier_hash: Some(account.clone()),
                expected_organization_identifier_hash: None,
                phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: u64::MAX,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("sidecar reconnect");
        let provider = provider_process_guard(operation_id, false)
            .expect("provider guard")
            .expect("provider lock");
        assert!(request_cancel(operation_id).expect("cancel request"));
        assert!(claim_ceremony(retry_id).is_err());
        assert_eq!(
            store
                .setup_operation(operation_id)
                .expect("terminal core op")
                .setup_operation
                .state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        assert!(read_operation(operation_id).is_some_and(|operation| {
            operation.cancel_requested && operation.outcome.is_none()
        }));
        drop(provider);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| operation.outcome.is_none())
        {
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            store
                .setup_operation(operation_id)
                .expect("terminal core op")
                .setup_operation
                .state,
            ClaudeAccountSetupOperationState::SetupStopped
        );
        claim_ceremony(retry_id).expect("released after provider teardown");
        store
            .begin_registered_slot_reconnect(1, retry_id.to_string(), &slot_id, account)
            .expect("fresh reconnect after terminal old op");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn reconnect_collection_preserves_prior_binding_while_active_and_after_mismatch() {
        let root = temp_dir("reconnect-collection-fence");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
                .expect("managed root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("register");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
            .expect("prior canonical evidence");

        let operation_id = "claude_setup_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
        store
            .begin_registered_slot_reconnect(1, operation_id.to_string(), &slot_id, account.clone())
            .expect("core reconnect");
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.clone(),
                config_dir: managed.to_string_lossy().into_owned(),
                ceremony_baseline: None,
                mode: PersistedMode::Reconnect,
                target_id: None,
                expected_account_identifier_hash: Some(account.clone()),
                expected_organization_identifier_hash: Some(organization.clone()),
                phase: ClaudeBrowserAuthPhaseV1::WaitingForProvider,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: u64::MAX,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("sidecar reconnect");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
        );
        let active = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "active".to_string(),
            "active-expiry".to_string(),
        );
        assert_eq!(active.account_identifier_hash, Some(account.clone()));
        assert_eq!(
            active.organization_identifier_hash,
            Some(organization.clone())
        );

        finish_mismatch(
            operation_id,
            ClaudeBrowserAuthIdentityMismatchV1::Organization,
            false,
        )
        .expect("terminal mismatch");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
        );
        let terminal = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "terminal".to_string(),
            "terminal-expiry".to_string(),
        );
        assert_eq!(terminal.account_identifier_hash, Some(account));
        assert_eq!(terminal.organization_identifier_hash, Some(organization));
        let durable = crate::agent_status::annotate_claude_accounts_status(
            store.load().expect("durable prior evidence"),
        );
        let durable = durable
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("canonical reconnect slot");
        assert_eq!(durable.collection, prior);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn target_registry_exposure_is_fenced_before_sidecar_binding_is_sealed() {
        let root = temp_dir("target-pre-sidecar-fence");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let reusable = managed_parent.join("claude_slot_81818181818181818181818181818181");
        fs::create_dir_all(&reusable).expect("reusable root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
            fs::set_permissions(&reusable, fs::Permissions::from_mode(0o700))
                .expect("reusable mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_81818181818181818181818181818181";
        let target_id = "claude_anchor_target_81818181818181818181818181818181";
        let expected_account = "a".repeat(64);
        let expected_organization = "b".repeat(64);
        claim_ceremony(operation_id).expect("claim");
        transact(|state| {
            state.quarantined_roots.push(QuarantinedRoot {
                root_id: "claude_slot_81818181818181818181818181818181".to_string(),
                config_dir: reusable.to_string_lossy().into_owned(),
                service_alias: ClaudeConfigDirSlot::registered(
                    reusable.to_string_lossy().into_owned(),
                )
                .expect("slot")
                .service_name(),
                pending_registry_removal: false,
                claimed_by: Some(operation_id.to_string()),
            });
        })
        .expect("quarantine");
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Target,
            None,
            reusable.to_str(),
            Some(target_id),
            Some(&expected_account),
            Some(&expected_organization),
        )
        .expect("pre-registry fence");
        fs::write(
            reusable.join(".claude.json"),
            br#"{"oauthAccount":{"accountUuid":"wrong-account","organizationUuid":"wrong-org","emailAddress":"wrong@example.invalid"}}"#,
        )
        .expect("wrong identity");
        fs::write(
            reusable.join(".credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"fixture-wrong-token"}}"#,
        )
        .expect("wrong credential");
        let store = FileClaudeConfigSlotSettingsStore::default();
        let prepared = store
            .prepare_managed_account_target_in_reusable_root(
                1,
                operation_id.to_string(),
                Some(target_id.to_string()),
                Some(expected_account),
                Some(expected_organization),
                reusable.to_string_lossy().into_owned(),
            )
            .expect("core exposure");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        assert!(read_operation(operation_id)
            .expect("placeholder")
            .slot_id
            .is_empty());
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::HideProvisionalTarget)
        );
        let direct = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "2026-08-31T00:00:00Z".to_string(),
            "2026-08-31T00:05:00Z".to_string(),
        );
        assert!(direct.account_identifier_hash.is_none());
        assert!(direct.organization_identifier_hash.is_none());
        let _ = crate::agent_status::collect_agent_status_collection(
            &ottto_protocol::SourceKind::ClaudeCode,
            "2026-08-31T00:00:00Z".to_string(),
            "2026-08-31T00:05:00Z".to_string(),
        );
        let durable = crate::agent_status::annotate_claude_accounts_status(
            store.load().expect("post-scheduled registry"),
        );
        let collection = &durable
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("target slot")
            .collection;
        assert!(collection.account_identifier_hash.is_none());
        assert!(collection.organization_identifier_hash.is_none());
        fs::remove_dir_all(&reusable).expect("remove root before start");
        assert!(start(prepared, BrowserLoginMode::Target).is_err());
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
        );
        assert_eq!(read_state().active_operation_id, None);
        assert!(!store
            .load()
            .expect("retired target")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn reconnect_core_refresh_is_fenced_before_sidecar_start() {
        let root = temp_dir("reconnect-pre-sidecar-fence");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_82828282828282828282828282828282");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("managed mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("register");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let account = "c".repeat(64);
        let organization = "d".repeat(64);
        let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
            .expect("prior canonical evidence");
        fs::write(
            managed.join(".claude.json"),
            br#"{"oauthAccount":{"accountUuid":"wrong-account","organizationUuid":"wrong-org","emailAddress":"wrong@example.invalid"}}"#,
        )
        .expect("wrong identity");
        fs::write(
            managed.join(".credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"fixture-wrong-token"}}"#,
        )
        .expect("wrong credential");
        let operation_id = "claude_setup_82828282828282828282828282828282";
        let target_id = "claude_anchor_target_82828282828282828282828282828282";
        claim_ceremony(operation_id).expect("claim");
        persist_registry_mutation_fence(
            operation_id,
            BrowserLoginMode::Reconnect,
            Some(&slot_id),
            managed.to_str(),
            Some(target_id),
            Some(&account),
            Some(&organization),
        )
        .expect("pre-core reconnect fence");
        let reconnecting = store
            .begin_registered_slot_reconnect_target(
                1,
                operation_id.to_string(),
                &slot_id,
                Some(target_id.to_string()),
                account.clone(),
                Some(organization.clone()),
            )
            .expect("core reconnect");
        let direct = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "2026-08-31T00:00:00Z".to_string(),
            "2026-08-31T00:05:00Z".to_string(),
        );
        assert_eq!(direct, prior);
        let _ = crate::agent_status::collect_agent_status_collection(
            &ottto_protocol::SourceKind::ClaudeCode,
            "2026-08-31T00:00:00Z".to_string(),
            "2026-08-31T00:05:00Z".to_string(),
        );
        let durable = crate::agent_status::annotate_claude_accounts_status(
            store.load().expect("post-scheduled registry"),
        );
        let durable_collection = &durable
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("reconnect slot")
            .collection;
        assert_eq!(
            durable_collection.account_identifier_hash,
            prior.account_identifier_hash
        );
        assert_eq!(
            durable_collection.organization_identifier_hash,
            prior.organization_identifier_hash
        );
        assert!(durable_collection.quota_snapshot.is_none());
        fs::remove_dir_all(&managed).expect("remove root before reconnect start");
        assert!(start(reconnecting, BrowserLoginMode::Reconnect).is_err());
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
        );
        assert_eq!(read_state().active_operation_id, None);
        assert!(store
            .load()
            .expect("canonical reconnect retained")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn corrupt_or_unreadable_sidecar_preserves_registered_collection_without_probe() {
        let root = temp_dir("collection-fence-corrupt-sidecar");
        let support = root.join("support");
        let managed_parent = support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
        let managed = managed_parent.join("claude_slot_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(&managed_parent, fs::Permissions::from_mode(0o700))
                .expect("managed parent mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700))
                .expect("managed root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("register");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let account = "d".repeat(64);
        let organization = "e".repeat(64);
        let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
            .expect("prior collection");

        fs::write(state_path(), b"{corrupt").expect("corrupt sidecar");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable)
        );
        let corrupt = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "corrupt".to_string(),
            "corrupt-expiry".to_string(),
        );
        assert_eq!(corrupt.account_identifier_hash, Some(account.clone()));
        assert_eq!(
            corrupt.organization_identifier_hash,
            Some(organization.clone())
        );

        fs::remove_file(state_path()).expect("remove corrupt sidecar");
        fs::create_dir(state_path()).expect("make sidecar unreadable as a file");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::PreserveWhileStateUnavailable)
        );
        let unreadable = crate::agent_status::collect_registered_claude_slot_status(
            &slot_id,
            "unreadable".to_string(),
            "unreadable-expiry".to_string(),
        );
        assert_eq!(unreadable.account_identifier_hash, Some(account));
        assert_eq!(unreadable.organization_identifier_hash, Some(organization));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn failed_reconnect_fence_survives_trim_and_successful_reconnect_clears_it() {
        let root = temp_dir("reconnect-fence-retention");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let slot_id = "claude_slot_c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4".to_string();
        let failed_id = "claude_setup_c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let failed = PersistedOperation {
            operation_id: failed_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: "/private/reconnect".to_string(),
            ceremony_baseline: None,
            mode: PersistedMode::Reconnect,
            target_id: None,
            expected_account_identifier_hash: Some("a".repeat(64)),
            expected_organization_identifier_hash: Some("b".repeat(64)),
            phase: ClaudeBrowserAuthPhaseV1::Complete,
            outcome: Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch),
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: Some(ClaudeBrowserAuthIdentityMismatchV1::Organization),
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: 2,
            completed_unix_seconds: Some(2),
            fallback_completed: false,
        };
        transact(|state| {
            state.operations.push(failed.clone());
            for index in 0..(MAX_RETAINED_OPERATIONS + 8) {
                let mut later = failed.clone();
                later.operation_id = format!("claude_setup_{:032x}", index + 1);
                later.slot_id = format!("claude_slot_{:032x}", index + 1);
                later.mode = PersistedMode::Generic;
                later.outcome = Some(ClaudeBrowserAuthOutcomeV1::LoginFailed);
                later.identity_mismatch = None;
                later.started_unix_seconds = 3 + index as u64;
                later.completed_unix_seconds = Some(3 + index as u64);
                state.operations.push(later);
            }
            trim_operations(state);
        })
        .expect("trim fixture");
        assert!(read_operation(failed_id).is_some());
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::PreserveCanonicalReconnect)
        );

        let mut successful = failed;
        successful.operation_id = "claude_setup_c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5".to_string();
        successful.outcome = Some(ClaudeBrowserAuthOutcomeV1::Complete);
        successful.identity_mismatch = None;
        successful.started_unix_seconds = 100;
        successful.completed_unix_seconds = Some(101);
        transact(|state| {
            state.operations.push(successful);
            trim_operations(state);
        })
        .expect("successful successor");
        assert_eq!(collection_suppression(&slot_id), None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn target_success_consumes_prelaunch_quarantine_claim() {
        let root = temp_dir("target-success-consumes-claim");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1".to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("config root");
        let operation = PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir,
            ceremony_baseline: None,
            mode: PersistedMode::Target,
            target_id: prepared.setup_operation.target_id.clone(),
            expected_account_identifier_hash: Some(account.clone()),
            expected_organization_identifier_hash: Some(organization.clone()),
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        };
        transact(|state| state.operations.push(operation.clone())).expect("sidecar");
        reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
        assert_eq!(
            collection_suppression(&slot_id),
            Some(ClaudeCollectionSuppression::HideProvisionalTarget)
        );
        let collection = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        finalize_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: account,
                organization_identifier_hash: organization,
                collection,
            },
        )
        .expect("admit target");
        assert_eq!(collection_suppression(&slot_id), None);
        let state = read_state();
        assert!(!state
            .quarantined_roots
            .iter()
            .any(|root| root.claimed_by.as_deref() == Some(operation_id)));
        assert!(store
            .load()
            .expect("registry")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn target_mismatch_retires_candidate_and_preserves_exact_root_for_reuse() {
        let root = temp_dir("target-mismatch-retire");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("config root");
        let operation = PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: None,
            mode: PersistedMode::Target,
            target_id: prepared.setup_operation.target_id.clone(),
            expected_account_identifier_hash: Some(account),
            expected_organization_identifier_hash: Some(organization.clone()),
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: None,
            fallback_completed: false,
        };
        transact(|state| state.operations.push(operation.clone())).expect("sidecar");
        reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
        let wrong_account = "c".repeat(64);
        let collection = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(wrong_account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        finalize_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: wrong_account,
                organization_identifier_hash: organization,
                collection,
            },
        )
        .expect("typed mismatch");
        let registry = store.load().expect("registry");
        assert!(!registry
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        assert_eq!(registry.capacity.used_slots, 1);
        let current = read_operation(operation_id).expect("operation");
        assert_eq!(
            current.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
        );
        assert_eq!(
            current.identity_mismatch,
            Some(ClaudeBrowserAuthIdentityMismatchV1::Account)
        );
        assert!(Path::new(&config_dir).is_dir());
        let retry_id = "claude_setup_d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
        let reused = claim_reusable_root(retry_id)
            .expect("claim reusable")
            .expect("retained exact root");
        assert_eq!(reused, config_dir);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn terminal_fallback_target_mismatch_retires_root_and_persists_typed_outcome() {
        let root = temp_dir("fallback-target-mismatch");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_12121212121212121212121212121212";
        let expected_account = "a".repeat(64);
        let expected_organization = "b".repeat(64);
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_12121212121212121212121212121212".to_string()),
                Some(expected_account),
                Some(expected_organization),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("root");
        let operation = PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir: config_dir.clone(),
            ceremony_baseline: Some("baseline".to_string()),
            mode: PersistedMode::Target,
            target_id: prepared.setup_operation.target_id.clone(),
            expected_account_identifier_hash: prepared
                .setup_operation
                .expected_account_identifier_hash
                .clone(),
            expected_organization_identifier_hash: prepared
                .setup_operation
                .expected_organization_identifier_hash
                .clone(),
            phase: ClaudeBrowserAuthPhaseV1::Complete,
            outcome: Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired),
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: 1,
            deadline_unix_seconds: u64::MAX,
            completed_unix_seconds: Some(unix_seconds()),
            fallback_completed: false,
        };
        transact(|state| {
            state.active_operation_id = Some(operation_id.to_string());
            state.operations.push(operation.clone());
        })
        .expect("fallback sidecar");
        reserve_quarantine_root(&operation, false).expect("prelaunch reservation");
        let wrong_account = "c".repeat(64);
        let wrong_organization = "d".repeat(64);
        finalize_identity_mode(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: wrong_account.clone(),
                organization_identifier_hash: wrong_organization.clone(),
                collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                    account_identifier_hash: Some(wrong_account),
                    organization_identifier_hash: Some(wrong_organization),
                    ..Default::default()
                },
            },
            true,
        )
        .expect("fallback mismatch");

        let current = read_operation(operation_id).expect("terminal sidecar");
        assert_eq!(
            current.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
        );
        assert_eq!(
            current.identity_mismatch,
            Some(ClaudeBrowserAuthIdentityMismatchV1::AccountAndOrganization)
        );
        assert!(read_state().active_operation_id.is_none());
        assert!(!store
            .load()
            .expect("registry")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        assert!(read_state()
            .quarantined_roots
            .iter()
            .any(|root| { root.config_dir == config_dir && root.claimed_by.is_none() }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn terminal_fallback_reconnect_mismatch_preserves_canonical_slot_and_typed_outcome() {
        let root = temp_dir("fallback-reconnect-mismatch");
        let support = root.join("support");
        let managed = support
            .join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)
            .join("claude_slot_13131313131313131313131313131313");
        fs::create_dir_all(&managed).expect("managed root");
        #[cfg(unix)]
        {
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
            fs::set_permissions(
                support.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME),
                fs::Permissions::from_mode(0o700),
            )
            .expect("managed mode");
            fs::set_permissions(&managed, fs::Permissions::from_mode(0o700)).expect("root mode");
        }
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_managed_path(1, managed.to_string_lossy().into_owned())
            .expect("register");
        let slot_id = registered.managed_slots[0].slot_id.clone();
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let prior = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(organization.clone()),
            ..Default::default()
        };
        crate::agent_status::persist_one_claude_slot_collection_state(&slot_id, &prior)
            .expect("prior identity");
        let operation_id = "claude_setup_13131313131313131313131313131313";
        let target_id = "claude_anchor_target_13131313131313131313131313131313";
        store
            .begin_registered_slot_reconnect_target(
                1,
                operation_id.to_string(),
                &slot_id,
                Some(target_id.to_string()),
                account.clone(),
                Some(organization.clone()),
            )
            .expect("reconnect");
        transact(|state| {
            state.active_operation_id = Some(operation_id.to_string());
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.clone(),
                config_dir: managed.to_string_lossy().into_owned(),
                ceremony_baseline: Some("baseline".to_string()),
                mode: PersistedMode::Reconnect,
                target_id: Some(target_id.to_string()),
                expected_account_identifier_hash: Some(account.clone()),
                expected_organization_identifier_hash: Some(organization.clone()),
                phase: ClaudeBrowserAuthPhaseV1::Complete,
                outcome: Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired),
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: u64::MAX,
                completed_unix_seconds: Some(unix_seconds()),
                fallback_completed: false,
            });
        })
        .expect("fallback sidecar");
        let wrong_organization = "c".repeat(64);
        finalize_identity_mode(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: account,
                organization_identifier_hash: wrong_organization.clone(),
                collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                    account_identifier_hash: Some("a".repeat(64)),
                    organization_identifier_hash: Some(wrong_organization),
                    ..Default::default()
                },
            },
            true,
        )
        .expect("fallback mismatch");

        let current = read_operation(operation_id).expect("terminal sidecar");
        assert_eq!(
            current.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::IdentityMismatch)
        );
        assert_eq!(
            current.identity_mismatch,
            Some(ClaudeBrowserAuthIdentityMismatchV1::Organization)
        );
        assert!(read_state().active_operation_id.is_none());
        let registry = store.load().expect("registry");
        assert!(registry
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        assert_eq!(
            registry.setup_operation.state,
            ClaudeAccountSetupOperationState::IdentityMismatch
        );
        let durable = crate::agent_status::annotate_claude_accounts_status(registry);
        assert_eq!(
            durable
                .managed_slots
                .iter()
                .find(|slot| slot.slot_id == slot_id)
                .expect("canonical")
                .collection,
            prior
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn repeated_target_failures_reuse_exact_root_without_capacity_growth() {
        let root = temp_dir("target-failure-reuse");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let target = "claude_anchor_target_15151515151515151515151515151515";
        let first_id = "claude_setup_15151515151515151515151515151515";
        let first = store
            .prepare_managed_account_target(
                1,
                first_id.to_string(),
                Some(target.to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("first target");
        let first_slot = first.setup_operation.slot_id.clone().expect("slot");
        let exact = first
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == first_slot)
            .and_then(|slot| slot.config_dir.clone())
            .expect("root");
        let now = unix_seconds();
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: first_id.to_string(),
                slot_id: first_slot,
                config_dir: exact.clone(),
                ceremony_baseline: None,
                mode: PersistedMode::Target,
                target_id: Some(target.to_string()),
                expected_account_identifier_hash: Some(account.clone()),
                expected_organization_identifier_hash: Some(organization.clone()),
                phase: ClaudeBrowserAuthPhaseV1::Validating,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: now,
                deadline_unix_seconds: now + 60,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("first state");
        fail_operation(first_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        assert_eq!(store.load().expect("after first").capacity.used_slots, 1);

        let second_id = "claude_setup_16161616161616161616161616161616";
        let reused = claim_reusable_root(second_id)
            .expect("claim")
            .expect("reusable target root");
        assert_eq!(reused, exact);
        let second = store
            .prepare_managed_account_target_in_reusable_root(
                1,
                second_id.to_string(),
                Some(target.to_string()),
                Some(account.clone()),
                Some(organization.clone()),
                reused,
            )
            .expect("second target");
        let second_slot = second.setup_operation.slot_id.clone().expect("slot");
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: second_id.to_string(),
                slot_id: second_slot,
                config_dir: exact.clone(),
                ceremony_baseline: None,
                mode: PersistedMode::Target,
                target_id: Some(target.to_string()),
                expected_account_identifier_hash: Some(account),
                expected_organization_identifier_hash: Some(organization),
                phase: ClaudeBrowserAuthPhaseV1::Validating,
                outcome: None,
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: now,
                deadline_unix_seconds: now + 60,
                completed_unix_seconds: None,
                fallback_completed: false,
            });
        })
        .expect("second state");
        fail_operation(second_id, ClaudeBrowserAuthOutcomeV1::LoginFailed);
        assert_eq!(store.load().expect("after second").capacity.used_slots, 1);
        assert!(Path::new(&exact).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn full_quarantine_keeps_target_candidate_registered_and_tracked() {
        let root = temp_dir("target-quarantine-full");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_17171717171717171717171717171717";
        let retry_id = "claude_setup_16161616161616161616161616161616";
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_17171717171717171717171717171717".to_string()),
                Some("a".repeat(64)),
                Some("b".repeat(64)),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("root");
        let now = unix_seconds();
        let operation = PersistedOperation {
            operation_id: operation_id.to_string(),
            slot_id: slot_id.clone(),
            config_dir,
            ceremony_baseline: None,
            mode: PersistedMode::Target,
            target_id: None,
            expected_account_identifier_hash: Some("a".repeat(64)),
            expected_organization_identifier_hash: Some("b".repeat(64)),
            phase: ClaudeBrowserAuthPhaseV1::Validating,
            outcome: None,
            canonical_slot_id: None,
            admission_slot_id: None,
            identity_mismatch: None,
            cancel_requested: false,
            started_unix_seconds: now,
            deadline_unix_seconds: now + 60,
            completed_unix_seconds: None,
            fallback_completed: false,
        };
        transact(|state| {
            state.operations.push(operation.clone());
            for index in 0..MAX_QUARANTINED_ROOTS {
                state.quarantined_roots.push(QuarantinedRoot {
                    root_id: format!("claude_slot_{index:032x}"),
                    config_dir: format!("/private/quarantine/{index}"),
                    service_alias: format!("Claude Code-{index:08x}"),
                    pending_registry_removal: false,
                    claimed_by: None,
                });
            }
        })
        .expect("state");
        assert!(retire_target_candidate(&operation, true).is_err());
        assert!(store
            .load()
            .expect("registry")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        assert!(Path::new(&operation.config_dir).is_dir());
        assert!(claim_ceremony(operation_id).expect("fallback claim"));
        transact(|state| {
            let persisted = state
                .operations
                .iter_mut()
                .find(|candidate| candidate.operation_id == operation_id)
                .expect("persisted target");
            persisted.phase = ClaudeBrowserAuthPhaseV1::Complete;
            persisted.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
        })
        .expect("fallback state");
        assert!(terminalize_fallback_operation(
            &read_operation(operation_id).expect("fallback target"),
            ClaudeBrowserAuthOutcomeV1::TimedOut,
        )
        .is_err());
        assert_eq!(
            read_operation(operation_id).and_then(|candidate| candidate.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        );
        assert!(claim_ceremony(retry_id).is_err());
        assert!(store
            .load()
            .expect("failed terminalization registry")
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        release_ceremony(operation_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn full_quarantine_rejects_target_before_provider_launch_with_terminal_truth() {
        let root = temp_dir("target-prelaunch-quarantine-full");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_18181818181818181818181818181818";
        let target_id = "claude_anchor_target_18181818181818181818181818181818";
        claim_ceremony(operation_id).expect("claim");
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some(target_id.to_string()),
                Some("a".repeat(64)),
                Some("b".repeat(64)),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        transact(|state| {
            for index in 0..MAX_QUARANTINED_ROOTS {
                state.quarantined_roots.push(QuarantinedRoot {
                    root_id: format!("claude_slot_{index:032x}"),
                    config_dir: format!("/private/quarantine/{index}"),
                    service_alias: format!("Claude Code-{index:08x}"),
                    pending_registry_removal: false,
                    claimed_by: None,
                });
            }
        })
        .expect("full quarantine");
        let error = start(prepared, BrowserLoginMode::Target).expect_err("capacity rejection");
        assert!(error.contains("capacity"));
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::LoginFailed)
        );
        assert_eq!(read_state().active_operation_id, None);
        let status = store
            .setup_operation(operation_id)
            .expect("terminal core op");
        assert_eq!(
            status.setup_operation.state,
            ClaudeAccountSetupOperationState::SetupFailed
        );
        assert!(status
            .managed_slots
            .iter()
            .any(|slot| slot.slot_id == slot_id));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn initial_fallback_transition_observer_auto_completes_after_legacy_login() {
        let root = temp_dir("fallback-observer");
        let support = root.join("support");
        let bin = root.join("bin");
        let home = root.join("home");
        for directory in [&support, &bin, &home] {
            fs::create_dir_all(directory).expect("directory");
        }
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let claude = bin.join("claude");
        fs::write(
            &claude,
            r#"#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  printf '%s\n' '{"status":"authenticated","email":"fallback@example.invalid","organizationId":"organization-fallback","subscriptionType":"max"}'
  exit 0
fi
exit 1
"#,
        )
        .expect("fake claude");
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("claude mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
        let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
        let operation_id = "claude_setup_18181818181818181818181818181818";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        let operation = read_operation(operation_id).expect("operation");
        let baseline = crate::agent_status::claude_auth_ceremony_witness(&operation.config_dir)
            .expect("baseline");
        transact(|state| {
            let persisted = state
                .operations
                .iter_mut()
                .find(|candidate| candidate.operation_id == operation_id)
                .expect("persisted");
            persisted.ceremony_baseline = Some(baseline);
            persisted.phase = ClaudeBrowserAuthPhaseV1::WaitingForProvider;
        })
        .expect("baseline state");
        reserve_quarantine_root(&read_operation(operation_id).expect("operation"), false)
            .expect("reserve fallback root");
        finish(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
            None,
        );
        fs::write(
            Path::new(&operation.config_dir).join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": "account-fallback",
                    "organizationUuid": "organization-fallback",
                    "emailAddress": "fallback@example.invalid"
                }
            }))
            .expect("identity"),
        )
        .expect("identity write");
        fs::write(
            Path::new(&operation.config_dir).join(".credentials.json"),
            br#"{"claudeAiOauth":{"accessToken":"fixture-fallback-token"}}"#,
        )
        .expect("credential write");
        for _ in 0..80 {
            if read_operation(operation_id).is_some_and(|current| current.fallback_completed) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let completed = read_operation(operation_id).expect("completed operation");
        assert!(completed.fallback_completed);
        assert_eq!(
            public_operation(&completed).outcome,
            Some(ClaudeBrowserAuthOutcomeV1::Complete)
        );
        assert_eq!(
            FileClaudeConfigSlotSettingsStore::default()
                .load()
                .expect("admitted registry")
                .capacity
                .used_slots,
            2
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn fallback_terminal_replay_restores_observer_and_releases_at_deadline() {
        let root = temp_dir("fallback-replay-deadline");
        let support = root.join("support");
        let bin = root.join("bin");
        let home = root.join("home");
        fs::create_dir_all(&support).expect("support");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&home).expect("home");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let executable = bin.join("claude");
        fs::write(&executable, "#!/bin/sh\nexit 1\n").expect("fake claude");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("fake executable mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", &bin);
        let _home = EnvGuard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home);
        let operation_id = "claude_setup_e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
        let retry_id = "claude_setup_e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        let prepared = prepare_generic(status, operation_id).expect("prepare");
        transact(|state| {
            let operation = state
                .operations
                .iter_mut()
                .find(|operation| operation.operation_id == operation_id)
                .expect("operation");
            operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
            operation.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
            operation.completed_unix_seconds = Some(0);
        })
        .expect("fallback transition fixture");
        let replay = terminal_replay(prepared, operation_id).expect("terminal replay");
        assert!(replay
            .setup_operation
            .browser_auth
            .as_ref()
            .is_some_and(|browser| browser.terminal_fallback_available));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| {
                operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
            })
        {
            thread::sleep(Duration::from_millis(25));
        }
        let terminal = read_operation(operation_id).expect("terminal operation");
        assert_eq!(terminal.outcome, Some(ClaudeBrowserAuthOutcomeV1::TimedOut));
        assert!(!public_operation(&terminal).terminal_fallback_available);
        assert!(claim_ceremony(retry_id).expect("fallback deadline released ceremony"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn fallback_stop_waiting_terminalizes_before_fresh_retry() {
        let root = temp_dir("fallback-stop-waiting");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
        let retry_id = "claude_setup_d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        finish(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
            None,
        );

        assert!(request_cancel(operation_id).expect("cancel request"));
        let cancelled = read_operation(operation_id).expect("cancelled fallback");
        assert_eq!(
            cancelled.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
        );
        assert!(read_state().quarantined_roots.iter().any(|candidate| {
            candidate.root_id == cancelled.slot_id && candidate.claimed_by.is_none()
        }));
        assert!(claim_ceremony(retry_id).expect("fresh retry claim"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn terminal_fallback_recovery_retains_ceremony_for_observer() {
        let root = temp_dir("fallback-recovery-retains-claim");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
        let retry_id = "claude_setup_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        transact(|state| {
            let operation = state
                .operations
                .iter_mut()
                .find(|operation| operation.operation_id == operation_id)
                .expect("operation");
            operation.phase = ClaudeBrowserAuthPhaseV1::Complete;
            operation.outcome = Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired);
            operation.completed_unix_seconds = Some(unix_seconds());
        })
        .expect("fallback fixture");

        recover_operation(operation_id);
        assert!(claim_ceremony(retry_id).is_err());
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        );
        assert!(request_cancel(operation_id).expect("cancel request"));
        assert!(claim_ceremony(retry_id).expect("fresh claim after fallback cancel"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn fallback_state_write_failure_preserves_nonterminal_claim() {
        let root = temp_dir("fallback-state-write-failure");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
        let retry_id = "claude_setup_c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");
        finish(
            operation_id,
            ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired,
            None,
        );
        let operation = read_operation(operation_id).expect("fallback operation");
        let state = fs::read(state_path()).expect("saved state");
        fs::remove_file(state_path()).expect("remove state");
        fs::create_dir(state_path()).expect("block state write");

        assert!(
            terminalize_fallback_operation(&operation, ClaudeBrowserAuthOutcomeV1::TimedOut)
                .is_err()
        );
        fs::remove_dir(state_path()).expect("remove blocker");
        fs::write(state_path(), state).expect("restore state");
        assert_eq!(
            read_operation(operation_id).and_then(|operation| operation.outcome),
            Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        );
        assert!(claim_ceremony(retry_id).is_err());

        assert!(request_cancel(operation_id).expect("cancel request"));
        assert!(claim_ceremony(retry_id).expect("claim after ordered cancel"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn fallback_observer_noop_finalize_keeps_cancel_cleanup_claim_until_terminal() {
        let root = temp_dir("fallback-cancel-finalize-interleaving");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let store = FileClaudeConfigSlotSettingsStore::default();
        let operation_id = "claude_setup_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
        let retry_id = "claude_setup_c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        let prepared = store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3".to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("target");
        let slot_id = prepared.setup_operation.slot_id.clone().expect("slot");
        let config_dir = prepared
            .managed_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .and_then(|slot| slot.config_dir.clone())
            .expect("root");
        assert!(claim_ceremony(operation_id).expect("claim fallback ceremony"));
        transact(|state| {
            state.operations.push(PersistedOperation {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.clone(),
                config_dir,
                ceremony_baseline: Some("baseline".to_string()),
                mode: PersistedMode::Target,
                target_id: prepared.setup_operation.target_id.clone(),
                expected_account_identifier_hash: Some(account.clone()),
                expected_organization_identifier_hash: Some(organization.clone()),
                phase: ClaudeBrowserAuthPhaseV1::Complete,
                outcome: Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired),
                canonical_slot_id: None,
                admission_slot_id: None,
                identity_mismatch: None,
                cancel_requested: false,
                started_unix_seconds: 1,
                deadline_unix_seconds: u64::MAX,
                completed_unix_seconds: Some(unix_seconds()),
                fallback_completed: false,
            });
            for index in 0..MAX_QUARANTINED_ROOTS {
                state.quarantined_roots.push(QuarantinedRoot {
                    root_id: format!("claude_slot_{index:032x}"),
                    config_dir: format!("/private/quarantine/{index}"),
                    service_alias: format!("Claude Code-{index:08x}"),
                    pending_registry_removal: false,
                    claimed_by: None,
                });
            }
        })
        .expect("fallback and full quarantine");

        assert!(request_cancel(operation_id).is_err());
        let pending = read_operation(operation_id).expect("cancel-pending fallback");
        assert!(pending.cancel_requested);
        assert_eq!(
            pending.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
        );
        assert!(!finalize_observed_fallback_identity(
            operation_id,
            crate::agent_status::ClaudeLocalIdentityProof {
                account_identifier_hash: account.clone(),
                organization_identifier_hash: organization.clone(),
                collection: ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
                    account_identifier_hash: Some(account),
                    organization_identifier_hash: Some(organization),
                    ..Default::default()
                },
            },
        ));
        assert!(claim_ceremony(retry_id).is_err());

        transact(|state| {
            state.quarantined_roots.pop();
        })
        .expect("free quarantine capacity");
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline
            && read_operation(operation_id).is_some_and(|operation| {
                operation.outcome == Some(ClaudeBrowserAuthOutcomeV1::BrowserFallbackRequired)
            })
        {
            thread::sleep(Duration::from_millis(25));
        }
        let terminal = read_operation(operation_id).expect("terminal cancel");
        assert_eq!(
            terminal.outcome,
            Some(ClaudeBrowserAuthOutcomeV1::Cancelled)
        );
        assert!(claim_ceremony(retry_id).expect("claim after durable terminal cleanup"));
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn nonterminal_worker_guard_never_releases_ceremony() {
        let root = temp_dir("nonterminal-worker-guard");
        let support = root.join("support");
        fs::create_dir_all(&support).expect("support");
        #[cfg(unix)]
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("support mode");
        let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let operation_id = "claude_setup_b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
        let retry_id = "claude_setup_b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
        let status = FileClaudeConfigSlotSettingsStore::default()
            .load()
            .expect("registry");
        prepare_generic(status, operation_id).expect("prepare");

        drop(WorkerCeremonyGuard { operation_id });
        assert!(claim_ceremony(retry_id).is_err());
        assert!(request_cancel(operation_id).expect("cancel request"));
        let deadline = Instant::now() + Duration::from_secs(2);
        let acquired = loop {
            match claim_ceremony(retry_id) {
                Ok(true) => break true,
                _ if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                _ => break false,
            }
        };
        assert!(acquired, "claim after terminal cancel");
        release_ceremony(retry_id);
        let _ = fs::remove_dir_all(root);
    }
}
