//! Exact Claude Code `CLAUDE_CONFIG_DIR` slot identity and machine-local
//! registration settings.
//!
//! Claude Code derives a macOS Keychain service from the exact environment
//! string. Path cleanup that would normally look harmless (canonicalization,
//! tilde expansion, or trailing-slash removal) selects a different credential.
//! This module is the single boundary used for service names, identity files,
//! and file-backed credentials so those three views cannot drift.

use anyhow::Result;
use ottto_protocol::{
    ClaudeAccountCapacityV1, ClaudeAccountSetupOperationState, ClaudeAccountSetupOperationV1,
    ClaudeAccountUpkeepConsentState, ClaudeAccountsStatusV1, ClaudeConfigSlotCollectionStatusV1,
    ClaudeConfigSlotDescriptorV1, ClaudeConfigSlotOwnership,
    CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub const CLAUDE_OAUTH_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
pub const CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME: &str = "claude-config-slots.json";
pub const CLAUDE_MANAGED_ACCOUNTS_DIR_NAME: &str = "claude-accounts";
pub const MAX_CLAUDE_ACCOUNT_SLOTS: usize = 10;
pub const MAX_REGISTERED_CLAUDE_CONFIG_SLOTS: usize = MAX_CLAUDE_ACCOUNT_SLOTS - 1;
pub const MAX_CLAUDE_CONFIG_DIR_BYTES: usize = 4096;

static CLAUDE_CONFIG_SLOT_SETTINGS_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();
static CLAUDE_SETUP_OPERATION_LOCKS: OnceLock<Mutex<BTreeMap<String, &'static Mutex<()>>>> =
    OnceLock::new();

struct ClaudeConfigSlotSettingsTransactionGuard {
    _process_guard: std::sync::MutexGuard<'static, ()>,
    _lock_file: File,
}

pub struct ClaudeSetupOperationObservationGuard {
    _process_guard: std::sync::MutexGuard<'static, ()>,
    lock_file: File,
}

#[cfg(unix)]
impl Drop for ClaudeSetupOperationObservationGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
impl Drop for ClaudeConfigSlotSettingsTransactionGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self._lock_file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Claude Code's credential slot selector.
///
/// `Default` means `CLAUDE_CONFIG_DIR` is unset. A registered slot retains the
/// exact raw string; no path normalization is performed anywhere in this type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClaudeConfigDirSlot {
    #[default]
    Default,
    Registered {
        config_dir: String,
    },
}

impl ClaudeConfigDirSlot {
    pub fn registered(
        config_dir: impl Into<String>,
    ) -> Result<Self, ClaudeConfigSlotSettingsError> {
        let config_dir = config_dir.into();
        validate_config_dir(&config_dir)?;
        Ok(Self::Registered { config_dir })
    }

    pub fn config_dir(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Registered { config_dir } => Some(config_dir),
        }
    }

    /// Claude Code's exact macOS generic-password service name.
    ///
    /// Custom slots hash NFC text, but the stored/path value remains the
    /// original string. The suffix is the first eight lowercase hexadecimal
    /// characters of SHA-256.
    pub fn service_name(&self) -> String {
        match self {
            Self::Default => CLAUDE_OAUTH_KEYCHAIN_SERVICE.to_string(),
            Self::Registered { config_dir } => {
                let normalized: String = config_dir.nfc().collect();
                let digest = Sha256::digest(normalized.as_bytes());
                let suffix = format!("{digest:x}");
                format!("{CLAUDE_OAUTH_KEYCHAIN_SERVICE}-{}", &suffix[..8])
            }
        }
    }

    /// Plaintext Claude account identity associated with this credential slot.
    pub fn identity_path(&self, home: &Path) -> PathBuf {
        match self {
            Self::Default => home.join(".claude.json"),
            Self::Registered { config_dir } => PathBuf::from(config_dir).join(".claude.json"),
        }
    }

    /// File-backed credential location used on platforms where Claude Code
    /// does not use the macOS Keychain. This is read-only in Ottto.
    pub fn credentials_path(&self, home: &Path) -> PathBuf {
        match self {
            Self::Default => home.join(".claude").join(".credentials.json"),
            Self::Registered { config_dir } => PathBuf::from(config_dir).join(".credentials.json"),
        }
    }

    pub fn descriptor(
        &self,
        slot_id: impl Into<String>,
        ownership: ClaudeConfigSlotOwnership,
    ) -> ClaudeConfigSlotDescriptorV1 {
        ClaudeConfigSlotDescriptorV1 {
            slot_id: slot_id.into(),
            ownership,
            config_dir: self.config_dir().map(ToString::to_string),
            service_name: self.service_name(),
            collection: ClaudeConfigSlotCollectionStatusV1::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ClaudeConfigSlotSettingsError {
    #[error("invalid Claude config-slot settings: {0}")]
    Invalid(String),
    #[error("Claude config-slot settings state is unavailable: {0}")]
    State(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeConfigSlotSettingsV1 {
    schema_version: u16,
    background_upkeep_consent: bool,
    #[serde(default)]
    registered_slots: Vec<PersistedClaudeConfigSlotV1>,
    #[serde(default)]
    setup_operations: Vec<PersistedClaudeAccountSetupOperationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeConfigSlotV1 {
    slot_id: String,
    ownership: ClaudeConfigSlotOwnership,
    config_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeAccountSetupOperationV1 {
    operation_id: String,
    slot_id: String,
    config_dir: String,
    state: ClaudeAccountSetupOperationState,
    /// Immutable prepare-request binding used for idempotent replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_expected_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Default for PersistedClaudeConfigSlotSettingsV1 {
    fn default() -> Self {
        Self {
            schema_version: CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            background_upkeep_consent: false,
            registered_slots: Vec::new(),
            setup_operations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileClaudeConfigSlotSettingsStore {
    path: PathBuf,
}

impl FileClaudeConfigSlotSettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        let persisted = self.load_persisted()?;
        Ok(status_contract(&persisted))
    }

    pub fn set_upkeep_consent(
        &self,
        schema_version: u16,
        consent: bool,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        self.transact(schema_version, |settings| {
            settings.background_upkeep_consent = consent;
            Ok(())
        })
    }

    pub fn register_path(
        &self,
        schema_version: u16,
        config_dir: String,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        self.register_path_with_ownership(
            schema_version,
            config_dir,
            ClaudeConfigSlotOwnership::External,
        )
    }

    pub fn register_managed_path(
        &self,
        schema_version: u16,
        config_dir: String,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        self.register_path_with_ownership(
            schema_version,
            config_dir,
            ClaudeConfigSlotOwnership::Managed,
        )
    }

    /// Create and register one private managed directory as a single
    /// daemon-owned transaction. Repeating an operation id returns the same
    /// slot and exact launch command, repairing a missing empty directory but
    /// never selecting a new path.
    pub fn prepare_managed_account(
        &self,
        schema_version: u16,
        operation_id: String,
        expected_account_identifier_hash: Option<String>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(&operation_id)?;
        validate_expected_account_hash(expected_account_identifier_hash.as_deref())?;
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;

        if let Some(existing) = persisted
            .setup_operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
            .cloned()
        {
            if existing.requested_expected_account_identifier_hash
                != expected_account_identifier_hash
            {
                return Err(ClaudeConfigSlotSettingsError::Invalid(
                    "setup operation expected account does not match its original binding"
                        .to_string(),
                ));
            }
            if let Some(slot) = persisted
                .registered_slots
                .iter()
                .find(|slot| slot.slot_id == existing.slot_id)
            {
                if slot.ownership != ClaudeConfigSlotOwnership::Managed
                    || slot.config_dir != existing.config_dir
                {
                    return Err(ClaudeConfigSlotSettingsError::State(
                        "setup operation no longer names its managed slot".to_string(),
                    ));
                }
                ensure_managed_directory(Path::new(&slot.config_dir))?;
                if existing.state == ClaudeAccountSetupOperationState::SetupStopped {
                    let operation = persisted
                        .setup_operations
                        .iter_mut()
                        .find(|candidate| candidate.operation_id == operation_id)
                        .expect("existing operation remains present");
                    operation.state = ClaudeAccountSetupOperationState::WaitingForUserLogin;
                    operation.message = Some(
                        "Setup observation resumed for this same registered Claude Code directory."
                            .to_string(),
                    );
                    self.write_persisted(&persisted)?;
                }
                return Ok(status_contract_for_operation(&persisted, &operation_id));
            }
            if !matches!(
                existing.state,
                ClaudeAccountSetupOperationState::Preparing
                    | ClaudeAccountSetupOperationState::SetupStopped
            ) {
                return Err(ClaudeConfigSlotSettingsError::State(
                    "setup operation registration is missing".to_string(),
                ));
            }
            if existing.state == ClaudeAccountSetupOperationState::SetupStopped {
                let operation = persisted
                    .setup_operations
                    .iter_mut()
                    .find(|candidate| candidate.operation_id == operation_id)
                    .expect("existing operation remains present");
                operation.state = ClaudeAccountSetupOperationState::Preparing;
                operation.message =
                    Some("Resuming the same private Claude Code directory.".to_string());
                self.write_persisted(&persisted)?;
            }
            return self.finalize_preparing_operation(&mut persisted, &operation_id);
        }

        let reserved_slots = persisted.registered_slots.len()
            + persisted
                .setup_operations
                .iter()
                .filter(|operation| {
                    !persisted
                        .registered_slots
                        .iter()
                        .any(|slot| slot.slot_id == operation.slot_id)
                })
                .count();
        if reserved_slots >= MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
            return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
                "at most {MAX_REGISTERED_CLAUDE_CONFIG_SLOTS} registered config dirs are allowed"
            )));
        }
        let slot_id = generate_opaque_slot_id()?;
        let managed_root = self.managed_accounts_root()?;
        ensure_managed_directory(&managed_root)?;
        let config_dir_path = managed_root.join(&slot_id);
        let config_dir = config_dir_path.to_str().ok_or_else(|| {
            ClaudeConfigSlotSettingsError::State(
                "managed Claude account root is not valid UTF-8".to_string(),
            )
        })?;
        validate_registered_config_dir(config_dir)?;
        persisted
            .setup_operations
            .push(PersistedClaudeAccountSetupOperationV1 {
                operation_id: operation_id.clone(),
                slot_id,
                config_dir: config_dir.to_string(),
                state: ClaudeAccountSetupOperationState::Preparing,
                requested_expected_account_identifier_hash: expected_account_identifier_hash
                    .clone(),
                expected_account_identifier_hash,
                account_identifier_hash: None,
                message: Some("Preparing a private Claude Code directory.".to_string()),
            });
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        self.finalize_preparing_operation(&mut persisted, &operation_id)
    }

    pub fn setup_operation(
        &self,
        operation_id: &str,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let persisted = self.load_persisted()?;
        require_setup_operation(&persisted, operation_id)?;
        Ok(status_contract_for_operation(&persisted, operation_id))
    }

    /// Claim the exact operation's validation/read side effects without
    /// waiting. A concurrent caller receives `None` and can render persisted
    /// progress without launching another credential or provider probe.
    pub fn try_setup_operation_observation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ClaudeSetupOperationObservationGuard>, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let process_lock = {
            let mut locks = CLAUDE_SETUP_OPERATION_LOCKS
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .map_err(|_| {
                    ClaudeConfigSlotSettingsError::State(
                        "setup operation lock registry is poisoned".to_string(),
                    )
                })?;
            *locks
                .entry(operation_id.to_string())
                .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
        };
        let process_guard = match process_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(ClaudeConfigSlotSettingsError::State(
                    "setup operation observation lock is poisoned".to_string(),
                ))
            }
        };
        let support_root = self.path.parent().ok_or_else(|| {
            ClaudeConfigSlotSettingsError::State(
                "Claude config-slot settings path has no support root".to_string(),
            )
        })?;
        ensure_managed_directory(support_root)?;
        let digest = Sha256::digest(operation_id.as_bytes());
        let lock_path = support_root.join(format!(".claude-account-check-{digest:x}.lock"));
        #[cfg(unix)]
        let lock_file = {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(lock_path)
                .map_err(|error| {
                    ClaudeConfigSlotSettingsError::State(format!(
                        "open setup observation lock: {error}"
                    ))
                })?;
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(ClaudeConfigSlotSettingsError::State(format!(
                    "lock setup observation: {error}"
                )));
            }
            file
        };
        #[cfg(not(unix))]
        let lock_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)
            .map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!(
                    "open setup observation lock: {error}"
                ))
            })?;
        Ok(Some(ClaudeSetupOperationObservationGuard {
            _process_guard: process_guard,
            lock_file,
        }))
    }

    pub fn transition_setup_operation(
        &self,
        schema_version: u16,
        operation_id: &str,
        expected_account_identifier_hash: Option<&str>,
        state: ClaudeAccountSetupOperationState,
        account_identifier_hash: Option<&str>,
        message: Option<&str>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        validate_expected_account_hash(expected_account_identifier_hash)?;
        validate_expected_account_hash(account_identifier_hash)?;
        self.transact_for_operation(schema_version, operation_id, |operation| {
            if operation.state == ClaudeAccountSetupOperationState::SetupStopped {
                return Ok(());
            }
            match (
                operation.expected_account_identifier_hash.as_deref(),
                expected_account_identifier_hash,
            ) {
                (Some(bound), Some(requested)) if bound != requested => {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "setup operation expected account does not match its original binding"
                            .to_string(),
                    ));
                }
                (None, Some(requested)) => {
                    operation.expected_account_identifier_hash = Some(requested.to_string());
                }
                _ => {}
            }
            if let (Some(bound), Some(observed)) = (
                operation.expected_account_identifier_hash.as_deref(),
                account_identifier_hash,
            ) {
                if bound != observed {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "setup operation observed account does not match its binding".to_string(),
                    ));
                }
            }
            if operation.expected_account_identifier_hash.is_none() {
                operation.expected_account_identifier_hash =
                    account_identifier_hash.map(ToString::to_string);
            }
            operation.state = state;
            operation.account_identifier_hash = account_identifier_hash.map(ToString::to_string);
            operation.message = message.map(ToString::to_string);
            Ok(())
        })
    }

    pub fn stop_waiting(
        &self,
        schema_version: u16,
        operation_id: &str,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;
        let registered = {
            let operation = require_setup_operation(&persisted, operation_id)?;
            persisted
                .registered_slots
                .iter()
                .any(|slot| slot.slot_id == operation.slot_id)
        };
        let operation = persisted
            .setup_operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .expect("validated setup operation remains present");
        if operation.state != ClaudeAccountSetupOperationState::Complete {
            if !registered {
                // Cleanup is empty-only. If Claude wrote anything during the
                // crash window, preserve it for the deterministic resume.
                let _ = fs::remove_dir(Path::new(&operation.config_dir));
            }
            operation.state = ClaudeAccountSetupOperationState::SetupStopped;
            operation.message = Some(
                "Ottto stopped observing this setup. Replay prepare to resume the same private directory."
                    .to_string(),
            );
        }
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract_for_operation(&persisted, operation_id))
    }

    fn register_path_with_ownership(
        &self,
        schema_version: u16,
        config_dir: String,
        ownership: ClaudeConfigSlotOwnership,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_registered_config_dir(&config_dir)?;
        let slot_id = generate_opaque_slot_id()?;
        self.transact(schema_version, move |settings| {
            settings.registered_slots.push(PersistedClaudeConfigSlotV1 {
                slot_id,
                ownership,
                config_dir,
            });
            Ok(())
        })
    }

    pub fn remove(
        &self,
        schema_version: u16,
        slot_id: &str,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        if slot_id == "default" {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "the implicit default Claude slot cannot be removed".to_string(),
            ));
        }
        self.transact(schema_version, |settings| {
            let index = settings
                .registered_slots
                .iter()
                .position(|slot| slot.slot_id == slot_id)
                .ok_or_else(|| {
                    ClaudeConfigSlotSettingsError::Invalid(format!(
                        "unknown Claude account slot_id {slot_id}"
                    ))
                })?;
            settings.registered_slots.remove(index);
            settings
                .setup_operations
                .retain(|operation| operation.slot_id != slot_id);
            Ok(())
        })
    }

    fn load_persisted(
        &self,
    ) -> Result<PersistedClaudeConfigSlotSettingsV1, ClaudeConfigSlotSettingsError> {
        let persisted = if self.path.exists() {
            let body = fs::read_to_string(&self.path).map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!("read settings: {error}"))
            })?;
            serde_json::from_str::<PersistedClaudeConfigSlotSettingsV1>(&body).map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!("parse settings: {error}"))
            })?
        } else {
            PersistedClaudeConfigSlotSettingsV1::default()
        };
        validate_persisted(&persisted)?;
        Ok(persisted)
    }

    fn transact(
        &self,
        schema_version: u16,
        mutation: impl FnOnce(
            &mut PersistedClaudeConfigSlotSettingsV1,
        ) -> Result<(), ClaudeConfigSlotSettingsError>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;
        mutation(&mut persisted)?;
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    fn transact_for_operation(
        &self,
        schema_version: u16,
        operation_id: &str,
        mutation: impl FnOnce(
            &mut PersistedClaudeAccountSetupOperationV1,
        ) -> Result<(), ClaudeConfigSlotSettingsError>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;
        let operation = persisted
            .setup_operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id)
            .ok_or_else(|| {
                ClaudeConfigSlotSettingsError::Invalid(format!(
                    "unknown Claude setup operation_id {operation_id}"
                ))
            })?;
        mutation(operation)?;
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract_for_operation(&persisted, operation_id))
    }

    fn write_persisted(
        &self,
        persisted: &PersistedClaudeConfigSlotSettingsV1,
    ) -> Result<(), ClaudeConfigSlotSettingsError> {
        let body = serde_json::to_vec_pretty(persisted).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("serialize settings: {error}"))
        })?;
        crate::write_owner_only_file_atomic(&self.path, &body).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("write settings: {error}"))
        })
    }

    fn finalize_preparing_operation(
        &self,
        persisted: &mut PersistedClaudeConfigSlotSettingsV1,
        operation_id: &str,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        let operation = require_setup_operation(persisted, operation_id)?.clone();
        if operation.state != ClaudeAccountSetupOperationState::Preparing {
            return Err(ClaudeConfigSlotSettingsError::State(
                "Claude setup operation is not preparing".to_string(),
            ));
        }
        let config_dir_path = PathBuf::from(&operation.config_dir);
        let created = create_managed_slot_directory(&config_dir_path)?;
        persisted
            .registered_slots
            .push(PersistedClaudeConfigSlotV1 {
                slot_id: operation.slot_id.clone(),
                ownership: ClaudeConfigSlotOwnership::Managed,
                config_dir: operation.config_dir.clone(),
            });
        let mutable = persisted
            .setup_operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation_id)
            .expect("validated setup operation must remain present");
        mutable.state = ClaudeAccountSetupOperationState::WaitingForUserLogin;
        mutable.message = Some(
            "Open official Claude Code with this exact command, then type /login.".to_string(),
        );
        validate_persisted(persisted)?;
        if let Err(error) = self.write_persisted(persisted) {
            if created {
                // Empty-only cleanup. Non-empty directories and credentials
                // are never removed by a failed preparation.
                let _ = fs::remove_dir(&config_dir_path);
            }
            return Err(error);
        }
        Ok(status_contract_for_operation(persisted, operation_id))
    }

    fn managed_accounts_root(&self) -> Result<PathBuf, ClaudeConfigSlotSettingsError> {
        let support_root = self.path.parent().ok_or_else(|| {
            ClaudeConfigSlotSettingsError::State(
                "Claude config-slot settings path has no support root".to_string(),
            )
        })?;
        if !support_root.is_absolute() {
            return Err(ClaudeConfigSlotSettingsError::State(
                "Claude config-slot support root must be absolute".to_string(),
            ));
        }
        Ok(support_root.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME))
    }

    fn settings_transaction_lock(
        &self,
    ) -> Result<ClaudeConfigSlotSettingsTransactionGuard, ClaudeConfigSlotSettingsError> {
        let process_guard = CLAUDE_CONFIG_SLOT_SETTINGS_TRANSACTION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| {
                ClaudeConfigSlotSettingsError::State(
                    "settings transaction lock is poisoned".to_string(),
                )
            })?;
        let support_root = self.path.parent().ok_or_else(|| {
            ClaudeConfigSlotSettingsError::State(
                "Claude config-slot settings path has no support root".to_string(),
            )
        })?;
        if !support_root.is_absolute() {
            return Err(ClaudeConfigSlotSettingsError::State(
                "Claude config-slot support root must be absolute".to_string(),
            ));
        }
        ensure_managed_directory(support_root)?;
        let lock_path = support_root.join(".claude-config-slots.lock");
        #[cfg(unix)]
        let lock_file = {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path)
                .map_err(|error| {
                    ClaudeConfigSlotSettingsError::State(format!(
                        "open Claude config-slot transaction lock: {error}"
                    ))
                })?;
            let lock_result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if lock_result != 0 {
                return Err(ClaudeConfigSlotSettingsError::State(format!(
                    "lock Claude config-slot transaction: {}",
                    std::io::Error::last_os_error()
                )));
            }
            file
        };
        #[cfg(not(unix))]
        let lock_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!(
                    "open Claude config-slot transaction lock: {error}"
                ))
            })?;
        Ok(ClaudeConfigSlotSettingsTransactionGuard {
            _process_guard: process_guard,
            _lock_file: lock_file,
        })
    }
}

impl Default for FileClaudeConfigSlotSettingsStore {
    fn default() -> Self {
        Self::new(crate::default_support_dir().join(CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME))
    }
}

fn validate_persisted(
    settings: &PersistedClaudeConfigSlotSettingsV1,
) -> Result<(), ClaudeConfigSlotSettingsError> {
    validate_schema_version(settings.schema_version)?;
    if settings.registered_slots.len() > MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "at most {MAX_REGISTERED_CLAUDE_CONFIG_SLOTS} registered config dirs are allowed"
        )));
    }
    let mut exact_values = BTreeSet::new();
    let mut service_names = BTreeSet::new();
    let mut slot_ids = BTreeSet::new();
    for registered in &settings.registered_slots {
        validate_opaque_slot_id(&registered.slot_id)?;
        validate_registered_config_dir(&registered.config_dir)?;
        let slot = ClaudeConfigDirSlot::registered(registered.config_dir.clone())?;
        if !slot_ids.insert(registered.slot_id.as_str()) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "registered Claude slot ids must be unique".to_string(),
            ));
        }
        if !exact_values.insert(registered.config_dir.as_str()) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "registered config dirs must be unique exact strings".to_string(),
            ));
        }
        if !service_names.insert(slot.service_name()) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "registered config dirs must resolve to distinct Claude credential services"
                    .to_string(),
            ));
        }
    }
    if settings.setup_operations.len() > MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude setup operation count exceeds capacity".to_string(),
        ));
    }
    let mut operation_ids = BTreeSet::new();
    let registered_slot_ids = settings
        .registered_slots
        .iter()
        .map(|slot| slot.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    for operation in &settings.setup_operations {
        validate_setup_operation_id(&operation.operation_id)?;
        validate_opaque_slot_id(&operation.slot_id)?;
        validate_registered_config_dir(&operation.config_dir)?;
        validate_expected_account_hash(
            operation
                .requested_expected_account_identifier_hash
                .as_deref(),
        )?;
        validate_expected_account_hash(operation.expected_account_identifier_hash.as_deref())?;
        validate_expected_account_hash(operation.account_identifier_hash.as_deref())?;
        if !operation_ids.insert(operation.operation_id.as_str()) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "Claude setup operation ids must be unique".to_string(),
            ));
        }
        if !registered_slot_ids.contains(operation.slot_id.as_str())
            && !matches!(
                operation.state,
                ClaudeAccountSetupOperationState::Preparing
                    | ClaudeAccountSetupOperationState::SetupStopped
            )
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "only a preparing Claude setup operation may precede registration".to_string(),
            ));
        }
        if let Some(slot) = settings
            .registered_slots
            .iter()
            .find(|slot| slot.slot_id == operation.slot_id)
        {
            if slot.ownership != ClaudeConfigSlotOwnership::Managed
                || slot.config_dir != operation.config_dir
            {
                return Err(ClaudeConfigSlotSettingsError::Invalid(
                    "Claude setup operation must match its managed registration".to_string(),
                ));
            }
        }
    }
    let preparing_count = settings
        .setup_operations
        .iter()
        .filter(|operation| !registered_slot_ids.contains(operation.slot_id.as_str()))
        .count();
    if settings.registered_slots.len() + preparing_count > MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude registered and preparing slots exceed capacity".to_string(),
        ));
    }
    Ok(())
}

fn require_setup_operation<'a>(
    settings: &'a PersistedClaudeConfigSlotSettingsV1,
    operation_id: &str,
) -> Result<&'a PersistedClaudeAccountSetupOperationV1, ClaudeConfigSlotSettingsError> {
    settings
        .setup_operations
        .iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or_else(|| {
            ClaudeConfigSlotSettingsError::Invalid(format!(
                "unknown Claude setup operation_id {operation_id}"
            ))
        })
}

fn validate_schema_version(schema_version: u16) -> Result<(), ClaudeConfigSlotSettingsError> {
    if schema_version != CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "unsupported schema_version {schema_version}; expected {CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn validate_config_dir(config_dir: &str) -> Result<(), ClaudeConfigSlotSettingsError> {
    if config_dir.is_empty() {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "registered config dir cannot be empty".to_string(),
        ));
    }
    if config_dir.len() > MAX_CLAUDE_CONFIG_DIR_BYTES {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "registered config dir exceeds {MAX_CLAUDE_CONFIG_DIR_BYTES} bytes"
        )));
    }
    if config_dir.contains('\0') {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "registered config dir cannot contain NUL".to_string(),
        ));
    }
    Ok(())
}

fn validate_registered_config_dir(config_dir: &str) -> Result<(), ClaudeConfigSlotSettingsError> {
    validate_config_dir(config_dir)?;
    if !Path::new(config_dir).is_absolute() {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "registered Claude config dir must be an absolute path".to_string(),
        ));
    }
    Ok(())
}

fn generate_opaque_slot_id() -> Result<String, ClaudeConfigSlotSettingsError> {
    let token = crate::generate_control_token().map_err(|error| {
        ClaudeConfigSlotSettingsError::State(format!("generate Claude slot id: {error}"))
    })?;
    Ok(format!("claude_slot_{}", &token[..32]))
}

fn validate_opaque_slot_id(slot_id: &str) -> Result<(), ClaudeConfigSlotSettingsError> {
    let Some(suffix) = slot_id.strip_prefix("claude_slot_") else {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "registered Claude slot id has an unsupported shape".to_string(),
        ));
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "registered Claude slot id has an unsupported shape".to_string(),
        ));
    }
    Ok(())
}

fn validate_setup_operation_id(operation_id: &str) -> Result<(), ClaudeConfigSlotSettingsError> {
    validate_prefixed_opaque_id(operation_id, "claude_setup_", "setup operation")
}

fn validate_prefixed_opaque_id(
    value: &str,
    prefix: &str,
    label: &str,
) -> Result<(), ClaudeConfigSlotSettingsError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "Claude {label} id has an unsupported shape"
        )));
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "Claude {label} id has an unsupported shape"
        )));
    }
    Ok(())
}

fn validate_expected_account_hash(
    account_hash: Option<&str>,
) -> Result<(), ClaudeConfigSlotSettingsError> {
    let Some(account_hash) = account_hash else {
        return Ok(());
    };
    if account_hash.len() != 64
        || !account_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "expected Claude account hash must be a strong lowercase SHA-256 value".to_string(),
        ));
    }
    Ok(())
}

fn ensure_managed_directory(path: &Path) -> Result<(), ClaudeConfigSlotSettingsError> {
    match create_private_directory(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(ClaudeConfigSlotSettingsError::State(format!(
                "create managed Claude account directory: {error}"
            )));
        }
    }
    verify_private_directory_descriptor(path)
}

fn create_managed_slot_directory(path: &Path) -> Result<bool, ClaudeConfigSlotSettingsError> {
    match create_private_directory(path) {
        Ok(()) => {
            verify_private_directory_descriptor(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_managed_directory(path)?;
            Ok(false)
        }
        Err(error) => Err(ClaudeConfigSlotSettingsError::State(format!(
            "create managed Claude account slot: {error}"
        ))),
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn verify_private_directory_descriptor(path: &Path) -> Result<(), ClaudeConfigSlotSettingsError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!(
                    "open managed Claude account directory without following links: {error}"
                ))
            })?;
        let fd = directory.as_raw_fd();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(ClaudeConfigSlotSettingsError::State(format!(
                "inspect managed Claude account directory descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(ClaudeConfigSlotSettingsError::State(
                "managed Claude account path is not an owner-controlled directory".to_string(),
            ));
        }
        if unsafe { libc::fchmod(fd, 0o700) } != 0 {
            return Err(ClaudeConfigSlotSettingsError::State(format!(
                "protect managed Claude account directory descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut verified = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, verified.as_mut_ptr()) } != 0 {
            return Err(ClaudeConfigSlotSettingsError::State(format!(
                "recheck managed Claude account directory descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        let verified = unsafe { verified.assume_init() };
        if verified.st_mode & 0o777 != 0o700 {
            return Err(ClaudeConfigSlotSettingsError::State(
                "managed Claude account directory is not owner-only".to_string(),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!(
                "inspect managed Claude account directory: {error}"
            ))
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(ClaudeConfigSlotSettingsError::State(
                "managed Claude account path is not a real directory".to_string(),
            ));
        }
    }
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn launch_command(config_dir: &str) -> String {
    format!(
        "CLAUDE_CONFIG_DIR={} claude",
        shell_single_quote(config_dir)
    )
}

fn status_contract(persisted: &PersistedClaudeConfigSlotSettingsV1) -> ClaudeAccountsStatusV1 {
    status_contract_with_selected_operation(persisted, None)
}

fn status_contract_for_operation(
    persisted: &PersistedClaudeConfigSlotSettingsV1,
    operation_id: &str,
) -> ClaudeAccountsStatusV1 {
    status_contract_with_selected_operation(persisted, Some(operation_id))
}

fn status_contract_with_selected_operation(
    persisted: &PersistedClaudeConfigSlotSettingsV1,
    selected_operation_id: Option<&str>,
) -> ClaudeAccountsStatusV1 {
    let mut managed_slots = Vec::new();
    let mut external_slots = Vec::new();
    for registered in &persisted.registered_slots {
        let Ok(slot) = ClaudeConfigDirSlot::registered(registered.config_dir.clone()) else {
            continue;
        };
        let descriptor = slot.descriptor(registered.slot_id.clone(), registered.ownership);
        match registered.ownership {
            ClaudeConfigSlotOwnership::Managed => managed_slots.push(descriptor),
            ClaudeConfigSlotOwnership::External => external_slots.push(descriptor),
        }
    }
    let used_slots = 1 + managed_slots.len() + external_slots.len();
    let selected_operation = selected_operation_id
        .and_then(|operation_id| {
            persisted
                .setup_operations
                .iter()
                .find(|operation| operation.operation_id == operation_id)
        })
        .or_else(|| persisted.setup_operations.last());
    let setup_operation = selected_operation
        .map(|operation| {
            let config_dir = persisted
                .registered_slots
                .iter()
                .find(|slot| slot.slot_id == operation.slot_id)
                .map(|slot| slot.config_dir.as_str())
                .unwrap_or(operation.config_dir.as_str());
            ClaudeAccountSetupOperationV1 {
                state: operation.state.clone(),
                operation_id: Some(operation.operation_id.clone()),
                slot_id: Some(operation.slot_id.clone()),
                expected_account_identifier_hash: operation
                    .expected_account_identifier_hash
                    .clone(),
                account_identifier_hash: operation.account_identifier_hash.clone(),
                launch_command: Some(launch_command(config_dir)),
                message: operation.message.clone(),
            }
        })
        .unwrap_or(ClaudeAccountSetupOperationV1 {
            state: ClaudeAccountSetupOperationState::Idle,
            operation_id: None,
            slot_id: None,
            expected_account_identifier_hash: None,
            account_identifier_hash: None,
            launch_command: None,
            message: None,
        });
    ClaudeAccountsStatusV1 {
        schema_version: persisted.schema_version,
        consent: if persisted.background_upkeep_consent {
            ClaudeAccountUpkeepConsentState::Granted
        } else {
            ClaudeAccountUpkeepConsentState::ConsentRequired
        },
        setup_operation,
        default_slot: ClaudeConfigDirSlot::Default
            .descriptor("default", ClaudeConfigSlotOwnership::External),
        managed_slots,
        external_slots,
        unresolved_accounts: Vec::new(),
        capacity: ClaudeAccountCapacityV1 {
            max_slots: MAX_CLAUDE_ACCOUNT_SLOTS as u8,
            used_slots: used_slots as u8,
            remaining_slots: (MAX_CLAUDE_ACCOUNT_SLOTS - used_slots) as u8,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "ottto-claude-config-slots-{label}-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ))
            .join("settings.json")
    }

    #[test]
    fn default_and_registered_service_names_match_claude_code() {
        assert_eq!(
            ClaudeConfigDirSlot::Default.service_name(),
            "Claude Code-credentials"
        );
        assert_eq!(
            ClaudeConfigDirSlot::registered("/Users/test/.claude")
                .expect("slot")
                .service_name(),
            "Claude Code-credentials-462977e4"
        );
        assert_eq!(
            ClaudeConfigDirSlot::registered("/Users/test/.claude-work")
                .expect("slot")
                .service_name(),
            "Claude Code-credentials-03abf0ee"
        );
        assert_eq!(
            ClaudeConfigDirSlot::registered("/Users/example/.claude-w3-quota-probe")
                .expect("independent synthetic vector")
                .service_name(),
            "Claude Code-credentials-f6139299"
        );
    }

    #[test]
    fn hashing_uses_nfc_but_never_normalizes_the_registered_path() {
        let composed = ClaudeConfigDirSlot::registered("/tmp/caf\u{e9}").expect("composed");
        let decomposed = ClaudeConfigDirSlot::registered("/tmp/cafe\u{301}").expect("decomposed");
        assert_eq!(composed.service_name(), decomposed.service_name());
        assert_ne!(composed.config_dir(), decomposed.config_dir());
        assert_eq!(
            decomposed.identity_path(Path::new("/unused")),
            PathBuf::from("/tmp/cafe\u{301}/.claude.json")
        );
    }

    #[test]
    fn low_level_hashing_keeps_relative_spelling_but_registration_requires_absolute_paths() {
        let plain = ClaudeConfigDirSlot::registered("/Users/test/.claude-work").expect("slot");
        let slash = ClaudeConfigDirSlot::registered("/Users/test/.claude-work/").expect("slot");
        assert_eq!(slash.service_name(), "Claude Code-credentials-8bd6f0f5");
        assert_ne!(plain.service_name(), slash.service_name());

        let relative = ClaudeConfigDirSlot::registered("../claude").expect("slot");
        assert_eq!(relative.config_dir(), Some("../claude"));
        assert_eq!(
            relative.identity_path(Path::new("/unused")),
            PathBuf::from("../claude/.claude.json")
        );

        let path = temp_path("relative-registration");
        let store = FileClaudeConfigSlotSettingsStore::new(path);
        assert!(matches!(
            store.register_path(1, "../claude".to_string()),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
    }

    #[test]
    fn settings_default_to_consent_required_with_the_bare_slot() {
        let path = temp_path("default");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let settings = store.load().expect("load default");
        assert_eq!(settings.schema_version, 1);
        assert_eq!(
            settings.consent,
            ClaudeAccountUpkeepConsentState::ConsentRequired
        );
        assert_eq!(
            settings.setup_operation.state,
            ClaudeAccountSetupOperationState::Idle
        );
        assert_eq!(
            settings.default_slot,
            ClaudeConfigDirSlot::Default.descriptor("default", ClaudeConfigSlotOwnership::External)
        );
        assert!(settings.managed_slots.is_empty());
        assert!(settings.external_slots.is_empty());
        assert!(settings.unresolved_accounts.is_empty());
        assert_eq!(settings.capacity.max_slots, 10);
        assert_eq!(settings.capacity.used_slots, 1);
        assert_eq!(settings.capacity.remaining_slots, 9);
    }

    #[test]
    fn mutations_round_trip_exact_strings_and_owner_only_permissions() {
        let path = temp_path("round-trip");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        store
            .register_path(1, "/tmp/claude-work/".to_string())
            .expect("register first");
        let saved = store
            .register_managed_path(1, "/tmp/claude-personal".to_string())
            .expect("register managed");
        assert_eq!(saved.external_slots.len(), 1);
        assert_eq!(saved.managed_slots.len(), 1);
        assert_eq!(
            saved.external_slots[0].ownership,
            ClaudeConfigSlotOwnership::External
        );
        assert_eq!(
            saved.managed_slots[0].ownership,
            ClaudeConfigSlotOwnership::Managed
        );
        assert!(saved.external_slots[0].slot_id.starts_with("claude_slot_"));
        assert_ne!(saved.external_slots[0].slot_id, "registered:03abf0ee");
        assert_eq!(
            saved.consent,
            ClaudeAccountUpkeepConsentState::ConsentRequired
        );
        let saved = store.set_upkeep_consent(1, true).expect("grant consent");
        assert_eq!(saved.consent, ClaudeAccountUpkeepConsentState::Granted);
        assert_eq!(store.load().expect("reload"), saved);
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read file")).expect("json");
        assert_eq!(
            persisted["registered_slots"][0]["config_dir"],
            serde_json::json!("/tmp/claude-work/")
        );
        assert_eq!(persisted["registered_slots"][0]["ownership"], "external");
        assert_eq!(persisted["registered_slots"][1]["ownership"], "managed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }
        let removed = store
            .remove(1, &saved.external_slots[0].slot_id)
            .expect("remove first");
        assert_eq!(removed.managed_slots.len(), 1);
        assert!(removed.external_slots.is_empty());
        assert_eq!(removed.capacity.used_slots, 2);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn mutations_reject_schema_duplicates_service_aliases_and_default_removal() {
        let path = temp_path("invalid");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        assert!(matches!(
            store.set_upkeep_consent(2, true),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        store.register_path(1, "/tmp/a".to_string()).expect("first");
        assert!(matches!(
            store.register_path(1, "/tmp/a".to_string()),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        store
            .register_path(1, "/tmp/caf\u{e9}".to_string())
            .expect("composed");
        assert!(matches!(
            store.register_path(1, "/tmp/cafe\u{301}".to_string()),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.remove(1, "default"),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.remove(1, "registered:missing"),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn registry_capacity_is_default_plus_nine_custom_slots() {
        let path = temp_path("capacity");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        for index in 0..MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
            store
                .register_path(1, format!("/tmp/claude-{index}"))
                .expect("within capacity");
        }
        let full = store.load().expect("full status");
        assert_eq!(full.capacity.used_slots, 10);
        assert_eq!(full.capacity.remaining_slots, 0);
        assert!(matches!(
            store.register_path(1, "/tmp/claude-overflow".to_string()),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn concurrent_mutations_do_not_lose_registered_paths() {
        let path = temp_path("concurrent");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let workers: Vec<_> = (0..MAX_REGISTERED_CLAUDE_CONFIG_SLOTS)
            .map(|index| {
                let store = store.clone();
                std::thread::spawn(move || {
                    store.register_path(1, format!("/tmp/claude-concurrent-{index}"))
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker").expect("register");
        }
        let status = store.load().expect("status");
        assert_eq!(status.external_slots.len(), 9);
        assert!(status.managed_slots.is_empty());
        assert_eq!(status.capacity.used_slots, 10);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn managed_prepare_is_0700_exact_idempotent_and_repairs_a_missing_directory() {
        let path = temp_path("managed-prepare-quote'");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let operation_id = "claude_setup_0123456789abcdef0123456789abcdef";
        let expected = "a".repeat(64);
        let prepared = store
            .prepare_managed_account(1, operation_id.to_string(), Some(expected.clone()))
            .expect("prepare");
        assert_eq!(
            prepared.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        assert_eq!(prepared.managed_slots.len(), 1);
        assert!(prepared.external_slots.is_empty());
        let slot = &prepared.managed_slots[0];
        let config_dir = slot.config_dir.as_deref().expect("managed exact path");
        assert!(config_dir.starts_with(root.to_str().expect("utf8 root")));
        assert_eq!(
            prepared.setup_operation.launch_command.as_deref(),
            Some(
                format!(
                    "CLAUDE_CONFIG_DIR={} claude",
                    shell_single_quote(config_dir)
                )
                .as_str()
            )
        );
        assert!(!prepared
            .setup_operation
            .launch_command
            .as_deref()
            .expect("launch command")
            .contains("login"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(config_dir)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        let again = store
            .prepare_managed_account(1, operation_id.to_string(), Some(expected))
            .expect("idempotent prepare");
        assert_eq!(
            again.setup_operation.slot_id,
            prepared.setup_operation.slot_id
        );
        assert_eq!(
            again.setup_operation.launch_command,
            prepared.setup_operation.launch_command
        );

        fs::remove_dir(config_dir).expect("remove empty managed directory");
        assert!(!Path::new(config_dir).exists());
        let repaired = store
            .prepare_managed_account(1, operation_id.to_string(), Some("a".repeat(64)))
            .expect("repair same operation directory");
        assert_eq!(
            repaired.setup_operation.slot_id,
            prepared.setup_operation.slot_id
        );
        assert!(Path::new(config_dir).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn setup_operation_binds_first_strong_account_retries_and_stop_preserves_registration() {
        let path = temp_path("setup-state-machine");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let operation_id = "claude_setup_11111111111111111111111111111111";
        let account_hash = "b".repeat(64);
        let waiting = store
            .prepare_managed_account(1, operation_id.to_string(), None)
            .expect("prepare without expected account");
        let config_dir = waiting.managed_slots[0]
            .config_dir
            .clone()
            .expect("managed dir");
        let validating = store
            .transition_setup_operation(
                1,
                operation_id,
                None,
                ClaudeAccountSetupOperationState::Validating,
                None,
                None,
            )
            .expect("validating");
        assert_eq!(
            validating.setup_operation.state,
            ClaudeAccountSetupOperationState::Validating
        );
        let reading = store
            .transition_setup_operation(
                1,
                operation_id,
                None,
                ClaudeAccountSetupOperationState::Reading,
                Some(&account_hash),
                None,
            )
            .expect("bind first strong account");
        assert_eq!(
            reading
                .setup_operation
                .expected_account_identifier_hash
                .as_deref(),
            Some(account_hash.as_str())
        );
        assert!(store
            .transition_setup_operation(
                1,
                operation_id,
                None,
                ClaudeAccountSetupOperationState::Reading,
                Some(&"c".repeat(64)),
                None,
            )
            .is_err());
        let stopped = store
            .stop_waiting(1, operation_id)
            .expect("stop observation");
        assert_eq!(
            stopped.setup_operation.state,
            ClaudeAccountSetupOperationState::SetupStopped
        );
        assert!(Path::new(&config_dir).is_dir());
        let queued_check = store
            .transition_setup_operation(
                1,
                operation_id,
                Some(&account_hash),
                ClaudeAccountSetupOperationState::Validating,
                None,
                None,
            )
            .expect("stopped operation remains durable");
        assert_eq!(
            queued_check.setup_operation.state,
            ClaudeAccountSetupOperationState::SetupStopped
        );
        let resumed = store
            .prepare_managed_account(1, operation_id.to_string(), None)
            .expect("explicit prepare replay resumes operation");
        assert_eq!(
            resumed.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        store
            .transition_setup_operation(
                1,
                operation_id,
                Some(&account_hash),
                ClaudeAccountSetupOperationState::Validating,
                Some(&account_hash),
                None,
            )
            .expect("validate resumed operation");
        let complete = store
            .transition_setup_operation(
                1,
                operation_id,
                Some(&account_hash),
                ClaudeAccountSetupOperationState::Complete,
                Some(&account_hash),
                None,
            )
            .expect("complete");
        let still_complete = store
            .stop_waiting(1, operation_id)
            .expect("stop after complete");
        assert_eq!(still_complete.setup_operation, complete.setup_operation);

        let slot_id = complete
            .setup_operation
            .slot_id
            .as_deref()
            .expect("slot id");
        let removed = store.remove(1, slot_id).expect("remove registration");
        assert_eq!(
            removed.setup_operation.state,
            ClaudeAccountSetupOperationState::Idle
        );
        assert!(Path::new(&config_dir).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_prepare_operation_is_concurrent_and_capacity_safe() {
        let path = temp_path("managed-concurrent");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let workers = (0..8)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || {
                    store.prepare_managed_account(
                        1,
                        "claude_setup_22222222222222222222222222222222".to_string(),
                        None,
                    )
                })
            })
            .collect::<Vec<_>>();
        let mut slot_ids = BTreeSet::new();
        for worker in workers {
            let status = worker.join().expect("worker").expect("prepare");
            slot_ids.insert(status.setup_operation.slot_id.expect("slot id"));
        }
        assert_eq!(slot_ids.len(), 1);
        let status = store.load().expect("status");
        assert_eq!(status.managed_slots.len(), 1);
        assert_eq!(status.capacity.used_slots, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_settings_and_downgrade_rewrite_preserve_managed_directory() {
        let path = temp_path("managed-downgrade");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let prepared = store
            .prepare_managed_account(
                1,
                "claude_setup_33333333333333333333333333333333".to_string(),
                None,
            )
            .expect("prepare");
        let config_dir = prepared.managed_slots[0]
            .config_dir
            .clone()
            .expect("managed dir");
        let mut persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read settings")).expect("json");
        persisted
            .as_object_mut()
            .expect("object")
            .remove("setup_operations");
        crate::write_owner_only_file_atomic(
            &path,
            &serde_json::to_vec_pretty(&persisted).expect("legacy settings"),
        )
        .expect("simulate old daemon rewrite");
        let downgraded = store.load().expect("load legacy-compatible settings");
        assert_eq!(
            downgraded.setup_operation.state,
            ClaudeAccountSetupOperationState::Idle
        );
        assert_eq!(downgraded.managed_slots.len(), 1);
        assert!(Path::new(&config_dir).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_persisted_prepare_is_visible_stoppable_and_resumes_same_path() {
        let path = temp_path("managed-crash-intent");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).expect("support root");
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let operation_id = "claude_setup_44444444444444444444444444444444";
        let slot_id = "claude_slot_44444444444444444444444444444444";
        let config_dir = root.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME).join(slot_id);
        let persisted = PersistedClaudeConfigSlotSettingsV1 {
            setup_operations: vec![PersistedClaudeAccountSetupOperationV1 {
                operation_id: operation_id.to_string(),
                slot_id: slot_id.to_string(),
                config_dir: config_dir.to_string_lossy().into_owned(),
                state: ClaudeAccountSetupOperationState::Preparing,
                requested_expected_account_identifier_hash: None,
                expected_account_identifier_hash: None,
                account_identifier_hash: None,
                message: Some("Preparing".to_string()),
            }],
            ..Default::default()
        };
        store
            .write_persisted(&persisted)
            .expect("persist crash intent");

        let visible = store.setup_operation(operation_id).expect("visible intent");
        assert_eq!(
            visible.setup_operation.state,
            ClaudeAccountSetupOperationState::Preparing
        );
        assert_eq!(visible.setup_operation.slot_id.as_deref(), Some(slot_id));
        assert!(visible.setup_operation.launch_command.is_some());
        assert_eq!(
            visible.capacity.used_slots, 1,
            "unregistered intent is reserved, not registered"
        );

        fs::create_dir_all(&config_dir).expect("simulate mkdir crash window");
        let stopped = store.stop_waiting(1, operation_id).expect("stop intent");
        assert_eq!(
            stopped.setup_operation.state,
            ClaudeAccountSetupOperationState::SetupStopped
        );
        assert!(
            !config_dir.exists(),
            "still-empty daemon directory is cleaned up"
        );

        let restarted = FileClaudeConfigSlotSettingsStore::new(&path)
            .prepare_managed_account(1, operation_id.to_string(), None)
            .expect("resume exact intent");
        assert_eq!(restarted.setup_operation.slot_id.as_deref(), Some(slot_id));
        assert_eq!(
            restarted.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        assert!(config_dir.is_dir());
        assert_eq!(restarted.capacity.used_slots, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn multiprocess_settings_child() {
        let Ok(settings_path) = std::env::var("OTTTO_TEST_CLAUDE_SETTINGS_CHILD_PATH") else {
            return;
        };
        let config_dir =
            std::env::var("OTTTO_TEST_CLAUDE_SETTINGS_CHILD_CONFIG").expect("child config path");
        FileClaudeConfigSlotSettingsStore::new(settings_path)
            .register_path(1, config_dir)
            .expect("cross-process registration");
    }

    #[test]
    fn multiprocess_settings_lock_prevents_lost_updates_and_enforces_capacity() {
        let path = temp_path("multiprocess-settings");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let executable = std::env::current_exe().expect("test executable");
        let mut children = Vec::new();
        for index in 0..MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
            children.push(
                std::process::Command::new(&executable)
                    .args([
                        "--exact",
                        "claude_config_slots::tests::multiprocess_settings_child",
                        "--nocapture",
                    ])
                    .env("OTTTO_TEST_CLAUDE_SETTINGS_CHILD_PATH", &path)
                    .env(
                        "OTTTO_TEST_CLAUDE_SETTINGS_CHILD_CONFIG",
                        format!("/tmp/claude-process-{index}"),
                    )
                    .spawn()
                    .expect("spawn settings child"),
            );
        }
        for mut child in children {
            assert!(child.wait().expect("wait child").success());
        }
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        assert_eq!(store.load().expect("status").external_slots.len(), 9);
        assert!(store
            .register_path(1, "/tmp/claude-process-overflow".to_string())
            .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn managed_prepare_rejects_symlinked_root_without_changing_target_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let path = temp_path("managed-symlink-root");
        let root = path.parent().expect("parent");
        let target = root.join("outside-target");
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(&target).expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("target mode");
        symlink(&target, root.join(CLAUDE_MANAGED_ACCOUNTS_DIR_NAME)).expect("symlink root");
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        assert!(store
            .prepare_managed_account(
                1,
                "claude_setup_55555555555555555555555555555555".to_string(),
                None,
            )
            .is_err());
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(fs::read_dir(&target)
            .expect("target readable")
            .next()
            .is_none());
        let _ = fs::remove_dir_all(root);
    }
}
