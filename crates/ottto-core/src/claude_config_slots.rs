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
    ClaudeAccountAnchorCoverageV1, ClaudeAccountCapacityV1, ClaudeAccountSetupOperationKind,
    ClaudeAccountSetupOperationState, ClaudeAccountSetupOperationV1,
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
const CLAUDE_RETIRED_RECONNECT_FILTER_FILE_SUFFIX: &str = "reconnect-retired-v1.json";
pub const CLAUDE_MANAGED_ACCOUNTS_DIR_NAME: &str = "claude-accounts";
pub const MAX_CLAUDE_ACCOUNT_SLOTS: usize = 10;
pub const MAX_REGISTERED_CLAUDE_CONFIG_SLOTS: usize = MAX_CLAUDE_ACCOUNT_SLOTS - 1;
pub const MAX_CLAUDE_CONFIG_DIR_BYTES: usize = 4096;
const RETIRED_RECONNECT_FILTER_WORDS: usize = 512;
const RETIRED_RECONNECT_FILTER_HASHES: usize = 8;
const CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION: u16 = 2;

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
    /// Kept outside the legacy setup array so an older daemon ignores
    /// reconnect observation state while still loading every registration.
    #[serde(default)]
    reconnect_operations: Vec<PersistedClaudeAccountSetupOperationV1>,
    /// Fixed-size fail-closed Bloom filter for operation ids retired after a
    /// terminal reconnect or slot removal. False positives only refuse a new
    /// id; a retired id can never be rebound while storage remains bounded.
    #[serde(default)]
    retired_reconnect_operation_filter: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeConfigSlotV1 {
    slot_id: String,
    ownership: ClaudeConfigSlotOwnership,
    config_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeAccountSetupOperationV1 {
    #[serde(default)]
    kind: ClaudeAccountSetupOperationKind,
    /// Monotonic creation order across managed setup and reconnect arrays.
    /// Legacy rows decode as zero; a new row always sorts after them.
    #[serde(default)]
    created_sequence: u64,
    operation_id: String,
    slot_id: String,
    config_dir: String,
    state: ClaudeAccountSetupOperationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_id: Option<String>,
    /// Immutable prepare-request binding used for idempotent replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_expected_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_expected_organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Default for PersistedClaudeConfigSlotSettingsV1 {
    fn default() -> Self {
        Self {
            schema_version: CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION,
            background_upkeep_consent: false,
            registered_slots: Vec::new(),
            setup_operations: Vec::new(),
            reconnect_operations: Vec::new(),
            retired_reconnect_operation_filter: Vec::new(),
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

    /// Inspect the current registry while holding the same process and
    /// cross-process transaction lock used by consent/registration mutations.
    /// This lets a caller serialize a final consent check with a bounded
    /// operation start without exposing persisted internals.
    pub fn with_locked_status<T>(
        &self,
        inspect: impl FnOnce(&ClaudeAccountsStatusV1) -> T,
    ) -> Result<T, ClaudeConfigSlotSettingsError> {
        let _transaction = self.settings_transaction_lock()?;
        let persisted = self.load_persisted()?;
        Ok(inspect(&status_contract(&persisted)))
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
        self.prepare_managed_account_target(
            schema_version,
            operation_id,
            None,
            expected_account_identifier_hash,
            None,
        )
    }

    pub fn prepare_managed_account_target(
        &self,
        schema_version: u16,
        operation_id: String,
        target_id: Option<String>,
        expected_account_identifier_hash: Option<String>,
        expected_organization_identifier_hash: Option<String>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(&operation_id)?;
        validate_expected_account_hash(expected_account_identifier_hash.as_deref())?;
        validate_expected_account_hash(expected_organization_identifier_hash.as_deref())?;
        validate_anchor_target_binding(
            target_id.as_deref(),
            expected_account_identifier_hash.as_deref(),
            expected_organization_identifier_hash.as_deref(),
        )?;
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;

        if persisted
            .reconnect_operations
            .iter()
            .any(|operation| operation.operation_id == operation_id)
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "setup operation id is already bound to a reconnect".to_string(),
            ));
        }

        if let Some(existing) = persisted
            .setup_operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
            .cloned()
        {
            if existing.target_id != target_id
                || existing.requested_expected_account_identifier_hash
                    != expected_account_identifier_hash
                || existing.requested_expected_organization_identifier_hash
                    != expected_organization_identifier_hash
            {
                return Err(ClaudeConfigSlotSettingsError::Invalid(
                    "setup operation target does not match its original strong binding".to_string(),
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
                    reject_other_nonterminal_operation(&persisted, &operation_id)?;
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
                reject_other_nonterminal_operation(&persisted, &operation_id)?;
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

        if reconnect_operation_id_is_retired(&persisted, &operation_id) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "setup operation id was retired by reconnect and cannot be rebound".to_string(),
            ));
        }
        reject_other_nonterminal_operation(&persisted, &operation_id)?;

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
        let created_sequence = next_operation_sequence(&persisted);
        persisted
            .setup_operations
            .push(PersistedClaudeAccountSetupOperationV1 {
                kind: ClaudeAccountSetupOperationKind::ConnectManagedAccount,
                created_sequence,
                operation_id: operation_id.clone(),
                slot_id,
                config_dir: config_dir.to_string(),
                state: ClaudeAccountSetupOperationState::Preparing,
                target_id,
                requested_expected_account_identifier_hash: expected_account_identifier_hash
                    .clone(),
                requested_expected_organization_identifier_hash:
                    expected_organization_identifier_hash.clone(),
                expected_account_identifier_hash,
                expected_organization_identifier_hash,
                account_identifier_hash: None,
                organization_identifier_hash: None,
                message: Some("Preparing a private Claude Code directory.".to_string()),
            });
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        self.finalize_preparing_operation(&mut persisted, &operation_id)
    }

    /// Start or replay customer-owned official login for one exact registered
    /// custom slot. Unlike managed prepare, this never allocates or creates a
    /// path. The immutable operation binding makes restart, stop, and check
    /// use the same descriptor without relying on a caller-supplied path.
    pub fn begin_registered_slot_reconnect(
        &self,
        schema_version: u16,
        operation_id: String,
        slot_id: &str,
        expected_account_identifier_hash: String,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        self.begin_registered_slot_reconnect_target(
            schema_version,
            operation_id,
            slot_id,
            None,
            expected_account_identifier_hash,
            None,
        )
    }

    pub fn begin_registered_slot_reconnect_target(
        &self,
        schema_version: u16,
        operation_id: String,
        slot_id: &str,
        target_id: Option<String>,
        expected_account_identifier_hash: String,
        expected_organization_identifier_hash: Option<String>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(&operation_id)?;
        validate_opaque_slot_id(slot_id)?;
        validate_expected_account_hash(Some(&expected_account_identifier_hash))?;
        validate_expected_account_hash(expected_organization_identifier_hash.as_deref())?;
        validate_anchor_target_binding(
            target_id.as_deref(),
            Some(&expected_account_identifier_hash),
            expected_organization_identifier_hash.as_deref(),
        )?;
        let _transaction = self.settings_transaction_lock()?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;

        if persisted
            .setup_operations
            .iter()
            .any(|operation| operation.operation_id == operation_id)
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "reconnect operation id is already bound to managed setup".to_string(),
            ));
        }
        if let Some(existing) = persisted
            .reconnect_operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
            .cloned()
        {
            if existing.kind != ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
                || existing.slot_id != slot_id
                || existing.target_id != target_id
                || existing
                    .requested_expected_account_identifier_hash
                    .as_deref()
                    != Some(expected_account_identifier_hash.as_str())
                || existing
                    .requested_expected_organization_identifier_hash
                    .as_deref()
                    != expected_organization_identifier_hash.as_deref()
            {
                return Err(ClaudeConfigSlotSettingsError::Invalid(
                    "reconnect operation does not match its original slot/account binding"
                        .to_string(),
                ));
            }
            let slot = persisted
                .registered_slots
                .iter()
                .find(|slot| slot.slot_id == existing.slot_id)
                .ok_or_else(|| {
                    ClaudeConfigSlotSettingsError::Invalid(
                        "reconnect slot is no longer registered".to_string(),
                    )
                })?;
            if slot.config_dir != existing.config_dir {
                return Err(ClaudeConfigSlotSettingsError::State(
                    "reconnect operation no longer names its exact registered slot".to_string(),
                ));
            }
            if existing.state == ClaudeAccountSetupOperationState::SetupStopped {
                reject_other_nonterminal_operation(&persisted, &operation_id)?;
                let operation = persisted
                    .reconnect_operations
                    .iter_mut()
                    .find(|candidate| candidate.operation_id == operation_id)
                    .expect("existing reconnect remains present");
                operation.state = ClaudeAccountSetupOperationState::WaitingForUserLogin;
                operation.message = Some(
                    "Reconnect observation resumed for this same registered Claude Code directory."
                        .to_string(),
                );
                self.write_persisted(&persisted)?;
            }
            return Ok(status_contract_for_operation(&persisted, &operation_id));
        }
        if reconnect_operation_id_is_retired(&persisted, &operation_id) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "reconnect operation id was retired and cannot be rebound".to_string(),
            ));
        }
        reject_other_nonterminal_operation(&persisted, &operation_id)?;

        let slot = persisted
            .registered_slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .cloned()
            .ok_or_else(|| {
                ClaudeConfigSlotSettingsError::Invalid(format!(
                    "unknown registered Claude account slot_id {slot_id}"
                ))
            })?;
        if let Some(existing) = persisted.setup_operations.iter().find(|operation| {
            operation.slot_id == slot_id && !operation_allows_reconnect_successor(operation)
        }) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
                "slot already has persisted operation {}; replay that operation id",
                existing.operation_id
            )));
        }
        if let Some(existing) = persisted
            .reconnect_operations
            .iter()
            .find(|operation| operation.slot_id == slot_id)
            .cloned()
        {
            if !operation_allows_reconnect_successor(&existing) {
                return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
                    "slot already has active reconnect operation {}; replay that operation id",
                    existing.operation_id
                )));
            }
            retire_reconnect_operation_id(&mut persisted, &existing.operation_id);
            persisted
                .reconnect_operations
                .retain(|operation| operation.operation_id != existing.operation_id);
        }
        let created_sequence = next_operation_sequence(&persisted);
        persisted
            .reconnect_operations
            .push(PersistedClaudeAccountSetupOperationV1 {
                kind: ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot,
                created_sequence,
                operation_id: operation_id.clone(),
                slot_id: slot.slot_id,
                config_dir: slot.config_dir,
                state: ClaudeAccountSetupOperationState::WaitingForUserLogin,
                target_id,
                requested_expected_account_identifier_hash: Some(
                    expected_account_identifier_hash.clone(),
                ),
                requested_expected_organization_identifier_hash:
                    expected_organization_identifier_hash.clone(),
                expected_account_identifier_hash: Some(expected_account_identifier_hash.clone()),
                expected_organization_identifier_hash: expected_organization_identifier_hash.clone(),
                account_identifier_hash: Some(expected_account_identifier_hash),
                organization_identifier_hash: expected_organization_identifier_hash,
                message: Some(
                    "Waiting for the customer to complete official Claude Code /login in this exact registered directory."
                        .to_string(),
                ),
            });
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract_for_operation(&persisted, &operation_id))
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

    /// Replay discovery without turning an unknown operation into an error.
    /// Target-bound control checks this before consulting current eligibility,
    /// so a successful operation remains idempotent after it becomes anchored.
    pub fn setup_operation_if_exists(
        &self,
        operation_id: &str,
    ) -> Result<Option<ClaudeAccountsStatusV1>, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let persisted = self.load_persisted()?;
        Ok(require_setup_operation(&persisted, operation_id)
            .ok()
            .map(|_| status_contract_for_operation(&persisted, operation_id)))
    }

    /// Replay an existing legacy v18 managed setup with its exact originally
    /// persisted binding. This prevents a legacy caller from changing a
    /// target-bound operation or turning an observed organization into the
    /// operation's requested organization during replay.
    pub fn replay_legacy_managed_account_setup(
        &self,
        schema_version: u16,
        operation_id: &str,
        expected_account_identifier_hash: Option<&str>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let persisted = self.load_persisted()?;
        let operation = require_setup_operation(&persisted, operation_id)?;
        if operation.kind != ClaudeAccountSetupOperationKind::ConnectManagedAccount
            || operation.target_id.is_some()
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "legacy setup replay requires an existing non-target managed operation".to_string(),
            ));
        }
        if operation
            .requested_expected_account_identifier_hash
            .as_deref()
            != expected_account_identifier_hash
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "setup operation expected account does not match its original binding".to_string(),
            ));
        }
        let requested_account = operation.requested_expected_account_identifier_hash.clone();
        let requested_organization = operation
            .requested_expected_organization_identifier_hash
            .clone();
        self.prepare_managed_account_target(
            schema_version,
            operation_id.to_string(),
            None,
            requested_account,
            requested_organization,
        )
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
        self.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            None,
            state,
            account_identifier_hash,
            None,
            message,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one atomic transition validates expected and observed composite bindings"
    )]
    pub fn transition_setup_operation_with_binding(
        &self,
        schema_version: u16,
        operation_id: &str,
        expected_account_identifier_hash: Option<&str>,
        expected_organization_identifier_hash: Option<&str>,
        state: ClaudeAccountSetupOperationState,
        account_identifier_hash: Option<&str>,
        organization_identifier_hash: Option<&str>,
        message: Option<&str>,
    ) -> Result<ClaudeAccountsStatusV1, ClaudeConfigSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        validate_expected_account_hash(expected_account_identifier_hash)?;
        validate_expected_account_hash(expected_organization_identifier_hash)?;
        validate_expected_account_hash(account_identifier_hash)?;
        validate_expected_account_hash(organization_identifier_hash)?;
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
            match (
                operation.expected_organization_identifier_hash.as_deref(),
                expected_organization_identifier_hash,
            ) {
                (Some(bound), Some(requested)) if bound != requested => {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "setup operation expected organization does not match its original binding"
                            .to_string(),
                    ));
                }
                (None, Some(requested)) => {
                    operation.expected_organization_identifier_hash = Some(requested.to_string());
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
            if let (Some(bound), Some(observed)) = (
                operation.expected_organization_identifier_hash.as_deref(),
                organization_identifier_hash,
            ) {
                if bound != observed {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "setup operation observed organization does not match its binding"
                            .to_string(),
                    ));
                }
            }
            if operation.expected_organization_identifier_hash.is_none() {
                operation.expected_organization_identifier_hash =
                    organization_identifier_hash.map(ToString::to_string);
            }
            operation.state = state;
            operation.account_identifier_hash = account_identifier_hash.map(ToString::to_string);
            operation.organization_identifier_hash =
                organization_identifier_hash.map(ToString::to_string);
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
        let (registered, kind) = {
            let operation = require_setup_operation(&persisted, operation_id)?;
            (
                persisted
                    .registered_slots
                    .iter()
                    .any(|slot| slot.slot_id == operation.slot_id),
                operation.kind,
            )
        };
        let operation = persisted
            .setup_operations
            .iter_mut()
            .chain(persisted.reconnect_operations.iter_mut())
            .find(|candidate| candidate.operation_id == operation_id)
            .expect("validated setup operation remains present");
        if !matches!(
            operation.state,
            ClaudeAccountSetupOperationState::Complete
                | ClaudeAccountSetupOperationState::SetupStopped
        ) {
            if !registered && kind == ClaudeAccountSetupOperationKind::ConnectManagedAccount {
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
            let retired_ids = settings
                .reconnect_operations
                .iter()
                .filter(|operation| operation.slot_id == slot_id)
                .map(|operation| operation.operation_id.clone())
                .collect::<Vec<_>>();
            for operation_id in retired_ids {
                retire_reconnect_operation_id(settings, &operation_id);
            }
            settings
                .reconnect_operations
                .retain(|operation| operation.slot_id != slot_id);
            Ok(())
        })
    }

    fn load_persisted(
        &self,
    ) -> Result<PersistedClaudeConfigSlotSettingsV1, ClaudeConfigSlotSettingsError> {
        let mut persisted = if self.path.exists() {
            let body = fs::read_to_string(&self.path).map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!("read settings: {error}"))
            })?;
            serde_json::from_str::<PersistedClaudeConfigSlotSettingsV1>(&body).map_err(|error| {
                ClaudeConfigSlotSettingsError::State(format!("parse settings: {error}"))
            })?
        } else {
            PersistedClaudeConfigSlotSettingsV1::default()
        };
        match persisted.schema_version {
            1 => persisted.schema_version = CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION,
            CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION => {}
            other => {
                return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
                    "unsupported persisted Claude config-slot schema {other}; expected 1 or {CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION}"
                )))
            }
        }
        if let Some(sidecar) = self.read_retired_reconnect_filter()? {
            if persisted.retired_reconnect_operation_filter.is_empty() {
                persisted.retired_reconnect_operation_filter = sidecar;
            } else {
                for (destination, source) in persisted
                    .retired_reconnect_operation_filter
                    .iter_mut()
                    .zip(sidecar)
                {
                    *destination |= source;
                }
            }
        }
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
        let retire_terminal_reconnect = {
            let operation = persisted
                .setup_operations
                .iter_mut()
                .chain(persisted.reconnect_operations.iter_mut())
                .find(|operation| operation.operation_id == operation_id)
                .ok_or_else(|| {
                    ClaudeConfigSlotSettingsError::Invalid(format!(
                        "unknown Claude setup operation_id {operation_id}"
                    ))
                })?;
            let was_terminal_reconnect = operation.kind
                == ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
                && operation_allows_reconnect_successor(operation);
            mutation(operation)?;
            !was_terminal_reconnect
                && operation.kind == ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
                && operation_allows_reconnect_successor(operation)
        };
        if retire_terminal_reconnect {
            // Keep the live row so exact same-binding status/replay remains
            // available, but retire the id before persisting the terminal
            // transition. The sidecar is written first, so an older daemon
            // that later drops additive reconnect fields cannot rebind it.
            retire_reconnect_operation_id(&mut persisted, operation_id);
        }
        validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract_for_operation(&persisted, operation_id))
    }

    fn write_persisted(
        &self,
        persisted: &PersistedClaudeConfigSlotSettingsV1,
    ) -> Result<(), ClaudeConfigSlotSettingsError> {
        if !persisted.retired_reconnect_operation_filter.is_empty() {
            let filter = serde_json::to_vec(&persisted.retired_reconnect_operation_filter)
                .map_err(|error| {
                    ClaudeConfigSlotSettingsError::State(format!(
                        "serialize retired reconnect filter: {error}"
                    ))
                })?;
            crate::write_owner_only_file_atomic(&self.retired_reconnect_filter_path(), &filter)
                .map_err(|error| {
                    ClaudeConfigSlotSettingsError::State(format!(
                        "write retired reconnect filter: {error}"
                    ))
                })?;
        }
        let body = serde_json::to_vec_pretty(persisted).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("serialize settings: {error}"))
        })?;
        crate::write_owner_only_file_atomic(&self.path, &body).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("write settings: {error}"))
        })
    }

    fn retired_reconnect_filter_path(&self) -> PathBuf {
        self.path
            .with_extension(CLAUDE_RETIRED_RECONNECT_FILTER_FILE_SUFFIX)
    }

    fn read_retired_reconnect_filter(
        &self,
    ) -> Result<Option<Vec<u64>>, ClaudeConfigSlotSettingsError> {
        let path = self.retired_reconnect_filter_path();
        if !path.exists() {
            return Ok(None);
        }
        let body = fs::read(&path).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("read retired reconnect filter: {error}"))
        })?;
        let filter = serde_json::from_slice::<Vec<u64>>(&body).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("parse retired reconnect filter: {error}"))
        })?;
        if filter.len() != RETIRED_RECONNECT_FILTER_WORDS {
            return Err(ClaudeConfigSlotSettingsError::State(
                "retired reconnect filter has invalid capacity".to_string(),
            ));
        }
        Ok(Some(filter))
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
    if settings.schema_version != CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "unsupported persisted Claude config-slot schema {}; expected {CLAUDE_CONFIG_SLOT_PERSISTED_SCHEMA_VERSION}",
            settings.schema_version
        )));
    }
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
    if !settings.retired_reconnect_operation_filter.is_empty()
        && settings.retired_reconnect_operation_filter.len() != RETIRED_RECONNECT_FILTER_WORDS
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "retired reconnect operation filter has invalid capacity".to_string(),
        ));
    }
    if settings.reconnect_operations.len() > MAX_REGISTERED_CLAUDE_CONFIG_SLOTS {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "active Claude reconnect operation count exceeds capacity".to_string(),
        ));
    }
    if settings
        .setup_operations
        .iter()
        .any(|operation| operation.kind != ClaudeAccountSetupOperationKind::ConnectManagedAccount)
        || settings.reconnect_operations.iter().any(|operation| {
            operation.kind != ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
        })
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude operation kind does not match its persisted collection".to_string(),
        ));
    }
    let mut operation_ids = BTreeSet::new();
    let mut reconnect_slot_ids = BTreeSet::new();
    let registered_slot_ids = settings
        .registered_slots
        .iter()
        .map(|slot| slot.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    for operation in settings
        .setup_operations
        .iter()
        .chain(settings.reconnect_operations.iter())
    {
        validate_setup_operation_id(&operation.operation_id)?;
        validate_opaque_slot_id(&operation.slot_id)?;
        validate_registered_config_dir(&operation.config_dir)?;
        validate_expected_account_hash(
            operation
                .requested_expected_account_identifier_hash
                .as_deref(),
        )?;
        validate_expected_account_hash(
            operation
                .requested_expected_organization_identifier_hash
                .as_deref(),
        )?;
        validate_expected_account_hash(operation.expected_account_identifier_hash.as_deref())?;
        validate_expected_account_hash(operation.expected_organization_identifier_hash.as_deref())?;
        validate_expected_account_hash(operation.account_identifier_hash.as_deref())?;
        validate_expected_account_hash(operation.organization_identifier_hash.as_deref())?;
        validate_anchor_target_binding(
            operation.target_id.as_deref(),
            operation
                .requested_expected_account_identifier_hash
                .as_deref(),
            operation
                .requested_expected_organization_identifier_hash
                .as_deref(),
        )?;
        if operation.target_id.is_some()
            && (operation.expected_account_identifier_hash
                != operation.requested_expected_account_identifier_hash
                || operation.expected_organization_identifier_hash
                    != operation.requested_expected_organization_identifier_hash)
        {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "target-bound Claude operation changed its composite identity".to_string(),
            ));
        }
        if !operation_ids.insert(operation.operation_id.as_str()) {
            return Err(ClaudeConfigSlotSettingsError::Invalid(
                "Claude setup operation ids must be unique".to_string(),
            ));
        }
        let registered_slot = settings
            .registered_slots
            .iter()
            .find(|slot| slot.slot_id == operation.slot_id);
        match operation.kind {
            ClaudeAccountSetupOperationKind::ConnectManagedAccount => {
                if registered_slot.is_none()
                    && !matches!(
                        operation.state,
                        ClaudeAccountSetupOperationState::Preparing
                            | ClaudeAccountSetupOperationState::SetupStopped
                    )
                {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "only a preparing managed Claude operation may precede registration"
                            .to_string(),
                    ));
                }
                if let Some(slot) = registered_slot {
                    if slot.ownership != ClaudeConfigSlotOwnership::Managed
                        || slot.config_dir != operation.config_dir
                    {
                        return Err(ClaudeConfigSlotSettingsError::Invalid(
                            "managed Claude operation must match its managed registration"
                                .to_string(),
                        ));
                    }
                }
            }
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot => {
                if !reconnect_slot_ids.insert(operation.slot_id.as_str()) {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "only one reconnect operation may be retained per slot".to_string(),
                    ));
                }
                if let Some(slot) = registered_slot {
                    if slot.config_dir != operation.config_dir {
                        return Err(ClaudeConfigSlotSettingsError::Invalid(
                            "reconnect operation must retain its exact registered directory"
                                .to_string(),
                        ));
                    }
                } else if operation.state != ClaudeAccountSetupOperationState::SetupStopped {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "only a stopped reconnect tombstone may outlive its registered custom slot"
                            .to_string(),
                    ));
                }
                if operation
                    .requested_expected_account_identifier_hash
                    .is_none()
                    || operation.expected_account_identifier_hash.is_none()
                {
                    return Err(ClaudeConfigSlotSettingsError::Invalid(
                        "reconnect operation requires a strong account binding".to_string(),
                    ));
                }
            }
        }
    }
    let preparing_count = settings
        .setup_operations
        .iter()
        .filter(|operation| {
            operation.kind == ClaudeAccountSetupOperationKind::ConnectManagedAccount
                && !registered_slot_ids.contains(operation.slot_id.as_str())
        })
        .count();
    let nonterminal_count = settings
        .setup_operations
        .iter()
        .chain(settings.reconnect_operations.iter())
        .filter(|operation| operation_is_nonterminal(operation))
        .count();
    if nonterminal_count > 1 {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "only one Claude setup or reconnect operation may be active".to_string(),
        ));
    }
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
        .chain(settings.reconnect_operations.iter())
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

fn next_operation_sequence(settings: &PersistedClaudeConfigSlotSettingsV1) -> u64 {
    settings
        .setup_operations
        .iter()
        .chain(settings.reconnect_operations.iter())
        .map(|operation| operation.created_sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn operation_allows_reconnect_successor(
    operation: &PersistedClaudeAccountSetupOperationV1,
) -> bool {
    matches!(
        operation.state,
        ClaudeAccountSetupOperationState::Complete
            | ClaudeAccountSetupOperationState::SetupFailed
            | ClaudeAccountSetupOperationState::IdentityMismatch
    )
}

fn operation_is_nonterminal(operation: &PersistedClaudeAccountSetupOperationV1) -> bool {
    matches!(
        operation.state,
        ClaudeAccountSetupOperationState::Preparing
            | ClaudeAccountSetupOperationState::WaitingForUserLogin
            | ClaudeAccountSetupOperationState::Validating
            | ClaudeAccountSetupOperationState::Reading
    )
}

fn reject_other_nonterminal_operation(
    settings: &PersistedClaudeConfigSlotSettingsV1,
    operation_id: &str,
) -> Result<(), ClaudeConfigSlotSettingsError> {
    if let Some(active) = settings
        .setup_operations
        .iter()
        .chain(settings.reconnect_operations.iter())
        .find(|operation| {
            operation.operation_id != operation_id && operation_is_nonterminal(operation)
        })
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(format!(
            "Claude account setup already has active operation {}; replay or stop it first",
            active.operation_id
        )));
    }
    Ok(())
}

fn validate_anchor_target_binding(
    target_id: Option<&str>,
    account_hash: Option<&str>,
    organization_hash: Option<&str>,
) -> Result<(), ClaudeConfigSlotSettingsError> {
    let Some(target_id) = target_id else {
        return Ok(());
    };
    let Some(suffix) = target_id.strip_prefix("claude_anchor_target_") else {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude anchor target id has an unsupported shape".to_string(),
        ));
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude anchor target id has an unsupported shape".to_string(),
        ));
    }
    if account_hash.is_none() || organization_hash.is_none() {
        return Err(ClaudeConfigSlotSettingsError::Invalid(
            "Claude anchor target requires an exact account and organization binding".to_string(),
        ));
    }
    Ok(())
}

fn retired_reconnect_filter_indexes(
    operation_id: &str,
) -> [usize; RETIRED_RECONNECT_FILTER_HASHES] {
    let digest = Sha256::digest(operation_id.as_bytes());
    std::array::from_fn(|index| {
        let offset = index * 4;
        let value = u32::from_be_bytes(
            digest[offset..offset + 4]
                .try_into()
                .expect("SHA-256 chunk is four bytes"),
        );
        value as usize % (RETIRED_RECONNECT_FILTER_WORDS * u64::BITS as usize)
    })
}

fn reconnect_operation_id_is_retired(
    settings: &PersistedClaudeConfigSlotSettingsV1,
    operation_id: &str,
) -> bool {
    if settings.retired_reconnect_operation_filter.is_empty() {
        return false;
    }
    retired_reconnect_filter_indexes(operation_id)
        .into_iter()
        .all(|bit| {
            settings.retired_reconnect_operation_filter[bit / u64::BITS as usize]
                & (1_u64 << (bit % u64::BITS as usize))
                != 0
        })
}

fn retire_reconnect_operation_id(
    settings: &mut PersistedClaudeConfigSlotSettingsV1,
    operation_id: &str,
) {
    if settings.retired_reconnect_operation_filter.is_empty() {
        settings
            .retired_reconnect_operation_filter
            .resize(RETIRED_RECONNECT_FILTER_WORDS, 0);
    }
    for bit in retired_reconnect_filter_indexes(operation_id) {
        settings.retired_reconnect_operation_filter[bit / u64::BITS as usize] |=
            1_u64 << (bit % u64::BITS as usize);
    }
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
                .chain(persisted.reconnect_operations.iter())
                .find(|operation| operation.operation_id == operation_id)
        })
        .or_else(|| {
            persisted
                .setup_operations
                .iter()
                .chain(persisted.reconnect_operations.iter())
                .max_by_key(|operation| operation.created_sequence)
        });
    let setup_operation = selected_operation
        .map(|operation| {
            let registered_config_dir = persisted
                .registered_slots
                .iter()
                .find(|slot| slot.slot_id == operation.slot_id)
                .map(|slot| slot.config_dir.as_str());
            let launch_command = match (operation.kind, registered_config_dir) {
                (ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot, None) => None,
                (_, Some(config_dir)) => Some(launch_command(config_dir)),
                (_, None) => Some(launch_command(&operation.config_dir)),
            };
            ClaudeAccountSetupOperationV1 {
                kind: operation.kind,
                state: operation.state.clone(),
                operation_id: Some(operation.operation_id.clone()),
                slot_id: Some(operation.slot_id.clone()),
                target_id: operation.target_id.clone(),
                expected_account_identifier_hash: operation
                    .expected_account_identifier_hash
                    .clone(),
                expected_organization_identifier_hash: operation
                    .expected_organization_identifier_hash
                    .clone(),
                account_identifier_hash: operation.account_identifier_hash.clone(),
                organization_identifier_hash: operation.organization_identifier_hash.clone(),
                launch_command,
                message: operation.message.clone(),
            }
        })
        .unwrap_or(ClaudeAccountSetupOperationV1 {
            kind: ClaudeAccountSetupOperationKind::ConnectManagedAccount,
            state: ClaudeAccountSetupOperationState::Idle,
            operation_id: None,
            slot_id: None,
            target_id: None,
            expected_account_identifier_hash: None,
            expected_organization_identifier_hash: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            launch_command: None,
            message: None,
        });
    ClaudeAccountsStatusV1 {
        schema_version: CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
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
        anchor_coverage: ClaudeAccountAnchorCoverageV1::default(),
        anchor_transitions: Vec::new(),
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
    fn launch_command_quotes_exact_adversarial_config_strings_without_injection() {
        let root = temp_path("launch-quoting");
        let root = root.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).expect("root");
        let sentinel = root.join("must-not-exist");
        let composed = format!("{}/caf\u{e9}", root.display());
        let decomposed = format!("{}/cafe\u{301}", root.display());
        let values = [
            format!("{}/space dir", root.display()),
            format!("{}/single'quote", root.display()),
            format!(
                "{}/$(touch {}) ; `touch {}` $HOME *",
                root.display(),
                sentinel.display(),
                sentinel.display()
            ),
            format!("{}/trailing/", root.display()),
            composed.clone(),
            decomposed.clone(),
        ];
        for value in values {
            let command = launch_command(&value);
            assert!(!command.contains("/login"));
            let script = format!(
                "set -eu\nclaude() {{ /usr/bin/printf '%s' \"$CLAUDE_CONFIG_DIR\"; }}\n{command}"
            );
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .output()
                .expect("run quoted launch command");
            assert!(output.status.success());
            assert_eq!(String::from_utf8(output.stdout).expect("utf8"), value);
            assert!(!sentinel.exists(), "shell metacharacters must stay data");
        }
        assert_ne!(launch_command(&composed), launch_command(&decomposed));
        assert_ne!(
            launch_command(&format!("{}/trailing", root.display())),
            launch_command(&format!("{}/trailing/", root.display()))
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reconnect_reuses_exact_registered_slot_and_persists_stop_restart_lifecycle() {
        let path = temp_path("registered-reconnect");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let config_dir = format!("{}/existing slot/'quoted/", root.display());
        let registered = store
            .register_path(1, config_dir.clone())
            .expect("register exact external slot");
        let slot_id = registered.external_slots[0].slot_id.clone();
        let operation_id = "claude_setup_11111111111111111111111111111111";
        let account_hash = "a".repeat(64);
        let begun = store
            .begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &slot_id,
                account_hash.clone(),
            )
            .expect("begin reconnect");
        assert_eq!(
            begun.setup_operation.kind,
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
        );
        assert_eq!(
            begun.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        assert_eq!(
            begun.setup_operation.slot_id.as_deref(),
            Some(slot_id.as_str())
        );
        assert_eq!(begun.external_slots.len(), 1, "no duplicate registration");
        assert!(begun.managed_slots.is_empty());
        assert_eq!(
            begun.external_slots[0].config_dir.as_deref(),
            Some(config_dir.as_str())
        );
        assert_eq!(
            begun.setup_operation.launch_command.as_deref(),
            Some(launch_command(&config_dir).as_str())
        );

        let stopped = store.stop_waiting(1, operation_id).expect("stop");
        assert_eq!(
            stopped.setup_operation.state,
            ClaudeAccountSetupOperationState::SetupStopped
        );
        let restarted = FileClaudeConfigSlotSettingsStore::new(&path)
            .begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &slot_id,
                account_hash.clone(),
            )
            .expect("restart and replay exact reconnect");
        assert_eq!(
            restarted.setup_operation.state,
            ClaudeAccountSetupOperationState::WaitingForUserLogin
        );
        assert_eq!(restarted.external_slots.len(), 1);
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &slot_id,
                "b".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                "claude_setup_22222222222222222222222222222222".to_string(),
                &slot_id,
                account_hash,
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let durable = store
            .setup_operation(operation_id)
            .expect("original operation id remains durably bound");
        assert_eq!(
            durable
                .setup_operation
                .expected_account_identifier_hash
                .as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        let mut downgrade: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read reconnect settings"))
                .expect("settings json");
        assert!(downgrade["setup_operations"]
            .as_array()
            .expect("legacy setup array")
            .is_empty());
        assert_eq!(
            downgrade["reconnect_operations"]
                .as_array()
                .expect("additive reconnect array")
                .len(),
            1
        );
        downgrade
            .as_object_mut()
            .expect("settings object")
            .remove("reconnect_operations");
        downgrade
            .as_object_mut()
            .expect("settings object")
            .remove("retired_reconnect_operation_filter");
        crate::write_owner_only_file_atomic(
            &path,
            &serde_json::to_vec_pretty(&downgrade).expect("downgrade settings"),
        )
        .expect("simulate older daemon rewrite");
        let downgraded = store.load().expect("old daemon-compatible settings");
        assert_eq!(
            downgraded.setup_operation.state,
            ClaudeAccountSetupOperationState::Idle
        );
        assert_eq!(downgraded.external_slots.len(), 1);
        assert_eq!(
            downgraded.external_slots[0].config_dir.as_deref(),
            Some(config_dir.as_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reconnect_refuses_default_weak_unknown_and_removed_slots() {
        let path = temp_path("registered-reconnect-refusals");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let registered = store
            .register_path(1, format!("{}/external", root.display()))
            .expect("register");
        let slot_id = registered.external_slots[0].slot_id.clone();
        let operation_id = "claude_setup_33333333333333333333333333333333";
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                "default",
                "a".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &slot_id,
                "weak".to_string(),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        store
            .remove(1, &slot_id)
            .expect("remove exact registration");
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &slot_id,
                "a".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ordinary_status_allows_only_one_active_operation_across_setup_and_reconnect() {
        let path = temp_path("cross-kind-operation-order");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let registered = store
            .register_path(1, format!("{}/external", root.display()))
            .expect("register external slot");
        let slot_id = registered.external_slots[0].slot_id.clone();
        let reconnect_id = "claude_setup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store
            .begin_registered_slot_reconnect(1, reconnect_id.to_string(), &slot_id, "a".repeat(64))
            .expect("persist reconnect");

        let managed_id = "claude_setup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(matches!(
            store.prepare_managed_account(1, managed_id.to_string(), None),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        store
            .stop_waiting(1, reconnect_id)
            .expect("stop reconnect before starting managed setup");
        store
            .prepare_managed_account(1, managed_id.to_string(), None)
            .expect("persist newer managed setup");
        let ordinary = store.load().expect("ordinary status");
        assert_eq!(
            ordinary.setup_operation.operation_id.as_deref(),
            Some(managed_id)
        );
        assert_eq!(
            ordinary.setup_operation.kind,
            ClaudeAccountSetupOperationKind::ConnectManagedAccount
        );
        let selected_reconnect = store
            .setup_operation(reconnect_id)
            .expect("old binding remains");
        assert_eq!(
            selected_reconnect.setup_operation.kind,
            ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn removed_slot_retires_reconnect_operation_id_without_unbounded_tombstone_or_rebinding() {
        let path = temp_path("removed-reconnect-tombstone");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let first = store
            .register_path(1, format!("{}/first", root.display()))
            .expect("register first slot");
        let first_slot_id = first.external_slots[0].slot_id.clone();
        let operation_id = "claude_setup_cccccccccccccccccccccccccccccccc";
        store
            .begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &first_slot_id,
                "a".repeat(64),
            )
            .expect("persist reconnect binding");
        store.remove(1, &first_slot_id).expect("remove first slot");

        assert!(matches!(
            store.setup_operation(operation_id),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let idle = store
            .load()
            .expect("removed slot has no actionable operation");
        assert_eq!(
            idle.setup_operation.state,
            ClaudeAccountSetupOperationState::Idle
        );

        let second = store
            .register_path(1, format!("{}/second", root.display()))
            .expect("register second slot");
        let second_slot_id = second.external_slots[0].slot_id.clone();
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &second_slot_id,
                "b".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.prepare_managed_account(1, operation_id.to_string(), None),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_slot_supports_first_and_repeated_terminal_reconnects_with_bounded_replay_guard() {
        let path = temp_path("managed-repeated-reconnect");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let account_hash = "a".repeat(64);
        let managed_id = "claude_setup_11111111111111111111111111111111";
        let prepared = store
            .prepare_managed_account(1, managed_id.to_string(), None)
            .expect("prepare managed slot");
        let slot_id = prepared.managed_slots[0].slot_id.clone();
        store
            .transition_setup_operation(
                1,
                managed_id,
                None,
                ClaudeAccountSetupOperationState::Complete,
                Some(&account_hash),
                Some("complete"),
            )
            .expect("complete managed setup");

        let first_reconnect = "claude_setup_22222222222222222222222222222222";
        store
            .begin_registered_slot_reconnect(
                1,
                first_reconnect.to_string(),
                &slot_id,
                account_hash.clone(),
            )
            .expect("first managed-slot reconnect");
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                "claude_setup_33333333333333333333333333333333".to_string(),
                &slot_id,
                account_hash.clone(),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        store
            .transition_setup_operation(
                1,
                first_reconnect,
                Some(&account_hash),
                ClaudeAccountSetupOperationState::Complete,
                Some(&account_hash),
                Some("complete"),
            )
            .expect("complete first reconnect");

        let second_reconnect = "claude_setup_44444444444444444444444444444444";
        let second = store
            .begin_registered_slot_reconnect(
                1,
                second_reconnect.to_string(),
                &slot_id,
                account_hash,
            )
            .expect("second reconnect after terminal first");
        assert_eq!(
            second.setup_operation.operation_id.as_deref(),
            Some(second_reconnect)
        );
        assert_eq!(second.managed_slots.len(), 1, "never duplicate the slot");
        assert!(matches!(
            store.setup_operation(first_reconnect),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(store.setup_operation(managed_id).is_ok());

        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("settings")).expect("settings json");
        assert_eq!(
            persisted["reconnect_operations"]
                .as_array()
                .expect("current reconnects")
                .len(),
            1
        );
        assert_eq!(
            persisted["retired_reconnect_operation_filter"]
                .as_array()
                .expect("bounded replay filter")
                .len(),
            RETIRED_RECONNECT_FILTER_WORDS
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn terminal_reconnect_is_retired_before_successor_and_survives_legacy_field_rewrite() {
        let path = temp_path("terminal-reconnect-downgrade-retirement");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let first = store
            .register_path(1, format!("{}/first", root.display()))
            .expect("register first slot");
        let first_slot_id = first.external_slots[0].slot_id.clone();
        let second = store
            .register_path(1, format!("{}/second", root.display()))
            .expect("register second slot");
        let second_slot_id = second
            .external_slots
            .iter()
            .find(|slot| slot.slot_id != first_slot_id)
            .expect("second slot")
            .slot_id
            .clone();
        let account_hash = "a".repeat(64);
        let operation_id = "claude_setup_55555555555555555555555555555555";
        store
            .begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &first_slot_id,
                account_hash.clone(),
            )
            .expect("begin reconnect");
        store
            .transition_setup_operation(
                1,
                operation_id,
                Some(&account_hash),
                ClaudeAccountSetupOperationState::Complete,
                Some(&account_hash),
                Some("complete"),
            )
            .expect("complete reconnect");

        let completed = store.load_persisted().expect("completed settings");
        assert!(reconnect_operation_id_is_retired(&completed, operation_id));
        assert_eq!(completed.reconnect_operations.len(), 1);
        assert!(store.retired_reconnect_filter_path().is_file());
        let sidecar_filter: Vec<u64> = serde_json::from_slice(
            &fs::read(store.retired_reconnect_filter_path()).expect("retirement sidecar"),
        )
        .expect("retirement sidecar json");
        assert_eq!(sidecar_filter.len(), RETIRED_RECONNECT_FILTER_WORDS);

        let replay = store
            .begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &first_slot_id,
                account_hash.clone(),
            )
            .expect("same binding replays before retirement refusal");
        assert_eq!(
            replay.setup_operation.operation_id.as_deref(),
            Some(operation_id)
        );
        assert_eq!(
            replay.setup_operation.state,
            ClaudeAccountSetupOperationState::Complete
        );

        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("settings")).expect("settings json");
        let legacy_object = legacy.as_object_mut().expect("settings object");
        legacy_object.remove("reconnect_operations");
        legacy_object.remove("retired_reconnect_operation_filter");
        crate::write_owner_only_file_atomic(
            &path,
            &serde_json::to_vec_pretty(&legacy).expect("legacy settings"),
        )
        .expect("simulate older daemon rewrite");

        let upgraded = store.load_persisted().expect("upgrade legacy settings");
        assert!(upgraded.reconnect_operations.is_empty());
        assert!(reconnect_operation_id_is_retired(&upgraded, operation_id));
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &second_slot_id,
                account_hash.clone(),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                operation_id.to_string(),
                &first_slot_id,
                "b".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.prepare_managed_account(1, operation_id.to_string(), None),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_register_reconnect_remove_keeps_fixed_retirement_capacity_and_decodes_without_it() {
        let path = temp_path("bounded-reconnect-retirement");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let first_operation_id = "claude_setup_00000000000000000000000000000001";
        for index in 1_u128..=64 {
            let registered = store
                .register_path(1, format!("{}/slot-{index}", root.display()))
                .expect("register cycle slot");
            let slot_id = registered.external_slots[0].slot_id.clone();
            let operation_id = format!("claude_setup_{index:032x}");
            store
                .begin_registered_slot_reconnect(1, operation_id, &slot_id, "a".repeat(64))
                .expect("begin cycle reconnect");
            store.remove(1, &slot_id).expect("remove cycle slot");
        }
        let final_slot = store
            .register_path(1, format!("{}/final", root.display()))
            .expect("register final slot");
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                first_operation_id.to_string(),
                &final_slot.external_slots[0].slot_id,
                "b".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));

        let mut persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("settings")).expect("settings json");
        assert!(persisted["reconnect_operations"]
            .as_array()
            .expect("current reconnects")
            .is_empty());
        assert_eq!(
            persisted["retired_reconnect_operation_filter"]
                .as_array()
                .expect("fixed retirement filter")
                .len(),
            RETIRED_RECONNECT_FILTER_WORDS
        );
        persisted
            .as_object_mut()
            .expect("settings object")
            .remove("retired_reconnect_operation_filter");
        crate::write_owner_only_file_atomic(
            &path,
            &serde_json::to_vec_pretty(&persisted).expect("downgrade settings"),
        )
        .expect("simulate older daemon rewrite");
        let downgraded = store.load().expect("legacy settings remain readable");
        assert_eq!(downgraded.external_slots.len(), 1);
        let sidecar_filter: Vec<u64> = serde_json::from_slice(
            &fs::read(store.retired_reconnect_filter_path()).expect("retirement sidecar"),
        )
        .expect("retirement sidecar json");
        assert_eq!(sidecar_filter.len(), RETIRED_RECONNECT_FILTER_WORDS);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(store.retired_reconnect_filter_path())
                    .expect("sidecar metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(matches!(
            store.begin_registered_slot_reconnect(
                1,
                first_operation_id.to_string(),
                &downgraded.external_slots[0].slot_id,
                "b".repeat(64),
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        assert!(matches!(
            store.prepare_managed_account(1, first_operation_id.to_string(), None),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
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
                kind: ClaudeAccountSetupOperationKind::ConnectManagedAccount,
                created_sequence: 1,
                operation_id: operation_id.to_string(),
                slot_id: slot_id.to_string(),
                config_dir: config_dir.to_string_lossy().into_owned(),
                state: ClaudeAccountSetupOperationState::Preparing,
                target_id: None,
                requested_expected_account_identifier_hash: None,
                requested_expected_organization_identifier_hash: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                account_identifier_hash: None,
                organization_identifier_hash: None,
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
    fn target_bound_setup_rejects_same_account_under_another_organization() {
        let path = temp_path("target-composite-binding");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        let operation_id = "claude_setup_abababababababababababababababab";
        let account = "a".repeat(64);
        let organization = "b".repeat(64);
        store
            .prepare_managed_account_target(
                1,
                operation_id.to_string(),
                Some("claude_anchor_target_abababababababababababababababab".to_string()),
                Some(account.clone()),
                Some(organization.clone()),
            )
            .expect("prepare target-bound operation");

        assert!(matches!(
            store.transition_setup_operation_with_binding(
                1,
                operation_id,
                Some(&account),
                Some(&organization),
                ClaudeAccountSetupOperationState::Validating,
                Some(&account),
                Some(&"c".repeat(64)),
                None,
            ),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
        let status = store.load().expect("binding remains persisted");
        assert_eq!(
            status.setup_operation.expected_organization_identifier_hash,
            Some(organization)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn v1_migration_fails_closed_when_multiple_operations_are_active() {
        let path = temp_path("v1-multiple-active");
        let root = path.parent().expect("parent");
        let _ = fs::remove_dir_all(root);
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        store
            .prepare_managed_account(
                1,
                "claude_setup_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string(),
                None,
            )
            .expect("prepare first operation");
        let mut persisted = store.load_persisted().expect("read prepared settings");
        let mut duplicate = persisted.setup_operations[0].clone();
        duplicate.operation_id = "claude_setup_efefefefefefefefefefefefefefefef".to_string();
        duplicate.created_sequence = duplicate.created_sequence.saturating_add(1);
        persisted.setup_operations.push(duplicate);
        persisted.schema_version = 1;
        crate::write_owner_only_file_atomic(
            &path,
            &serde_json::to_vec_pretty(&persisted).expect("serialize v1 settings"),
        )
        .expect("write v1 settings");

        assert!(matches!(
            store.load(),
            Err(ClaudeConfigSlotSettingsError::Invalid(_))
        ));
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
