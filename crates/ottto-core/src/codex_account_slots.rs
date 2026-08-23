use ottto_protocol::{
    CodexAccountCapacityV1, CodexAccountSetupOperationStateV1, CodexAccountSetupOperationV1,
    CodexAccountSlotCollectionStatusV1, CodexAccountSlotDescriptorV1, CodexAccountSlotOwnershipV1,
    CodexAccountsStatusV1, CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use thiserror::Error;

pub const CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME: &str = "codex-account-slots.json";
pub const CODEX_MANAGED_ACCOUNTS_DIR_NAME: &str = "codex-accounts";
pub const MAX_CODEX_ACCOUNT_SLOTS: u8 = 10;
pub const MAX_MANAGED_CODEX_ACCOUNT_SLOTS: usize = MAX_CODEX_ACCOUNT_SLOTS as usize - 1;

static CODEX_ACCOUNT_SLOT_SETTINGS_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum CodexAccountSlotSettingsError {
    #[error("invalid Codex account-slot settings: {0}")]
    Invalid(String),
    #[error("Codex account-slot settings state is unavailable: {0}")]
    State(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCodexAccountSlotsV1 {
    schema_version: u16,
    #[serde(default)]
    managed_slot_ids: Vec<String>,
    #[serde(default)]
    managed_bindings: BTreeMap<String, PersistedCodexAccountBindingV1>,
    #[serde(default)]
    setup_operation: CodexAccountSetupOperationV1,
    #[serde(default)]
    setup_preserves_accepted_binding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCodexAccountBindingV1 {
    account_identifier_hash: String,
    workspace_identifier_hash: String,
    #[serde(default)]
    accepted: bool,
}

impl Default for PersistedCodexAccountSlotsV1 {
    fn default() -> Self {
        Self {
            schema_version: CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
            managed_slot_ids: Vec::new(),
            managed_bindings: BTreeMap::new(),
            setup_operation: CodexAccountSetupOperationV1::default(),
            setup_preserves_accepted_binding: false,
        }
    }
}

pub struct FileCodexAccountSlotSettingsStore {
    path: PathBuf,
}

#[derive(Clone)]
pub struct CodexRegisteredSlotBinding {
    pub slot_id: String,
    pub account_identifier_hash: String,
    pub workspace_identifier_hash: String,
    pub accepted: bool,
}

impl FileCodexAccountSlotSettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    pub fn registered_bindings(
        &self,
    ) -> Result<Vec<CodexRegisteredSlotBinding>, CodexAccountSlotSettingsError> {
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        Ok(persisted
            .managed_slot_ids
            .iter()
            .filter_map(|slot_id| {
                let binding = persisted.managed_bindings.get(slot_id)?;
                Some(CodexRegisteredSlotBinding {
                    slot_id: slot_id.clone(),
                    account_identifier_hash: binding.account_identifier_hash.clone(),
                    workspace_identifier_hash: binding.workspace_identifier_hash.clone(),
                    accepted: binding.accepted,
                })
            })
            .collect())
    }

    pub fn prepare_managed_account(
        &self,
        schema_version: u16,
        operation_id: String,
        expected_account_identifier_hash: String,
        expected_workspace_identifier_hash: String,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(&operation_id)?;
        validate_strong_hash(&expected_account_identifier_hash, "account")?;
        validate_strong_hash(&expected_workspace_identifier_hash, "workspace")?;
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;

        if persisted.setup_operation.operation_id.as_deref() == Some(operation_id.as_str()) {
            if persisted
                .setup_operation
                .expected_account_identifier_hash
                .as_deref()
                != Some(expected_account_identifier_hash.as_str())
                || persisted
                    .setup_operation
                    .expected_workspace_identifier_hash
                    .as_deref()
                    != Some(expected_workspace_identifier_hash.as_str())
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "setup operation identity does not match its original binding".to_string(),
                ));
            }
            return Ok(status_contract(&persisted));
        }
        if matches!(
            persisted.setup_operation.state,
            CodexAccountSetupOperationStateV1::WaitingForUserLogin
                | CodexAccountSetupOperationStateV1::Validating
        ) {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "another Codex account setup operation is already active".to_string(),
            ));
        }
        let existing_slot = persisted
            .managed_bindings
            .iter()
            .find_map(|(slot_id, binding)| {
                (binding.account_identifier_hash == expected_account_identifier_hash
                    && binding.workspace_identifier_hash == expected_workspace_identifier_hash)
                    .then_some((slot_id.clone(), binding.accepted))
            });
        if existing_slot
            .as_ref()
            .is_some_and(|(_, accepted)| *accepted)
        {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "That Codex account and workspace already has a durable connection.".to_string(),
            ));
        }
        let (slot_id, home) = if let Some((slot_id, _)) = existing_slot {
            let home = self.slot_home(&slot_id)?;
            write_codex_home_config(&home, None)?;
            (slot_id, home)
        } else {
            if persisted.managed_slot_ids.len() >= MAX_MANAGED_CODEX_ACCOUNT_SLOTS {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "Codex account-slot capacity has been reached".to_string(),
                ));
            }
            let slot_id = generate_opaque_slot_id()?;
            ensure_managed_directory(&self.managed_accounts_root()?)?;
            let slot_root = self.slot_root_unchecked(&slot_id)?;
            let home = slot_root.join("home");
            let created_root = create_managed_slot_directory(&slot_root)?;
            let created_home = match create_managed_slot_directory(&home) {
                Ok(created) => created,
                Err(error) => {
                    if created_root {
                        let _ = fs::remove_dir(&slot_root);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = write_codex_home_config(&home, None) {
                if created_home {
                    let _ = fs::remove_dir(&home);
                }
                if created_root {
                    let _ = fs::remove_dir(&slot_root);
                }
                return Err(error);
            }
            persisted.managed_slot_ids.push(slot_id.clone());
            persisted.managed_slot_ids.sort();
            persisted.managed_bindings.insert(
                slot_id.clone(),
                PersistedCodexAccountBindingV1 {
                    account_identifier_hash: expected_account_identifier_hash.clone(),
                    workspace_identifier_hash: expected_workspace_identifier_hash.clone(),
                    accepted: false,
                },
            );
            (slot_id, home)
        };
        persisted.setup_operation = CodexAccountSetupOperationV1 {
            state: CodexAccountSetupOperationStateV1::WaitingForUserLogin,
            operation_id: Some(operation_id),
            slot_id: Some(slot_id),
            expected_account_identifier_hash: Some(expected_account_identifier_hash),
            expected_workspace_identifier_hash: Some(expected_workspace_identifier_hash),
            account_identifier_hash: None,
            workspace_identifier_hash: None,
            launch_command: Some(format!(
                "CODEX_HOME={} codex login",
                shell_single_quote(home.to_string_lossy().as_ref())
            )),
            message: Some(
                "Complete the official Codex sign-in and select the intended workspace."
                    .to_string(),
            ),
        };
        persisted.setup_preserves_accepted_binding = false;
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    pub fn begin_reconnect(
        &self,
        schema_version: u16,
        operation_id: String,
        slot_id: &str,
        expected_account_identifier_hash: String,
        expected_workspace_identifier_hash: String,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(&operation_id)?;
        validate_opaque_slot_id(slot_id)?;
        validate_strong_hash(&expected_account_identifier_hash, "account")?;
        validate_strong_hash(&expected_workspace_identifier_hash, "workspace")?;
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        if persisted.setup_operation.operation_id.as_deref() == Some(operation_id.as_str()) {
            if persisted.setup_operation.slot_id.as_deref() != Some(slot_id)
                || persisted
                    .setup_operation
                    .expected_account_identifier_hash
                    .as_deref()
                    != Some(expected_account_identifier_hash.as_str())
                || persisted
                    .setup_operation
                    .expected_workspace_identifier_hash
                    .as_deref()
                    != Some(expected_workspace_identifier_hash.as_str())
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "reconnect operation does not match its original Codex binding".to_string(),
                ));
            }
            return Ok(status_contract(&persisted));
        }
        if matches!(
            persisted.setup_operation.state,
            CodexAccountSetupOperationStateV1::WaitingForUserLogin
                | CodexAccountSetupOperationStateV1::Validating
        ) {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "another Codex account setup operation is already active".to_string(),
            ));
        }
        let binding = persisted.managed_bindings.get(slot_id).ok_or_else(|| {
            CodexAccountSlotSettingsError::Invalid("unknown managed Codex account slot".to_string())
        })?;
        if !binding.accepted
            || binding.account_identifier_hash != expected_account_identifier_hash
            || binding.workspace_identifier_hash != expected_workspace_identifier_hash
        {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "reconnect target does not match an accepted Codex account and workspace"
                    .to_string(),
            ));
        }
        let home = self.slot_home(slot_id)?;
        persisted.setup_operation = CodexAccountSetupOperationV1 {
            state: CodexAccountSetupOperationStateV1::WaitingForUserLogin,
            operation_id: Some(operation_id),
            slot_id: Some(slot_id.to_string()),
            expected_account_identifier_hash: Some(expected_account_identifier_hash),
            expected_workspace_identifier_hash: Some(expected_workspace_identifier_hash),
            account_identifier_hash: None,
            workspace_identifier_hash: None,
            launch_command: Some(format!(
                "CODEX_HOME={} codex login",
                shell_single_quote(home.to_string_lossy().as_ref())
            )),
            message: Some(
                "Sign in again through Codex for this exact account and workspace.".to_string(),
            ),
        };
        persisted.setup_preserves_accepted_binding = true;
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    pub fn begin_validation(
        &self,
        schema_version: u16,
        operation_id: &str,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(operation_id)?;
        self.mutate(|persisted| {
            require_setup_operation(persisted, operation_id)?;
            if persisted.setup_operation.state == CodexAccountSetupOperationStateV1::Complete {
                return Ok(());
            }
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::Validating;
            persisted.setup_operation.message =
                Some("Validating exact Codex identity and quota.".to_string());
            Ok(())
        })
    }

    pub fn finish_validation(
        &self,
        schema_version: u16,
        operation_id: &str,
        account_identifier_hash: String,
        workspace_identifier_hash: String,
        raw_workspace_id: &str,
        duplicate: bool,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(operation_id)?;
        validate_strong_hash(&account_identifier_hash, "account")?;
        validate_strong_hash(&workspace_identifier_hash, "workspace")?;
        validate_raw_workspace_id(raw_workspace_id)?;
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        require_setup_operation(&persisted, operation_id)?;
        let matches_expected = persisted
            .setup_operation
            .expected_account_identifier_hash
            .as_deref()
            == Some(account_identifier_hash.as_str())
            && persisted
                .setup_operation
                .expected_workspace_identifier_hash
                .as_deref()
                == Some(workspace_identifier_hash.as_str());
        persisted.setup_operation.account_identifier_hash = Some(account_identifier_hash);
        persisted.setup_operation.workspace_identifier_hash = Some(workspace_identifier_hash);
        if !matches_expected {
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::IdentityMismatch;
            let slot_id = persisted.setup_operation.slot_id.clone().ok_or_else(|| {
                CodexAccountSlotSettingsError::State(
                    "setup operation lost its Codex slot binding".to_string(),
                )
            })?;
            let home = self.slot_home(&slot_id)?;
            persisted.setup_operation.launch_command = Some(format!(
                "CODEX_HOME={} codex login",
                shell_single_quote(home.to_string_lossy().as_ref())
            ));
            persisted.setup_operation.message = Some(
                "Signed-in Codex account or workspace does not match the selected target."
                    .to_string(),
            );
        } else if duplicate {
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::DuplicateAccount;
            persisted.setup_operation.launch_command = None;
            persisted.setup_operation.message = Some(
                "That Codex account and workspace already has a durable connection.".to_string(),
            );
        } else {
            persisted.setup_operation.launch_command = None;
            let slot_id = persisted.setup_operation.slot_id.clone().ok_or_else(|| {
                CodexAccountSlotSettingsError::State(
                    "setup operation lost its Codex slot binding".to_string(),
                )
            })?;
            let home = self.slot_home(&slot_id)?;
            write_codex_home_config(&home, Some(raw_workspace_id))?;
            persisted
                .managed_bindings
                .get_mut(&slot_id)
                .ok_or_else(|| {
                    CodexAccountSlotSettingsError::State(
                        "setup operation lost its Codex identity binding".to_string(),
                    )
                })?
                .accepted = true;
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::Complete;
            persisted.setup_operation.message = Some(
                "Codex limits will remain available for this exact account and workspace."
                    .to_string(),
            );
        }
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    pub fn fail_validation(
        &self,
        schema_version: u16,
        operation_id: &str,
        message: &str,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(operation_id)?;
        self.mutate(|persisted| {
            require_setup_operation(persisted, operation_id)?;
            if !persisted.setup_preserves_accepted_binding {
                if let Some(slot_id) = persisted.setup_operation.slot_id.as_deref() {
                    if let Some(binding) = persisted.managed_bindings.get_mut(slot_id) {
                        binding.accepted = false;
                    }
                }
            }
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::SetupFailed;
            persisted.setup_operation.launch_command = None;
            persisted.setup_operation.message = Some(message.to_string());
            Ok(())
        })
    }

    pub fn stop_waiting(
        &self,
        schema_version: u16,
        operation_id: &str,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(operation_id)?;
        self.mutate(|persisted| {
            require_setup_operation(persisted, operation_id)?;
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::SetupStopped;
            persisted.setup_operation.launch_command = None;
            persisted.setup_operation.message = Some(
                "Stopped waiting; the Codex home and provider credential were left untouched."
                    .to_string(),
            );
            Ok(())
        })
    }

    pub fn remove(
        &self,
        schema_version: u16,
        slot_id: &str,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_opaque_slot_id(slot_id)?;
        self.mutate(|persisted| {
            let initial = persisted.managed_slot_ids.len();
            persisted
                .managed_slot_ids
                .retain(|candidate| candidate != slot_id);
            if persisted.managed_slot_ids.len() == initial {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "unknown managed Codex account slot".to_string(),
                ));
            }
            persisted.managed_bindings.remove(slot_id);
            if persisted.setup_operation.slot_id.as_deref() == Some(slot_id) {
                persisted.setup_operation = CodexAccountSetupOperationV1::default();
                persisted.setup_preserves_accepted_binding = false;
            }
            Ok(())
        })
    }

    pub fn slot_home(&self, slot_id: &str) -> Result<PathBuf, CodexAccountSlotSettingsError> {
        validate_opaque_slot_id(slot_id)?;
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        if !persisted
            .managed_slot_ids
            .iter()
            .any(|candidate| candidate == slot_id)
        {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "unknown managed Codex account slot".to_string(),
            ));
        }
        let root = self.slot_root_unchecked(slot_id)?;
        let home = root.join("home");
        verify_private_directory_descriptor(&root)?;
        verify_private_directory_descriptor(&home)?;
        Ok(home)
    }

    pub fn setup_operation(
        &self,
        operation_id: &str,
    ) -> Result<CodexAccountSetupOperationV1, CodexAccountSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        require_setup_operation(&persisted, operation_id)?;
        Ok(persisted.setup_operation)
    }

    pub fn has_registered_binding(
        &self,
        account_identifier_hash: &str,
        workspace_identifier_hash: &str,
        excluding_slot_id: Option<&str>,
    ) -> Result<bool, CodexAccountSlotSettingsError> {
        validate_strong_hash(account_identifier_hash, "account")?;
        validate_strong_hash(workspace_identifier_hash, "workspace")?;
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        Ok(persisted.managed_bindings.iter().any(|(slot_id, binding)| {
            binding.accepted
                && excluding_slot_id != Some(slot_id.as_str())
                && binding.account_identifier_hash == account_identifier_hash
                && binding.workspace_identifier_hash == workspace_identifier_hash
        }))
    }

    fn mutate(
        &self,
        change: impl FnOnce(
            &mut PersistedCodexAccountSlotsV1,
        ) -> Result<(), CodexAccountSlotSettingsError>,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        change(&mut persisted)?;
        self.validate_persisted(&persisted)?;
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    fn read_persisted(
        &self,
    ) -> Result<PersistedCodexAccountSlotsV1, CodexAccountSlotSettingsError> {
        match fs::read_to_string(&self.path) {
            Ok(body) => serde_json::from_str(&body).map_err(|error| {
                CodexAccountSlotSettingsError::State(format!("parse settings: {error}"))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PersistedCodexAccountSlotsV1::default())
            }
            Err(error) => Err(CodexAccountSlotSettingsError::State(format!(
                "read settings: {error}"
            ))),
        }
    }

    fn write_persisted(
        &self,
        persisted: &PersistedCodexAccountSlotsV1,
    ) -> Result<(), CodexAccountSlotSettingsError> {
        self.validate_persisted(persisted)?;
        let body = serde_json::to_vec_pretty(persisted).map_err(|error| {
            CodexAccountSlotSettingsError::State(format!("serialize settings: {error}"))
        })?;
        crate::write_owner_only_file_atomic(&self.path, &body).map_err(|error| {
            CodexAccountSlotSettingsError::State(format!("write settings: {error}"))
        })
    }

    fn validate_persisted(
        &self,
        persisted: &PersistedCodexAccountSlotsV1,
    ) -> Result<(), CodexAccountSlotSettingsError> {
        validate_schema_version(persisted.schema_version)?;
        if persisted.managed_slot_ids.len() > MAX_MANAGED_CODEX_ACCOUNT_SLOTS {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "Codex account-slot capacity has been exceeded".to_string(),
            ));
        }
        let mut sorted = persisted.managed_slot_ids.clone();
        for slot_id in &sorted {
            validate_opaque_slot_id(slot_id)?;
        }
        sorted.sort();
        sorted.dedup();
        if sorted.len() != persisted.managed_slot_ids.len() {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "duplicate Codex account slot id".to_string(),
            ));
        }
        if persisted.managed_bindings.len() != persisted.managed_slot_ids.len()
            || persisted
                .managed_slot_ids
                .iter()
                .any(|slot_id| !persisted.managed_bindings.contains_key(slot_id))
        {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "Codex account bindings do not match registered slots".to_string(),
            ));
        }
        for binding in persisted.managed_bindings.values() {
            validate_strong_hash(&binding.account_identifier_hash, "account")?;
            validate_strong_hash(&binding.workspace_identifier_hash, "workspace")?;
        }
        if let Some(operation_id) = persisted.setup_operation.operation_id.as_deref() {
            validate_setup_operation_id(operation_id)?;
        }
        if let Some(slot_id) = persisted.setup_operation.slot_id.as_deref() {
            validate_opaque_slot_id(slot_id)?;
            if !persisted
                .managed_slot_ids
                .iter()
                .any(|candidate| candidate == slot_id)
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "setup operation references an unregistered Codex slot".to_string(),
                ));
            }
        }
        if persisted.setup_preserves_accepted_binding {
            let slot_id = persisted
                .setup_operation
                .slot_id
                .as_deref()
                .ok_or_else(|| {
                    CodexAccountSlotSettingsError::Invalid(
                        "reconnect state has no Codex slot binding".to_string(),
                    )
                })?;
            if !persisted
                .managed_bindings
                .get(slot_id)
                .is_some_and(|binding| binding.accepted)
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "reconnect state does not reference an accepted Codex binding".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn managed_accounts_root(&self) -> Result<PathBuf, CodexAccountSlotSettingsError> {
        let support_root = self.path.parent().ok_or_else(|| {
            CodexAccountSlotSettingsError::State(
                "Codex account-slot settings path has no support root".to_string(),
            )
        })?;
        if !support_root.is_absolute() {
            return Err(CodexAccountSlotSettingsError::State(
                "Codex account-slot support root must be absolute".to_string(),
            ));
        }
        Ok(support_root.join(CODEX_MANAGED_ACCOUNTS_DIR_NAME))
    }

    fn slot_root_unchecked(&self, slot_id: &str) -> Result<PathBuf, CodexAccountSlotSettingsError> {
        Ok(self.managed_accounts_root()?.join(slot_id))
    }

    fn transaction_lock(
        &self,
    ) -> Result<CodexAccountSlotTransactionGuard<'_>, CodexAccountSlotSettingsError> {
        let process_guard = CODEX_ACCOUNT_SLOT_SETTINGS_TRANSACTION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| {
                CodexAccountSlotSettingsError::State(
                    "settings transaction lock is poisoned".to_string(),
                )
            })?;
        let support_root = self.path.parent().ok_or_else(|| {
            CodexAccountSlotSettingsError::State(
                "Codex account-slot settings path has no support root".to_string(),
            )
        })?;
        ensure_managed_directory(support_root)?;
        let lock_path = support_root.join(".codex-account-slots.lock");
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
                    CodexAccountSlotSettingsError::State(format!(
                        "open Codex account-slot transaction lock: {error}"
                    ))
                })?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(CodexAccountSlotSettingsError::State(format!(
                    "lock Codex account-slot transaction: {}",
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
                CodexAccountSlotSettingsError::State(format!(
                    "open Codex account-slot transaction lock: {error}"
                ))
            })?;
        Ok(CodexAccountSlotTransactionGuard {
            _process_guard: process_guard,
            lock_file,
        })
    }
}

impl Default for FileCodexAccountSlotSettingsStore {
    fn default() -> Self {
        Self::new(crate::default_support_dir().join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME))
    }
}

struct CodexAccountSlotTransactionGuard<'a> {
    _process_guard: MutexGuard<'a, ()>,
    lock_file: fs::File,
}

impl Drop for CodexAccountSlotTransactionGuard<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn status_contract(persisted: &PersistedCodexAccountSlotsV1) -> CodexAccountsStatusV1 {
    let used_slots = 1_u8.saturating_add(persisted.managed_slot_ids.len() as u8);
    CodexAccountsStatusV1 {
        schema_version: CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
        setup_operation: persisted.setup_operation.clone(),
        default_slot: CodexAccountSlotDescriptorV1 {
            slot_id: "default".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Default,
            collection: CodexAccountSlotCollectionStatusV1::default(),
        },
        managed_slots: persisted
            .managed_slot_ids
            .iter()
            .map(|slot_id| CodexAccountSlotDescriptorV1 {
                slot_id: slot_id.clone(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                collection: CodexAccountSlotCollectionStatusV1::default(),
            })
            .collect(),
        capacity: CodexAccountCapacityV1 {
            max_slots: MAX_CODEX_ACCOUNT_SLOTS,
            used_slots,
            remaining_slots: MAX_CODEX_ACCOUNT_SLOTS.saturating_sub(used_slots),
        },
    }
}

fn require_setup_operation(
    persisted: &PersistedCodexAccountSlotsV1,
    operation_id: &str,
) -> Result<(), CodexAccountSlotSettingsError> {
    if persisted.setup_operation.operation_id.as_deref() != Some(operation_id) {
        return Err(CodexAccountSlotSettingsError::Invalid(
            "unknown Codex account setup operation".to_string(),
        ));
    }
    Ok(())
}

fn generate_opaque_slot_id() -> Result<String, CodexAccountSlotSettingsError> {
    let token = crate::generate_control_token().map_err(|error| {
        CodexAccountSlotSettingsError::State(format!("generate Codex slot id: {error}"))
    })?;
    Ok(format!("codex_slot_{}", &token[..32]))
}

fn validate_opaque_slot_id(slot_id: &str) -> Result<(), CodexAccountSlotSettingsError> {
    validate_prefixed_opaque_id(slot_id, "codex_slot_", "slot")
}

fn validate_setup_operation_id(value: &str) -> Result<(), CodexAccountSlotSettingsError> {
    validate_prefixed_opaque_id(value, "codex_setup_", "setup operation")
}

fn validate_prefixed_opaque_id(
    value: &str,
    prefix: &str,
    label: &str,
) -> Result<(), CodexAccountSlotSettingsError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(CodexAccountSlotSettingsError::Invalid(format!(
            "Codex {label} id has an unsupported shape"
        )));
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CodexAccountSlotSettingsError::Invalid(format!(
            "Codex {label} id has an unsupported shape"
        )));
    }
    Ok(())
}

fn validate_schema_version(schema_version: u16) -> Result<(), CodexAccountSlotSettingsError> {
    if schema_version != CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION {
        return Err(CodexAccountSlotSettingsError::Invalid(format!(
            "unsupported Codex account-slot schema {schema_version}"
        )));
    }
    Ok(())
}

fn validate_strong_hash(value: &str, label: &str) -> Result<(), CodexAccountSlotSettingsError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CodexAccountSlotSettingsError::Invalid(format!(
            "expected Codex {label} hash must be a lowercase SHA-256 value"
        )));
    }
    Ok(())
}

fn validate_raw_workspace_id(value: &str) -> Result<(), CodexAccountSlotSettingsError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CodexAccountSlotSettingsError::Invalid(
            "Codex workspace id has an unsupported shape".to_string(),
        ));
    }
    Ok(())
}

fn write_codex_home_config(
    home: &Path,
    workspace_id: Option<&str>,
) -> Result<(), CodexAccountSlotSettingsError> {
    if let Some(workspace_id) = workspace_id {
        validate_raw_workspace_id(workspace_id)?;
    }
    let mut body =
        String::from("cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n");
    if let Some(workspace_id) = workspace_id {
        body.push_str(&format!(
            "forced_chatgpt_workspace_id = \"{workspace_id}\"\n"
        ));
    }
    body.push_str("\n[analytics]\nenabled = false\n");
    crate::write_owner_only_file_atomic(&home.join("config.toml"), body.as_bytes()).map_err(
        |error| CodexAccountSlotSettingsError::State(format!("write Codex home config: {error}")),
    )
}

fn ensure_managed_directory(path: &Path) -> Result<(), CodexAccountSlotSettingsError> {
    match create_private_directory(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(CodexAccountSlotSettingsError::State(format!(
                "create managed Codex account directory: {error}"
            )))
        }
    }
    verify_private_directory_descriptor(path)
}

fn create_managed_slot_directory(path: &Path) -> Result<bool, CodexAccountSlotSettingsError> {
    match create_private_directory(path) {
        Ok(()) => {
            verify_private_directory_descriptor(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_managed_directory(path)?;
            Ok(false)
        }
        Err(error) => Err(CodexAccountSlotSettingsError::State(format!(
            "create managed Codex account slot: {error}"
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

fn verify_private_directory_descriptor(path: &Path) -> Result<(), CodexAccountSlotSettingsError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                CodexAccountSlotSettingsError::State(format!(
                    "open managed Codex account directory safely: {error}"
                ))
            })?;
        let fd = directory.as_raw_fd();
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(CodexAccountSlotSettingsError::State(format!(
                "inspect managed Codex account directory: {}",
                std::io::Error::last_os_error()
            )));
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != unsafe { libc::geteuid() }
        {
            return Err(CodexAccountSlotSettingsError::State(
                "managed Codex account path is not an owner-controlled directory".to_string(),
            ));
        }
        if unsafe { libc::fchmod(fd, 0o700) } != 0 {
            return Err(CodexAccountSlotSettingsError::State(format!(
                "protect managed Codex account directory: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            CodexAccountSlotSettingsError::State(format!(
                "inspect managed Codex account directory: {error}"
            ))
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(CodexAccountSlotSettingsError::State(
                "managed Codex account path is not a real directory".to_string(),
            ));
        }
    }
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_store(label: &str) -> (PathBuf, FileCodexAccountSlotSettingsStore) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ottto-codex-account-slots-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test root");
        let store = FileCodexAccountSlotSettingsStore::new(
            root.join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME),
        );
        (root, store)
    }

    #[test]
    fn prepare_is_idempotent_and_creates_private_file_backed_home() {
        let (root, store) = test_store("prepare");
        let operation = format!("codex_setup_{}", "a".repeat(32));
        let first = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                operation.clone(),
                "b".repeat(64),
                "c".repeat(64),
            )
            .expect("prepare");
        let replay = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                operation,
                "b".repeat(64),
                "c".repeat(64),
            )
            .expect("replay");
        assert_eq!(first, replay);
        assert_eq!(first.managed_slots.len(), 1);
        assert!(!store.registered_bindings().expect("bindings")[0].accepted);
        let home = store
            .slot_home(&first.managed_slots[0].slot_id)
            .expect("slot home");
        let config = fs::read_to_string(home.join("config.toml")).expect("config");
        assert!(config.contains("cli_auth_credentials_store = \"file\""));
        assert!(config.contains("forced_login_method = \"chatgpt\""));
        assert!(!config.contains("forced_chatgpt_workspace_id"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_completion_pins_workspace_and_removal_preserves_home() {
        let (root, store) = test_store("complete");
        let operation = format!("codex_setup_{}", "d".repeat(32));
        let prepared = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                operation.clone(),
                "e".repeat(64),
                "f".repeat(64),
            )
            .expect("prepare");
        let slot_id = prepared.managed_slots[0].slot_id.clone();
        let home = store.slot_home(&slot_id).expect("home");
        let complete = store
            .finish_validation(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &operation,
                "e".repeat(64),
                "f".repeat(64),
                "workspace_123",
                false,
            )
            .expect("complete");
        assert_eq!(
            complete.setup_operation.state,
            CodexAccountSetupOperationStateV1::Complete
        );
        assert!(store.registered_bindings().expect("bindings")[0].accepted);
        let replayed_check = store
            .begin_validation(CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION, &operation)
            .expect("completed validation replay");
        assert_eq!(
            replayed_check.setup_operation.state,
            CodexAccountSetupOperationStateV1::Complete
        );
        assert!(store.registered_bindings().expect("bindings")[0].accepted);
        let config = fs::read_to_string(home.join("config.toml")).expect("config");
        assert!(config.contains("forced_chatgpt_workspace_id = \"workspace_123\""));
        let reconnect_operation = format!("codex_setup_{}", "c".repeat(32));
        let reconnect = store
            .begin_reconnect(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                reconnect_operation.clone(),
                &slot_id,
                "e".repeat(64),
                "f".repeat(64),
            )
            .expect("begin reconnect");
        assert_eq!(
            reconnect.setup_operation.state,
            CodexAccountSetupOperationStateV1::WaitingForUserLogin
        );
        assert_eq!(
            reconnect.setup_operation.slot_id.as_deref(),
            Some(slot_id.as_str())
        );
        store
            .fail_validation(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &reconnect_operation,
                "provider temporarily unavailable",
            )
            .expect("failed reconnect observation");
        assert!(
            store.registered_bindings().expect("bindings")[0].accepted,
            "a failed reconnect must preserve the prior durable registration"
        );
        let removed = store
            .remove(CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION, &slot_id)
            .expect("remove");
        assert!(removed.managed_slots.is_empty());
        assert!(home.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unfinished_binding_reuses_slot_but_accepted_binding_rejects_duplicate() {
        let (root, store) = test_store("binding-lifecycle");
        let first_operation = format!("codex_setup_{}", "7".repeat(32));
        let account = "8".repeat(64);
        let workspace = "9".repeat(64);
        let first = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                first_operation.clone(),
                account.clone(),
                workspace.clone(),
            )
            .expect("first prepare");
        let slot_id = first.managed_slots[0].slot_id.clone();
        store
            .stop_waiting(CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION, &first_operation)
            .expect("stop");

        let second_operation = format!("codex_setup_{}", "a".repeat(32));
        let resumed = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                second_operation.clone(),
                account.clone(),
                workspace.clone(),
            )
            .expect("resume existing binding");
        assert_eq!(resumed.managed_slots.len(), 1);
        assert_eq!(
            resumed.setup_operation.slot_id.as_deref(),
            Some(slot_id.as_str())
        );
        store
            .finish_validation(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &second_operation,
                account.clone(),
                workspace.clone(),
                "workspace_accepted",
                false,
            )
            .expect("accept binding");

        let duplicate = store.prepare_managed_account(
            CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
            format!("codex_setup_{}", "b".repeat(32)),
            account,
            workspace,
        );
        assert!(matches!(
            duplicate,
            Err(CodexAccountSlotSettingsError::Invalid(message))
                if message.contains("already has a durable connection")
        ));
        assert_eq!(store.load().expect("status").managed_slots.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mismatch_and_duplicate_never_complete() {
        for (label, account, workspace, duplicate, expected) in [
            (
                "mismatch",
                "1".repeat(64),
                "2".repeat(64),
                false,
                CodexAccountSetupOperationStateV1::IdentityMismatch,
            ),
            (
                "duplicate",
                "3".repeat(64),
                "4".repeat(64),
                true,
                CodexAccountSetupOperationStateV1::DuplicateAccount,
            ),
        ] {
            let (root, store) = test_store(label);
            let operation = format!("codex_setup_{}", "5".repeat(32));
            let expected_account = if duplicate {
                account.clone()
            } else {
                "6".repeat(64)
            };
            let expected_workspace = if duplicate {
                workspace.clone()
            } else {
                "7".repeat(64)
            };
            store
                .prepare_managed_account(
                    CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                    operation.clone(),
                    expected_account,
                    expected_workspace,
                )
                .expect("prepare");
            let status = store
                .finish_validation(
                    CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                    &operation,
                    account,
                    workspace,
                    "workspace_456",
                    duplicate,
                )
                .expect("finish");
            assert_eq!(status.setup_operation.state, expected);
            let _ = fs::remove_dir_all(root);
        }
    }
}
