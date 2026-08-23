use ottto_protocol::{
    CodexAccountCapacityV1, CodexAccountSetupOperationStateV1, CodexAccountSetupOperationV1,
    CodexAccountSlotCollectionStatusV1, CodexAccountSlotDescriptorV1, CodexAccountSlotOwnershipV1,
    CodexAccountsStatusV1, CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
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
    /// Slots whose managed credential trees must be removed before their
    /// registry rows can be forgotten. This makes deletion restart-safe.
    #[serde(default)]
    deleting_managed_slot_ids: Vec<String>,
    #[serde(default)]
    setup_operation: CodexAccountSetupOperationV1,
    #[serde(default)]
    setup_preserves_accepted_binding: bool,
    /// True after the workspace restriction is durable but before a fresh
    /// restricted provider session has been accepted. The public operation
    /// remains `validating` for backward-compatible clients.
    #[serde(default)]
    verifying_pinned_workspace: bool,
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
            deleting_managed_slot_ids: Vec::new(),
            setup_operation: CodexAccountSetupOperationV1::default(),
            setup_preserves_accepted_binding: false,
            verifying_pinned_workspace: false,
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
        self.recover_pending_deletions()?;
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
        ) || persisted.verifying_pinned_workspace
        {
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
            launch_command: Some(codex_login_command(&home)),
            message: Some(
                "Complete the official Codex sign-in and select the intended workspace."
                    .to_string(),
            ),
        };
        persisted.setup_preserves_accepted_binding = false;
        persisted.verifying_pinned_workspace = false;
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
        ) || persisted.verifying_pinned_workspace
        {
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
            launch_command: Some(codex_login_command(&home)),
            message: Some(
                "Sign in again through Codex for this exact account and workspace.".to_string(),
            ),
        };
        persisted.setup_preserves_accepted_binding = true;
        persisted.verifying_pinned_workspace = false;
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
            if persisted.setup_operation.state == CodexAccountSetupOperationStateV1::Complete
                || persisted.verifying_pinned_workspace
            {
                return Ok(());
            }
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::Validating;
            persisted.setup_operation.message =
                Some("Validating exact Codex identity and quota.".to_string());
            Ok(())
        })
    }

    /// Persist the provider-supported workspace restriction while leaving a
    /// new binding unaccepted. A caller must perform a fresh provider
    /// collection and call [`Self::complete_pinned_verification`] before the
    /// connection becomes durable.
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
            persisted.setup_operation.launch_command = Some(codex_login_command(&home));
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
            if !persisted.setup_preserves_accepted_binding {
                persisted
                    .managed_bindings
                    .get_mut(&slot_id)
                    .ok_or_else(|| {
                        CodexAccountSlotSettingsError::State(
                            "setup operation lost its Codex identity binding".to_string(),
                        )
                    })?
                    .accepted = false;
            }
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::Validating;
            persisted.verifying_pinned_workspace = true;
            persisted.setup_operation.message = Some(
                "Verifying the restricted Codex workspace in a fresh provider session.".to_string(),
            );
        }
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
    }

    pub fn complete_pinned_verification(
        &self,
        schema_version: u16,
        operation_id: &str,
        account_identifier_hash: &str,
        workspace_identifier_hash: &str,
    ) -> Result<CodexAccountsStatusV1, CodexAccountSlotSettingsError> {
        validate_schema_version(schema_version)?;
        validate_setup_operation_id(operation_id)?;
        validate_strong_hash(account_identifier_hash, "account")?;
        validate_strong_hash(workspace_identifier_hash, "workspace")?;
        self.mutate(|persisted| {
            require_setup_operation(persisted, operation_id)?;
            if persisted.setup_operation.state == CodexAccountSetupOperationStateV1::Complete {
                return Ok(());
            }
            if !persisted.verifying_pinned_workspace
                || persisted.setup_operation.account_identifier_hash.as_deref()
                    != Some(account_identifier_hash)
                || persisted
                    .setup_operation
                    .workspace_identifier_hash
                    .as_deref()
                    != Some(workspace_identifier_hash)
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "pinned Codex verification does not match the pending identity".to_string(),
                ));
            }
            let slot_id = persisted
                .setup_operation
                .slot_id
                .as_deref()
                .ok_or_else(|| {
                    CodexAccountSlotSettingsError::State(
                        "pinned verification lost its Codex slot binding".to_string(),
                    )
                })?;
            persisted
                .managed_bindings
                .get_mut(slot_id)
                .ok_or_else(|| {
                    CodexAccountSlotSettingsError::State(
                        "pinned verification lost its Codex identity binding".to_string(),
                    )
                })?
                .accepted = true;
            persisted.setup_operation.state = CodexAccountSetupOperationStateV1::Complete;
            persisted.verifying_pinned_workspace = false;
            persisted.setup_operation.message = Some(
                "Codex limits will remain available for this exact account and workspace."
                    .to_string(),
            );
            Ok(())
        })
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
            persisted.verifying_pinned_workspace = false;
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
            persisted.verifying_pinned_workspace = false;
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
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
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
        if !persisted
            .deleting_managed_slot_ids
            .iter()
            .any(|candidate| candidate == slot_id)
        {
            persisted
                .deleting_managed_slot_ids
                .push(slot_id.to_string());
            persisted.deleting_managed_slot_ids.sort();
            self.write_persisted(&persisted)?;
        }
        self.delete_managed_slot_tree(slot_id)?;
        finalize_managed_slot_deletion(&mut persisted, slot_id);
        self.write_persisted(&persisted)?;
        Ok(status_contract(&persisted))
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

    pub fn is_verifying_pinned_workspace(
        &self,
        operation_id: &str,
    ) -> Result<bool, CodexAccountSlotSettingsError> {
        validate_setup_operation_id(operation_id)?;
        let persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        require_setup_operation(&persisted, operation_id)?;
        Ok(persisted.verifying_pinned_workspace)
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

    fn recover_pending_deletions(&self) -> Result<(), CodexAccountSlotSettingsError> {
        let initial = self.read_persisted()?;
        if initial.deleting_managed_slot_ids.is_empty() {
            return Ok(());
        }
        let _transaction = self.transaction_lock()?;
        let mut persisted = self.read_persisted()?;
        self.validate_persisted(&persisted)?;
        for slot_id in persisted.deleting_managed_slot_ids.clone() {
            self.delete_managed_slot_tree(&slot_id)?;
            finalize_managed_slot_deletion(&mut persisted, &slot_id);
        }
        self.write_persisted(&persisted)
    }

    fn delete_managed_slot_tree(&self, slot_id: &str) -> Result<(), CodexAccountSlotSettingsError> {
        remove_managed_slot_tree_fd(&self.managed_accounts_root()?, slot_id).map_err(|error| {
            CodexAccountSlotSettingsError::State(format!(
                "delete managed Codex credential home: {error}"
            ))
        })
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
        let mut deleting = persisted.deleting_managed_slot_ids.clone();
        for slot_id in &deleting {
            validate_opaque_slot_id(slot_id)?;
            if !persisted
                .managed_slot_ids
                .iter()
                .any(|candidate| candidate == slot_id)
            {
                return Err(CodexAccountSlotSettingsError::Invalid(
                    "Codex deletion tombstone references an unregistered slot".to_string(),
                ));
            }
        }
        deleting.sort();
        deleting.dedup();
        if deleting.len() != persisted.deleting_managed_slot_ids.len() {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "duplicate Codex deletion tombstone".to_string(),
            ));
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
        if persisted.verifying_pinned_workspace
            && (persisted.setup_operation.state != CodexAccountSetupOperationStateV1::Validating
                || persisted.setup_operation.account_identifier_hash.is_none()
                || persisted
                    .setup_operation
                    .workspace_identifier_hash
                    .is_none())
        {
            return Err(CodexAccountSlotSettingsError::Invalid(
                "pinned Codex verification state is incomplete".to_string(),
            ));
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

fn finalize_managed_slot_deletion(persisted: &mut PersistedCodexAccountSlotsV1, slot_id: &str) {
    persisted
        .managed_slot_ids
        .retain(|candidate| candidate != slot_id);
    persisted.managed_bindings.remove(slot_id);
    persisted
        .deleting_managed_slot_ids
        .retain(|candidate| candidate != slot_id);
    if persisted.setup_operation.slot_id.as_deref() == Some(slot_id) {
        persisted.setup_operation = CodexAccountSetupOperationV1::default();
        persisted.setup_preserves_accepted_binding = false;
        persisted.verifying_pinned_workspace = false;
    }
}

#[cfg(unix)]
fn remove_managed_slot_tree_fd(managed_root: &Path, slot_id: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let parent = open_private_directory_chain(managed_root)?;
    let name = CString::new(slot_id).expect("validated opaque slot id");
    let root_fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    let root = unsafe { fs::File::from_raw_fd(root_fd) };
    let mut opened_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(root.as_raw_fd(), opened_stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let opened_stat = unsafe { opened_stat.assume_init() };
    if opened_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || opened_stat.st_uid != unsafe { libc::geteuid() }
        || opened_stat.st_mode & 0o777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed Codex slot root ownership or mode is unsafe",
        ));
    }
    remove_directory_contents_fd(&root)?;
    let mut linked_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            linked_stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    let linked_stat = unsafe { linked_stat.assume_init() };
    if linked_stat.st_dev != opened_stat.st_dev || linked_stat.st_ino != opened_stat.st_ino {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed Codex slot root changed during deletion",
        ));
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    parent.sync_all()
}

#[cfg(unix)]
fn remove_directory_contents_fd(directory: &fs::File) -> std::io::Result<()> {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd};

    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            return Ok(());
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let child = unsafe { fs::File::from_raw_fd(fd) };
            remove_directory_contents_fd(&child)?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        } else if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    })();
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(not(unix))]
fn remove_managed_slot_tree_fd(managed_root: &Path, slot_id: &str) -> std::io::Result<()> {
    fs::remove_dir_all(managed_root.join(slot_id))
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
    write_owner_only_file_at(home, "config.toml", body.as_bytes()).map_err(|error| {
        CodexAccountSlotSettingsError::State(format!("write Codex home config: {error}"))
    })
}

/// Read an exact Codex credential file without following any path component or
/// final-file symlink. The credential home must be owner-controlled mode 0700;
/// the file, when present, must be a regular owner-controlled mode 0600 file.
pub fn read_codex_auth_file_secure(home: &Path) -> std::io::Result<Option<Vec<u8>>> {
    read_safe_file_at(home, "auth.json", true)
}

/// Read Codex configuration without following any path component or final-file
/// symlink. Config must be a regular owner-controlled file and must not be
/// group- or world-writable. Unlike `auth.json`, an existing config may be
/// mode 0644 because Codex historically creates non-secret config that way.
pub fn read_codex_config_file_secure(home: &Path) -> std::io::Result<Option<Vec<u8>>> {
    read_safe_file_at(home, "config.toml", false)
}

fn reject_cloud_sync_root(path: &Path) -> std::io::Result<()> {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(|component| component.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let cloud_component = components.iter().any(|component| {
        component == "mobile documents"
            || component == "cloudstorage"
            || component == "dropbox"
            || component.starts_with("onedrive")
            || component == "google drive"
            || component.starts_with("googledrive")
    });
    if cloud_component {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Codex credential homes cannot be stored under a cloud-sync root",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_directory_chain(path: &Path) -> std::io::Result<fs::File> {
    open_directory_chain(path, true)
}

#[cfg(unix)]
fn open_directory_chain(path: &Path, final_private: bool) -> std::io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    reject_cloud_sync_root(path)?;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Codex credential home must be absolute",
        ));
    }
    let mut directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut components = path.components().peekable();
    let _ = components.next();
    while let Some(component) = components.next() {
        let name = CString::new(component.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in credential path")
        })?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let next = unsafe { fs::File::from_raw_fd(fd) };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(next.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let mode = stat.st_mode & 0o777;
        let current_uid = unsafe { libc::geteuid() };
        let is_home = final_private && components.peek().is_none();
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || (is_home && (stat.st_uid != current_uid || mode != 0o700))
            || (!is_home && ((stat.st_uid != current_uid && stat.st_uid != 0) || mode & 0o022 != 0))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Codex credential path ownership or mode is unsafe",
            ));
        }
        directory = next;
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_private_directory_chain(path: &Path) -> std::io::Result<fs::File> {
    reject_cloud_sync_root(path)?;
    fs::File::open(path)
}

#[cfg(unix)]
fn read_safe_file_at(
    home: &Path,
    name: &str,
    require_mode_0600: bool,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let directory = open_private_directory_chain(home)?;
    let name = CString::new(name).expect("static Codex file name");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode() & 0o777;
    let unsafe_mode = if require_mode_0600 {
        mode != 0o600
    } else {
        mode & 0o022 != 0 || mode & 0o400 == 0
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || unsafe_mode
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Codex credential file ownership, type, or mode is unsafe",
        ));
    }
    if metadata.len() > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Codex credential file is too large",
        ));
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut body)?;
    Ok(Some(body))
}

#[cfg(not(unix))]
fn read_safe_file_at(
    home: &Path,
    name: &str,
    _require_mode_0600: bool,
) -> std::io::Result<Option<Vec<u8>>> {
    match fs::read(home.join(name)) {
        Ok(body) => Ok(Some(body)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn write_owner_only_file_at(home: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let directory = open_private_directory_chain(home)?;
    let target = CString::new(name).expect("static Codex file name");
    let existing = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            target.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if existing >= 0 {
        let existing = unsafe { fs::File::from_raw_fd(existing) };
        let metadata = existing.metadata()?;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "existing Codex config ownership, type, or mode is unsafe",
            ));
        }
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    let nonce = crate::generate_control_token().map_err(std::io::Error::other)?;
    let temp_name = CString::new(format!(".{name}.{}.tmp", &nonce[..16])).expect("temp name");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut temp = unsafe { fs::File::from_raw_fd(fd) };
    let result = temp.write_all(bytes).and_then(|()| temp.sync_all());
    drop(temp);
    if let Err(error) = result {
        unsafe { libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0) };
        return Err(error);
    }
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            temp_name.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        unsafe { libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0) };
        return Err(error);
    }
    directory.sync_all()
}

#[cfg(not(unix))]
fn write_owner_only_file_at(home: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    crate::write_owner_only_file_atomic(&home.join(name), bytes)
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
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        reject_cloud_sync_root(path)?;
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "directory has no parent")
        })?;
        let directory = open_directory_chain(parent, false)?;
        let name = path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory has no file name",
            )
        })?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        directory.sync_all()
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn verify_private_directory_descriptor(path: &Path) -> Result<(), CodexAccountSlotSettingsError> {
    #[cfg(unix)]
    {
        open_private_directory_chain(path).map_err(|error| {
            CodexAccountSlotSettingsError::State(format!(
                "open managed Codex account directory safely: {error}"
            ))
        })?;
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

fn codex_login_command(home: &Path) -> String {
    let home = shell_single_quote(home.to_string_lossy().as_ref());
    format!("CODEX_HOME={home} CODEX_SQLITE_HOME={home} codex login")
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        }
        let root = root.canonicalize().expect("canonical test root");
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
        assert_eq!(
            first.setup_operation.launch_command.as_deref(),
            Some(codex_login_command(&home).as_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_preexisting_credential_root_is_rejected_without_mode_repair() {
        use std::os::unix::fs::PermissionsExt;

        let (root, store) = test_store("unsafe-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("unsafe mode");
        let result = store.prepare_managed_account(
            CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
            format!("codex_setup_{}", "1".repeat(32)),
            "2".repeat(64),
            "3".repeat(64),
        );

        assert!(
            result.is_err(),
            "unsafe pre-existing state must fail closed"
        );
        assert_eq!(
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o777,
            "validation must not chmod-repair unsafe state"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("cleanup mode");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_credential_ancestor_is_rejected_component_by_component() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "ottto-codex-slots-unsafe-ancestor-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let ancestor = base.join("unsafe-parent");
        let support = ancestor.join("support");
        fs::create_dir_all(&support).expect("nested support root");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("private base");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).expect("unsafe ancestor");
        fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).expect("private support");
        let store = FileCodexAccountSlotSettingsStore::new(
            support.join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME),
        );

        assert!(store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                format!("codex_setup_{}", "a".repeat(32)),
                "b".repeat(64),
                "c".repeat(64),
            )
            .is_err());
        assert_eq!(
            fs::metadata(&ancestor)
                .expect("ancestor metadata")
                .permissions()
                .mode()
                & 0o777,
            0o777,
            "ancestor validation must not repair unsafe state"
        );

        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).expect("cleanup mode");
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn cloud_sync_credential_root_and_unsafe_auth_file_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (root, _) = test_store("cloud-root");
        let cloud_support = root.join("Dropbox").join("Ottto");
        fs::create_dir_all(&cloud_support).expect("cloud fixture");
        fs::set_permissions(root.join("Dropbox"), fs::Permissions::from_mode(0o700))
            .expect("cloud parent mode");
        fs::set_permissions(&cloud_support, fs::Permissions::from_mode(0o700))
            .expect("cloud support mode");
        let cloud_store = FileCodexAccountSlotSettingsStore::new(
            cloud_support.join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME),
        );
        assert!(cloud_store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                format!("codex_setup_{}", "4".repeat(32)),
                "5".repeat(64),
                "6".repeat(64),
            )
            .is_err());

        let (safe_root, safe_store) = test_store("unsafe-auth");
        let prepared = safe_store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                format!("codex_setup_{}", "7".repeat(32)),
                "8".repeat(64),
                "9".repeat(64),
            )
            .expect("prepare safe home");
        let home = safe_store
            .slot_home(&prepared.managed_slots[0].slot_id)
            .expect("home");
        fs::write(home.join("auth.json"), b"{}").expect("auth fixture");
        assert!(
            read_codex_auth_file_secure(&home).is_err(),
            "0644 auth must fail"
        );
        fs::remove_file(home.join("auth.json")).expect("remove mode fixture");
        let outside = safe_root.join("outside-auth");
        fs::write(&outside, b"{}").expect("outside fixture");
        symlink(&outside, home.join("auth.json")).expect("auth symlink");
        assert!(
            read_codex_auth_file_secure(&home).is_err(),
            "auth symlink must fail"
        );
        fs::remove_file(home.join("auth.json")).expect("remove auth symlink");
        fs::remove_file(home.join("config.toml")).expect("remove config fixture");
        symlink(&outside, home.join("config.toml")).expect("config symlink");
        assert!(
            read_codex_config_file_secure(&home).is_err(),
            "config symlink must fail"
        );

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(safe_root);
    }

    #[test]
    fn pinned_workspace_verification_resumes_unaccepted_after_restart() {
        let (root, store) = test_store("pinned-restart");
        let operation = format!("codex_setup_{}", "a".repeat(32));
        store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                operation.clone(),
                "b".repeat(64),
                "c".repeat(64),
            )
            .expect("prepare");
        let verifying = store
            .finish_validation(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &operation,
                "b".repeat(64),
                "c".repeat(64),
                "synthetic_workspace",
                false,
            )
            .expect("persist pin");
        assert_eq!(
            verifying.setup_operation.state,
            CodexAccountSetupOperationStateV1::Validating
        );
        assert!(store
            .is_verifying_pinned_workspace(&operation)
            .expect("pinned phase"));
        assert!(!store.registered_bindings().expect("bindings")[0].accepted);

        let restarted = FileCodexAccountSlotSettingsStore::new(store.path.clone());
        let resumed = restarted
            .begin_validation(CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION, &operation)
            .expect("resume after restart");
        assert_eq!(
            resumed.setup_operation.state,
            CodexAccountSetupOperationStateV1::Validating
        );
        assert!(restarted
            .is_verifying_pinned_workspace(&operation)
            .expect("resumed pinned phase"));
        assert!(!restarted.registered_bindings().expect("bindings")[0].accepted);
        restarted
            .complete_pinned_verification(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &operation,
                &"b".repeat(64),
                &"c".repeat(64),
            )
            .expect("complete after fresh verification");
        assert!(restarted.registered_bindings().expect("bindings")[0].accepted);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_removal_deletes_only_managed_home_and_preserves_default_bytes() {
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
        let verifying = store
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
            verifying.setup_operation.state,
            CodexAccountSetupOperationStateV1::Validating
        );
        assert!(store
            .is_verifying_pinned_workspace(&operation)
            .expect("pinned phase"));
        assert!(!store.registered_bindings().expect("bindings")[0].accepted);
        let complete = store
            .complete_pinned_verification(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &operation,
                &"e".repeat(64),
                &"f".repeat(64),
            )
            .expect("complete pinned verification");
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
        let default_home = root.join("default-codex-home");
        fs::create_dir(&default_home).expect("default home fixture");
        let default_bytes = b"synthetic-default-credential-bytes";
        fs::write(default_home.join("auth.json"), default_bytes).expect("default fixture");
        let outside = root.join("external-credential");
        fs::write(&outside, b"synthetic-external-credential").expect("external fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, home.join("credential-link")).expect("managed symlink fixture");
        }
        let removed = store
            .remove(CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION, &slot_id)
            .expect("remove");
        assert!(removed.managed_slots.is_empty());
        assert!(!home.exists(), "managed credential home must be deleted");
        assert_eq!(
            fs::read(default_home.join("auth.json")).expect("unchanged default fixture"),
            default_bytes
        );
        assert_eq!(
            fs::read(&outside).expect("external credential preserved"),
            b"synthetic-external-credential"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_removal_tombstone_recovers_after_restart() {
        let (root, store) = test_store("remove-recovery");
        let prepared = store
            .prepare_managed_account(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                format!("codex_setup_{}", "d".repeat(32)),
                "e".repeat(64),
                "f".repeat(64),
            )
            .expect("prepare");
        let slot_id = prepared.managed_slots[0].slot_id.clone();
        let home = store.slot_home(&slot_id).expect("managed home");
        let mut persisted = store.read_persisted().expect("persisted state");
        persisted.deleting_managed_slot_ids.push(slot_id.clone());
        store
            .write_persisted(&persisted)
            .expect("deletion tombstone");
        fs::remove_dir_all(&home).expect("simulate crash after deleting credential home");

        let restarted = FileCodexAccountSlotSettingsStore::new(store.path.clone());
        let recovered = restarted.load().expect("restart recovery");
        assert!(recovered.managed_slots.is_empty());
        assert!(!home.exists());
        assert!(restarted
            .read_persisted()
            .expect("recovered state")
            .deleting_managed_slot_ids
            .is_empty());
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
            .expect("pin binding");
        store
            .complete_pinned_verification(
                CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
                &second_operation,
                &account,
                &workspace,
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
