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
    ClaudeAccountUpkeepConsentState, ClaudeAccountsStatusV1, ClaudeConfigSlotDescriptorV1,
    ClaudeConfigSlotOwnership, CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub const CLAUDE_OAUTH_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
pub const CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME: &str = "claude-config-slots.json";
pub const MAX_CLAUDE_ACCOUNT_SLOTS: usize = 10;
pub const MAX_REGISTERED_CLAUDE_CONFIG_SLOTS: usize = MAX_CLAUDE_ACCOUNT_SLOTS - 1;
pub const MAX_CLAUDE_CONFIG_DIR_BYTES: usize = 4096;

static CLAUDE_CONFIG_SLOT_SETTINGS_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedClaudeConfigSlotV1 {
    slot_id: String,
    ownership: ClaudeConfigSlotOwnership,
    config_dir: String,
}

impl Default for PersistedClaudeConfigSlotSettingsV1 {
    fn default() -> Self {
        Self {
            schema_version: CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            background_upkeep_consent: false,
            registered_slots: Vec::new(),
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
        let _transaction = CLAUDE_CONFIG_SLOT_SETTINGS_TRANSACTION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| {
                ClaudeConfigSlotSettingsError::State(
                    "settings transaction lock is poisoned".to_string(),
                )
            })?;
        validate_schema_version(schema_version)?;
        let mut persisted = self.load_persisted()?;
        mutation(&mut persisted)?;
        validate_persisted(&persisted)?;
        let body = serde_json::to_vec_pretty(&persisted).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("serialize settings: {error}"))
        })?;
        crate::write_owner_only_file_atomic(&self.path, &body).map_err(|error| {
            ClaudeConfigSlotSettingsError::State(format!("write settings: {error}"))
        })?;
        Ok(status_contract(&persisted))
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
    Ok(())
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

fn status_contract(persisted: &PersistedClaudeConfigSlotSettingsV1) -> ClaudeAccountsStatusV1 {
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
    ClaudeAccountsStatusV1 {
        schema_version: persisted.schema_version,
        consent: if persisted.background_upkeep_consent {
            ClaudeAccountUpkeepConsentState::Granted
        } else {
            ClaudeAccountUpkeepConsentState::ConsentRequired
        },
        setup_operation: ClaudeAccountSetupOperationV1 {
            state: ClaudeAccountSetupOperationState::Idle,
        },
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
}
