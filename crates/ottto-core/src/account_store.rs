use anyhow::{Context, Result};
use ottto_protocol::{LocalAccountBinding, SourceHealth};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const ACCOUNT_FILE_NAME: &str = "account.json";
pub const CONNECTION_FILE_NAME: &str = "connection.json";
pub const DEVICE_FILE_NAME: &str = "device.json";
pub const PENDING_DEVICE_CREDENTIAL_FILE_NAME: &str = "pending-device-credential.json";
pub const MACHINE_FILE_NAME: &str = "machine.json";
pub const SETTINGS_FILE_NAME: &str = "settings.json";
pub const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";

pub fn default_support_dir() -> PathBuf {
    if let Ok(path) = std::env::var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR") {
        return PathBuf::from(path);
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Ottto");
    }

    std::env::temp_dir().join("Ottto")
}

pub fn default_account_path() -> PathBuf {
    default_support_dir().join(ACCOUNT_FILE_NAME)
}

pub fn default_connection_path() -> PathBuf {
    default_support_dir().join(CONNECTION_FILE_NAME)
}

pub fn default_device_path() -> PathBuf {
    default_support_dir().join(DEVICE_FILE_NAME)
}

pub fn default_pending_device_credential_path() -> PathBuf {
    default_support_dir().join(PENDING_DEVICE_CREDENTIAL_FILE_NAME)
}

pub fn default_machine_path() -> PathBuf {
    default_support_dir().join(MACHINE_FILE_NAME)
}

/// Path to the per-user persisted daemon settings file
/// (`<support>/settings.json`).
pub fn default_settings_path() -> PathBuf {
    default_support_dir().join(SETTINGS_FILE_NAME)
}

/// Directory holding the per-source daemon state files
/// (`<support>/sources/<slug>-state.json`).
pub fn default_sources_dir() -> PathBuf {
    default_support_dir().join("sources")
}

/// File name for a source's persisted daemon-side state, e.g.
/// `codex-state.json`. The caller supplies the source slug so the naming
/// convention lives in one place regardless of the parent directory.
pub fn source_state_file_name(source_slug: &str) -> String {
    format!("{source_slug}-state.json")
}

pub fn default_connection_api_base_url() -> String {
    std::env::var("OTTTO_API_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConnectionBinding {
    pub setup_run_id: String,
    pub setup_run_token_expires_at: String,
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_code: Option<String>,
    #[serde(default = "default_connection_api_base_url")]
    pub api_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeviceBinding {
    pub device_id: String,
    pub machine_id: Option<String>,
    pub sources: Vec<String>,
}

/// Generation-bound device authority written by the two-phase credential
/// installer. The flattened representation remains readable by released
/// clients that deserialize [`LocalDeviceBinding`] and ignore unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeviceCredentialBinding {
    #[serde(flatten)]
    pub device: LocalDeviceBinding,
    pub credential_generation: u64,
}

/// Exact non-secret authority inputs used to request a prepared relay-device
/// credential. Secret proof bytes remain in Keychain; only their commitment is
/// durable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceCredentialRequestAuthority {
    pub flow: String,
    pub credential_preparation_idempotency_key: String,
    pub machine_id: String,
    pub installation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_continuity_capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_device_sources: Option<Vec<String>>,
    /// One-way binding to the established Keychain secret presented in the
    /// preparation request. The prior secret itself is never journaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_secret_commitment_sha256: Option<String>,
}

/// Non-secret half of a prepared relay-device credential. The candidate
/// secret lives in its own Keychain account so this crash-recovery journal can
/// be inspected and rewritten without ever serializing the secret to JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeviceCredentialPreparation {
    pub schema_version: u16,
    pub capability: String,
    pub preparation_id: String,
    pub api_base_url: String,
    pub expires_at: String,
    pub credential_generation: u64,
    /// One-way binding for the separately staged candidate secret. Recovery
    /// must never promote Keychain bytes that do not match the exact secret
    /// issued for this preparation and generation.
    pub secret_commitment_sha256: String,
    /// Exact non-secret authority inputs used to create this preparation.
    /// Older v2 journals may omit this additive field; all newly staged rows
    /// include it and immutable-journal equality prevents rebinding on retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_authority: Option<PendingDeviceCredentialRequestAuthority>,
    pub device: LocalDeviceBinding,
    /// False while a different-account setup claim waits for explicit local
    /// switch confirmation. Startup recovery must not confirm such a row.
    #[serde(default)]
    pub confirmation_authorized: bool,
    /// Durable evidence that the local pre-confirm cleanup gate completed in
    /// this process. Recovery still reruns the gate under a fresh identity
    /// reservation immediately before any remote confirm.
    #[serde(default)]
    pub preconfirm_guards_passed: bool,
    /// Complete non-secret local claim commit that must move atomically with
    /// this device generation. Its setup-run token is staged separately in
    /// Keychain and is never serialized here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_commit: Option<PendingClaimCredentialCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingClaimCredentialCommit {
    pub account: LocalAccountBinding,
    pub connection: LocalConnectionBinding,
    pub target_user_id: String,
    /// One-way binding for the separately staged setup-run token. This lets a
    /// retry replace an inert orphan Keychain value without serializing the
    /// token into the journal or accepting a changed server response.
    pub setup_run_token_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_cutoff_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMachineBinding {
    pub machine_id: String,
    pub installation_id: String,
    /// Raw hardware identifier (e.g. macOS `IOPlatformUUID`). Absent in
    /// legacy `machine.json` files; the daemon backfills it on next boot.
    #[serde(default)]
    pub hardware_uuid: Option<String>,
}

/// Persisted daemon-side state for a single source. It carries the real
/// first-seen timestamp and the most recent verification-derived health so a
/// daemon restart cannot hide a current Verify failure behind registered-device
/// placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocalSourceState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_health: Option<SourceHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccountStore {
    path: PathBuf,
}

impl FileAccountStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<LocalAccountBinding> {
        if !self.path.exists() {
            return Ok(LocalAccountBinding::not_connected());
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read account binding {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse account binding {}", self.path.display()))
    }

    pub fn save(&self, account: &LocalAccountBinding) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(account)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<LocalAccountBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove account binding {}", self.path.display()))?;
        Ok(Some(existing))
    }
}

impl Default for FileAccountStore {
    fn default() -> Self {
        Self::new(default_account_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConnectionStore {
    path: PathBuf,
}

impl FileConnectionStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<LocalConnectionBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read connection binding {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse connection binding {}", self.path.display()))
    }

    pub fn save(&self, connection: &LocalConnectionBinding) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(connection)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<LocalConnectionBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove connection binding {}", self.path.display()))?;
        Ok(existing)
    }
}

impl Default for FileConnectionStore {
    fn default() -> Self {
        Self::new(default_connection_path())
    }
}

/// Reads and writes one source's `<support>/sources/<slug>-state.json` file,
/// mirroring `FileConnectionStore`. There is no `Default` because the path is
/// per-source; build it from `default_sources_dir()` +
/// `source_state_file_name(slug)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSourceStateStore {
    path: PathBuf,
}

impl FileSourceStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<LocalSourceState>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read source state {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse source state {}", self.path.display()))
    }

    pub fn save(&self, state: &LocalSourceState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(state)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<LocalSourceState>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove source state {}", self.path.display()))?;
        Ok(existing)
    }
}

/// Environment variable that explicitly overrides Claude attribution capture
/// for one process, whatever `settings.json` says.
pub const CLAUDE_ATTRIBUTION_CAPTURE_ENV: &str = "OTTTO_CLAUDE_ATTRIBUTION_CAPTURE";

/// Claude attribution capture is a local opt-IN. Nothing about persistence
/// changes that: with no environment override and no persisted value, capture
/// is off.
pub const CLAUDE_ATTRIBUTION_CAPTURE_DEFAULT: bool = false;

/// Which of the three resolution inputs decided a setting's effective value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingSource {
    /// The reading process's own environment carried an explicit override.
    Environment,
    /// `settings.json` carried a value this build recognizes.
    Persisted,
    /// `settings.json` carried a word this build does not recognize. The value
    /// is ignored and the built-in default applies; this is reported as its own
    /// source rather than as `Default` so an operator can see the difference
    /// between "nothing was ever set" and "what was set means nothing here".
    PersistedInvalid,
    /// Neither input said anything; the built-in default applies.
    Default,
}

impl SettingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SettingSource::Environment => "environment",
            SettingSource::Persisted => "persisted",
            SettingSource::PersistedInvalid => "persisted_invalid",
            SettingSource::Default => "default",
        }
    }
}

/// One resolved boolean setting: what it is, and why it is that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedToggle {
    pub enabled: bool,
    pub source: SettingSource,
}

/// The historical `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE` parse, unchanged: an
/// explicit environment override is ON for exactly these words and OFF for
/// anything else, including a word nobody recognizes.
pub fn claude_attribution_capture_env_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "on" | "1" | "true" | "yes" | "enabled"
    )
}

/// A PERSISTED value must be an explicit word in either direction. Unlike the
/// environment override, an unrecognized word is not silently read as "off":
/// there is no operator intent to honor, so it is invalid and the default
/// applies. Both answers are `false` today; the difference is what the source
/// says, and what happens the day the default changes.
fn persisted_toggle(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" | "enabled" => Some(true),
        "off" | "0" | "false" | "no" | "disabled" => Some(false),
        _ => None,
    }
}

/// Resolve Claude attribution capture from, in order: an explicit environment
/// override, the persisted setting, then the built-in default.
///
/// The environment stays the top of the order so a one-shot
/// `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE=on ottto-service serve` still wins, and so
/// nothing about existing operator muscle memory changes. What changes is the
/// step below it: a LaunchAgent plist regenerated by `brew upgrade` no longer
/// silently means "off", because the persisted value is still there.
pub fn resolve_claude_attribution_capture(
    env_value: Option<&str>,
    persisted_value: Option<&str>,
) -> ResolvedToggle {
    if let Some(raw) = env_value {
        return ResolvedToggle {
            enabled: claude_attribution_capture_env_enabled(raw),
            source: SettingSource::Environment,
        };
    }
    match persisted_value {
        Some(raw) => match persisted_toggle(raw) {
            Some(enabled) => ResolvedToggle {
                enabled,
                source: SettingSource::Persisted,
            },
            None => ResolvedToggle {
                enabled: CLAUDE_ATTRIBUTION_CAPTURE_DEFAULT,
                source: SettingSource::PersistedInvalid,
            },
        },
        None => ResolvedToggle {
            enabled: CLAUDE_ATTRIBUTION_CAPTURE_DEFAULT,
            source: SettingSource::Default,
        },
    }
}

/// Persisted per-user daemon settings (`<support>/settings.json`).
///
/// Values are kept as RAW strings rather than typed booleans on purpose: a word
/// this build does not recognize must degrade to "invalid, use the default" for
/// that one setting, not make the whole file unparseable and take every other
/// setting down with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_attribution_capture: Option<String>,
}

impl LocalSettings {
    /// Resolve Claude attribution capture against a process environment.
    pub fn claude_attribution_capture(&self, env_value: Option<&str>) -> ResolvedToggle {
        resolve_claude_attribution_capture(env_value, self.claude_attribution_capture.as_deref())
    }
}

/// Reads and writes `<support>/settings.json`, mirroring `FileConnectionStore`.
/// Only an explicit operator command writes it; the daemon never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettingsStore {
    path: PathBuf,
}

impl FileSettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<LocalSettings>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read settings {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse settings {}", self.path.display()))
    }

    /// Never fails. A missing, unreadable, or corrupt settings file yields the
    /// empty settings so a bad file can never stop collection; the operator-
    /// facing error belongs to the CLI, which uses `load`.
    pub fn load_lenient(&self) -> LocalSettings {
        self.load().ok().flatten().unwrap_or_default()
    }

    pub fn save(&self, settings: &LocalSettings) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(settings)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<LocalSettings>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove settings {}", self.path.display()))?;
        Ok(existing)
    }
}

impl Default for FileSettingsStore {
    fn default() -> Self {
        Self::new(default_settings_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeviceStore {
    path: PathBuf,
}

impl FileDeviceStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<LocalDeviceBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read device binding {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse device binding {}", self.path.display()))
    }

    pub fn save(&self, device: &LocalDeviceBinding) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(device)?;
        write_user_only(&self.path, &body)
    }

    pub fn load_with_credential_generation(&self) -> Result<Option<LocalDeviceCredentialBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read device binding {}", self.path.display()))?;
        serde_json::from_str(&body).with_context(|| {
            format!(
                "parse generation-bound device binding {}",
                self.path.display()
            )
        })
    }

    pub fn save_with_credential_generation(
        &self,
        device: &LocalDeviceCredentialBinding,
    ) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(device)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<LocalDeviceBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove device binding {}", self.path.display()))?;
        Ok(existing)
    }
}

impl Default for FileDeviceStore {
    fn default() -> Self {
        Self::new(default_device_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePendingDeviceCredentialStore {
    path: PathBuf,
}

impl FilePendingDeviceCredentialStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<PendingDeviceCredentialPreparation>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read pending device credential {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse pending device credential {}", self.path.display()))
    }

    pub fn save(&self, pending: &PendingDeviceCredentialPreparation) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(pending)?;
        write_user_only(&self.path, &body)
    }

    pub fn reset(&self) -> Result<Option<PendingDeviceCredentialPreparation>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove pending device credential {}", self.path.display()))?;
        Ok(existing)
    }
}

impl Default for FilePendingDeviceCredentialStore {
    fn default() -> Self {
        Self::new(default_pending_device_credential_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMachineStore {
    path: PathBuf,
}

impl FileMachineStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<LocalMachineBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let body = fs::read_to_string(&self.path)
            .with_context(|| format!("read machine binding {}", self.path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse machine binding {}", self.path.display()))
    }

    pub fn save(&self, machine: &LocalMachineBinding) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(machine)?;
        write_user_only(&self.path, &body)
    }

    pub fn load_or_create(
        &self,
        create: impl FnOnce() -> Result<LocalMachineBinding>,
    ) -> Result<LocalMachineBinding> {
        if let Some(existing) = self.load()? {
            if is_persistent_machine_id(&existing.machine_id)
                && is_persistent_installation_id(&existing.installation_id)
            {
                return Ok(existing);
            }
        }
        let created = create()?;
        self.save(&created)?;
        Ok(created)
    }

    pub fn reset(&self) -> Result<Option<LocalMachineBinding>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = self.load()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove machine binding {}", self.path.display()))?;
        Ok(existing)
    }
}

impl Default for FileMachineStore {
    fn default() -> Self {
        Self::new(default_machine_path())
    }
}

pub fn is_persistent_machine_id(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("otm_")
        && trimmed.len() >= 20
        && trimmed != "local-development-machine"
        && trimmed != "machine_test"
}

pub fn is_persistent_installation_id(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("oti_")
        && trimmed.len() >= 20
        && trimmed != "local-development-installation"
        && trimmed != "install_test"
}

/// Creates the secret-bearing directory and restricts it to owner-only
/// (`0o700`) so secrecy does not silently depend on an ancestor (`~/Library`)
/// the daemon never controls.
fn create_secret_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create secret dir {}", dir.display()))?;
    crate::token_store::restrict_secret_dir_to_owner(dir)
        .with_context(|| format!("chmod secret dir {}", dir.display()))
}

/// Writes a secret-bearing binding without ever exposing a world-readable or
/// symlink-followable window. Delegates to the shared `0o600`-from-creation
/// atomic writer in `token_store.rs`.
fn write_user_only(path: &Path, body: &[u8]) -> Result<()> {
    crate::token_store::write_secret_file_0600(path, body)
        .with_context(|| format!("write account binding {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{
        LocalAccountOrganization, LocalAccountState, LocalAccountUser, StableMessage,
    };

    #[test]
    fn missing_account_loads_as_not_connected() {
        let store = FileAccountStore::new(temp_path("missing"));
        assert_eq!(
            store.load().expect("load missing").state,
            LocalAccountState::NotConnected
        );
    }

    #[test]
    fn account_store_round_trips_and_resets() {
        let path = temp_path("round-trip");
        let store = FileAccountStore::new(&path);
        let account = connected_account();

        store.save(&account).expect("save account");
        assert_eq!(store.load().expect("load account"), account);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let removed = store.reset().expect("reset account");
        assert_eq!(removed, Some(account));
        assert_eq!(
            store.load().expect("load reset").state,
            LocalAccountState::NotConnected
        );
    }

    #[test]
    fn connection_store_round_trips_and_resets() {
        let path = temp_path("connection");
        let store = FileConnectionStore::new(&path);
        let connection = LocalConnectionBinding {
            setup_run_id: "setup_run_test".to_string(),
            setup_run_token_expires_at: "2026-05-05T11:00:00Z".to_string(),
            machine_id: Some("otm_test".to_string()),
            claim_code: Some("claim_test".to_string()),
            api_base_url: "http://localhost:4318".to_string(),
        };

        assert_eq!(store.load().expect("load missing"), None);
        store.save(&connection).expect("save connection");
        assert_eq!(
            store.load().expect("load connection"),
            Some(connection.clone())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert_eq!(store.reset().expect("reset connection"), Some(connection));
        assert_eq!(store.load().expect("load reset"), None);
    }

    #[test]
    fn generation_bound_device_remains_legacy_readable() {
        let path = temp_path("generation-device").with_file_name(DEVICE_FILE_NAME);
        let store = FileDeviceStore::new(&path);
        let generation_bound = LocalDeviceCredentialBinding {
            device: LocalDeviceBinding {
                device_id: "device-next".to_string(),
                machine_id: Some("machine-one".to_string()),
                sources: vec!["codex".to_string()],
            },
            credential_generation: 7,
        };

        store
            .save_with_credential_generation(&generation_bound)
            .expect("save generation-bound device");

        assert_eq!(
            store.load().expect("legacy load"),
            Some(generation_bound.device.clone())
        );
        assert_eq!(
            store
                .load_with_credential_generation()
                .expect("generation load"),
            Some(generation_bound)
        );
    }

    #[test]
    fn pending_device_credential_store_never_contains_candidate_secret() {
        let path = temp_path("pending-device").with_file_name(PENDING_DEVICE_CREDENTIAL_FILE_NAME);
        let store = FilePendingDeviceCredentialStore::new(&path);
        let pending = PendingDeviceCredentialPreparation {
            schema_version: 1,
            capability: "device_credential_prepare_confirm_v1".to_string(),
            preparation_id: "preparation-one".to_string(),
            api_base_url: "https://api.ottto.net".to_string(),
            expires_at: "2026-08-01T00:00:00Z".to_string(),
            credential_generation: 9,
            secret_commitment_sha256: format!("sha256:{}", "a".repeat(64)),
            request_authority: Some(PendingDeviceCredentialRequestAuthority {
                flow: "setup_claim".to_string(),
                credential_preparation_idempotency_key: format!("sha256:{}", "b".repeat(64)),
                machine_id: "machine-one".to_string(),
                installation_id: "install-one".to_string(),
                hardware_uuid: Some("hardware-one".to_string()),
                account_scope: Some("account-one".to_string()),
                identity_continuity_capability: Some("prior_device_credential_v1".to_string()),
                prior_device_id: Some("device-prior".to_string()),
                prior_device_sources: Some(vec!["codex".to_string()]),
                prior_secret_commitment_sha256: Some(format!("sha256:{}", "c".repeat(64))),
            }),
            device: LocalDeviceBinding {
                device_id: "device-next".to_string(),
                machine_id: Some("machine-one".to_string()),
                sources: vec!["codex".to_string()],
            },
            confirmation_authorized: true,
            preconfirm_guards_passed: true,
            claim_commit: None,
            confirmed_at: None,
        };

        store.save(&pending).expect("save pending");
        let raw = fs::read_to_string(&path).expect("read pending");
        assert!(!raw.contains("candidate_secret"));
        assert!(!raw.contains("prior_device_secret\""));
        assert!(raw.contains("prior_secret_commitment_sha256"));
        assert_eq!(store.load().expect("load pending"), Some(pending.clone()));
        assert_eq!(store.reset().expect("reset pending"), Some(pending));
        assert_eq!(store.load().expect("load reset"), None);
    }

    #[test]
    fn source_state_store_round_trips_and_resets() {
        let path = temp_path("source-state").with_file_name(source_state_file_name("codex"));
        let store = FileSourceStateStore::new(&path);
        let state = LocalSourceState {
            first_seen_at: Some("2026-05-05T09:09:00Z".to_string()),
            last_health: None,
        };

        assert_eq!(store.load().expect("load missing"), None);
        store.save(&state).expect("save source state");
        assert_eq!(
            store.load().expect("load source state"),
            Some(state.clone())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert_eq!(store.reset().expect("reset source state"), Some(state));
        assert_eq!(store.load().expect("load reset"), None);
    }

    #[test]
    fn settings_store_round_trips_and_resets() {
        let path = temp_path("settings").with_file_name(SETTINGS_FILE_NAME);
        let store = FileSettingsStore::new(&path);
        let settings = LocalSettings {
            claude_attribution_capture: Some("on".to_string()),
        };

        assert_eq!(store.load().expect("load missing"), None);
        store.save(&settings).expect("save settings");
        assert_eq!(store.load().expect("load settings"), Some(settings.clone()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert_eq!(store.reset().expect("reset settings"), Some(settings));
        assert_eq!(store.load().expect("load reset"), None);
        assert_eq!(store.load_lenient(), LocalSettings::default());
    }

    #[test]
    fn settings_store_omits_an_unset_setting_from_the_file() {
        let path = temp_path("settings-empty").with_file_name(SETTINGS_FILE_NAME);
        let store = FileSettingsStore::new(&path);

        store
            .save(&LocalSettings::default())
            .expect("save empty settings");

        let raw = fs::read_to_string(&path).expect("read settings");
        assert!(!raw.contains("claude_attribution_capture"));
        assert_eq!(
            store.load().expect("load empty settings"),
            Some(LocalSettings::default())
        );
    }

    #[test]
    fn settings_store_load_lenient_survives_a_corrupt_file() {
        let path = temp_path("settings-corrupt").with_file_name(SETTINGS_FILE_NAME);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create temp parent");
        }
        fs::write(&path, b"{ this is not json").expect("write corrupt settings");
        let store = FileSettingsStore::new(&path);

        assert!(store.load().is_err(), "the operator-facing read reports it");
        assert_eq!(store.load_lenient(), LocalSettings::default());
        assert_eq!(
            store.load_lenient().claude_attribution_capture(None),
            ResolvedToggle {
                enabled: false,
                source: SettingSource::Default,
            }
        );
    }

    #[test]
    fn claude_attribution_capture_defaults_off() {
        let default_enabled: bool = CLAUDE_ATTRIBUTION_CAPTURE_DEFAULT;
        assert!(
            !default_enabled,
            "the shipped default must stay OFF; changing it is a product decision"
        );
        assert_eq!(
            resolve_claude_attribution_capture(None, None),
            ResolvedToggle {
                enabled: false,
                source: SettingSource::Default,
            }
        );
    }

    #[test]
    fn claude_attribution_capture_environment_beats_persisted() {
        for (env, persisted, enabled) in [
            ("on", "off", true),
            ("off", "on", false),
            ("1", "false", true),
            ("disabled", "enabled", false),
        ] {
            assert_eq!(
                resolve_claude_attribution_capture(Some(env), Some(persisted)),
                ResolvedToggle {
                    enabled,
                    source: SettingSource::Environment,
                },
                "env {env:?} over persisted {persisted:?}"
            );
        }
    }

    #[test]
    fn claude_attribution_capture_environment_parsing_is_unchanged() {
        for on in ["on", "1", "true", "yes", "enabled", " ON ", "True"] {
            assert!(claude_attribution_capture_env_enabled(on), "{on:?}");
            assert!(resolve_claude_attribution_capture(Some(on), None).enabled);
        }
        // Anything else, recognized word or not, is off for an env override.
        for off in ["off", "0", "false", "no", "disabled", "", "maybe", "ON!"] {
            assert!(!claude_attribution_capture_env_enabled(off), "{off:?}");
            assert_eq!(
                resolve_claude_attribution_capture(Some(off), None),
                ResolvedToggle {
                    enabled: false,
                    source: SettingSource::Environment,
                },
                "{off:?}"
            );
        }
    }

    #[test]
    fn claude_attribution_capture_persisted_beats_default() {
        for (persisted, enabled) in [
            ("on", true),
            ("1", true),
            ("true", true),
            ("yes", true),
            ("enabled", true),
            (" On ", true),
            ("off", false),
            ("0", false),
            ("false", false),
            ("no", false),
            ("disabled", false),
        ] {
            assert_eq!(
                resolve_claude_attribution_capture(None, Some(persisted)),
                ResolvedToggle {
                    enabled,
                    source: SettingSource::Persisted,
                },
                "persisted {persisted:?}"
            );
        }
    }

    #[test]
    fn malformed_persisted_claude_attribution_capture_is_the_default_off() {
        for persisted in ["", "  ", "maybe", "on!", "yes please", "2"] {
            assert_eq!(
                resolve_claude_attribution_capture(None, Some(persisted)),
                ResolvedToggle {
                    enabled: CLAUDE_ATTRIBUTION_CAPTURE_DEFAULT,
                    source: SettingSource::PersistedInvalid,
                },
                "persisted {persisted:?}"
            );
        }
    }

    #[test]
    fn connection_store_loads_legacy_binding_without_api_base_url() {
        let path = temp_path("connection-legacy");
        let store = FileConnectionStore::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create temp parent");
        }
        fs::write(
            &path,
            br#"{
  "setup_run_id": "setup_run_legacy",
  "setup_run_token_expires_at": "2026-05-05T11:00:00Z",
  "machine_id": "otm_legacy"
}"#,
        )
        .expect("write legacy connection");

        let connection = store.load().expect("load legacy").expect("connection");

        assert_eq!(connection.setup_run_id, "setup_run_legacy");
        assert!(!connection.api_base_url.is_empty());
    }

    #[test]
    fn machine_store_replaces_placeholder_binding() {
        let path = temp_path("machine").with_file_name(MACHINE_FILE_NAME);
        let store = FileMachineStore::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create temp parent");
        }
        fs::write(
            &path,
            br#"{
  "machine_id": "local-development-machine",
  "installation_id": "local-development-installation"
}"#,
        )
        .expect("write placeholder");

        let machine = store
            .load_or_create(|| {
                Ok(LocalMachineBinding {
                    machine_id: "otm_1234567890abcdef".to_string(),
                    installation_id: "oti_1234567890abcdef".to_string(),
                    hardware_uuid: None,
                })
            })
            .expect("load or create machine");

        assert_eq!(machine.machine_id, "otm_1234567890abcdef");
        assert_eq!(store.load().expect("load").expect("machine"), machine);
    }

    #[cfg(unix)]
    #[test]
    fn account_save_creates_owner_only_support_dir() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("dirmode");
        let parent = path.parent().expect("parent").to_path_buf();
        let store = FileAccountStore::new(&path);

        store.save(&connected_account()).expect("save account");

        let mode = fs::metadata(&parent)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        let _ = fs::remove_dir_all(&parent);
    }

    #[cfg(unix)]
    #[test]
    fn account_save_overwrites_symlink_without_following_to_target() {
        let path = temp_path("symlink");
        let dir = path.parent().expect("parent").to_path_buf();
        fs::create_dir_all(&dir).expect("create dir");

        let target = dir.join("attacker-target");
        fs::write(&target, "untouched").expect("seed target");
        std::os::unix::fs::symlink(&target, &path).expect("plant symlink");

        let store = FileAccountStore::new(&path);
        store.save(&connected_account()).expect("save account");

        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "untouched"
        );
        assert!(!fs::symlink_metadata(&path)
            .expect("link metadata")
            .file_type()
            .is_symlink());
        assert_eq!(store.load().expect("load account"), connected_account());
        let _ = fs::remove_dir_all(&dir);
    }

    fn connected_account() -> LocalAccountBinding {
        LocalAccountBinding {
            state: LocalAccountState::Connected,
            user: Some(LocalAccountUser {
                id: "user_test".to_string(),
                email: "ron@example.com".to_string(),
                display_name: Some("Ron".to_string()),
            }),
            organization: Some(LocalAccountOrganization {
                id: "org_test".to_string(),
                name: "Ottto QA".to_string(),
            }),
            connected_at: Some("2026-05-05T10:00:00Z".to_string()),
            last_refreshed_at: Some("2026-05-05T10:00:00Z".to_string()),
            message: Some(StableMessage {
                code: "connected".to_string(),
                text: "Connected".to_string(),
            }),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ottto-account-store-test-{}-{}",
            std::process::id(),
            label
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join(ACCOUNT_FILE_NAME)
    }
}
