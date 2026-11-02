use anyhow::{Context, Result};
use ottto_protocol::{LocalAccountBinding, SourceHealth};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const ACCOUNT_FILE_NAME: &str = "account.json";
pub const CONNECTION_FILE_NAME: &str = "connection.json";
pub const DEVICE_FILE_NAME: &str = "device.json";
pub const PRIOR_DEVICE_FILE_NAME: &str = "prior-device.json";
pub const PENDING_DEVICE_CREDENTIAL_FILE_NAME: &str = "pending-device-credential.json";
pub const MACHINE_FILE_NAME: &str = "machine.json";
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

pub fn default_prior_device_path() -> PathBuf {
    default_support_dir().join(PRIOR_DEVICE_FILE_NAME)
}

pub fn default_pending_device_credential_path() -> PathBuf {
    default_support_dir().join(PENDING_DEVICE_CREDENTIAL_FILE_NAME)
}

pub fn default_machine_path() -> PathBuf {
    default_support_dir().join(MACHINE_FILE_NAME)
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

/// How a store reads its file: stores differ in whether the read is capped and in
/// the error context a failed open reports.
enum BodyRead {
    Uncapped,
    /// Capped; a failed open reports `open <noun> <path>`.
    Capped(crate::CredentialFileCapRefused),
    /// Capped; a failed open reports `read <noun> <path>`.
    CappedOpenAsRead(crate::CredentialFileCapRefused),
}

/// One store's JSON file: its path, the noun its error messages use and how its
/// body is read.
struct JsonFile<'a> {
    path: &'a Path,
    noun: &'static str,
    read: BodyRead,
}

impl JsonFile<'_> {
    fn read_body(&self) -> Result<String> {
        let path = self.path;
        let noun = self.noun;
        match self.read {
            BodyRead::Uncapped => {
                fs::read_to_string(path).with_context(|| format!("read {noun} {}", path.display()))
            }
            BodyRead::Capped(cap) => {
                let file = fs::File::open(path)
                    .with_context(|| format!("open {noun} {}", path.display()))?;
                crate::credential_file::read(file, cap)
                    .with_context(|| format!("read {noun} {}", path.display()))
            }
            BodyRead::CappedOpenAsRead(cap) => fs::File::open(path)
                .and_then(|file| crate::credential_file::read(file, cap))
                .with_context(|| format!("read {noun} {}", path.display())),
        }
    }

    /// Parses the file into `T`, or returns `missing()` when there is no file.
    fn load_or<T: DeserializeOwned>(&self, missing: impl FnOnce() -> T) -> Result<T> {
        self.load_or_parsing_as(self.noun, missing)
    }

    /// [`Self::load_or`] with a different noun in the parse error only.
    fn load_or_parsing_as<T: DeserializeOwned>(
        &self,
        parse_noun: &str,
        missing: impl FnOnce() -> T,
    ) -> Result<T> {
        if !self.path.exists() {
            return Ok(missing());
        }
        let body = self.read_body()?;
        serde_json::from_str(&body)
            .with_context(|| format!("parse {parse_noun} {}", self.path.display()))
    }

    fn save<T: Serialize>(&self, value: &T) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_secret_dir(parent)?;
        }
        let body = serde_json::to_vec_pretty(value)?;
        write_user_only(self.path, &body)
    }

    /// Loads the file and then removes it; `None` when there is no file. A file
    /// that does not load stays in place.
    fn take<T>(&self, load: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let existing = load()?;
        fs::remove_file(self.path)
            .with_context(|| format!("remove {} {}", self.noun, self.path.display()))?;
        Ok(Some(existing))
    }
}

/// The part every file store shares: the struct, `new`, `path`, `save`, and
/// `Default` when the store has a default path. Each store writes its own `load`
/// and `reset`, whose missing-file results differ.
macro_rules! json_file_store {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            noun: $noun:literal,
            read: $read:expr,
            saves: $saved:ty,
            $(default_path: $default_path:ident,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            path: PathBuf,
        }

        impl $name {
            pub fn new(path: impl Into<PathBuf>) -> Self {
                Self { path: path.into() }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }

            pub fn save(&self, value: &$saved) -> Result<()> {
                self.file().save(value)
            }

            fn file(&self) -> JsonFile<'_> {
                JsonFile {
                    path: &self.path,
                    noun: $noun,
                    read: $read,
                }
            }
        }

        $(
            impl Default for $name {
                fn default() -> Self {
                    Self::new($default_path())
                }
            }
        )?
    };
}

json_file_store! {
    pub struct FileAccountStore {
        noun: "account binding",
        read: BodyRead::Uncapped,
        saves: LocalAccountBinding,
        default_path: default_account_path,
    }
}

impl FileAccountStore {
    pub fn load(&self) -> Result<LocalAccountBinding> {
        self.file().load_or(LocalAccountBinding::not_connected)
    }

    pub fn reset(&self) -> Result<Option<LocalAccountBinding>> {
        self.file().take(|| self.load())
    }
}

json_file_store! {
    pub struct FileConnectionStore {
        noun: "connection binding",
        read: BodyRead::Capped(crate::CredentialFileCapRefused::ConnectionBinding),
        saves: LocalConnectionBinding,
        default_path: default_connection_path,
    }
}

impl FileConnectionStore {
    pub fn load(&self) -> Result<Option<LocalConnectionBinding>> {
        self.file().load_or(|| None)
    }

    pub fn reset(&self) -> Result<Option<LocalConnectionBinding>> {
        self.file().take(|| self.load()).map(Option::flatten)
    }
}

json_file_store! {
    /// Reads and writes one source's `<support>/sources/<slug>-state.json` file,
    /// mirroring `FileConnectionStore`. There is no `Default` because the path is
    /// per-source; build it from `default_sources_dir()` +
    /// `source_state_file_name(slug)`.
    pub struct FileSourceStateStore {
        noun: "source state",
        read: BodyRead::Uncapped,
        saves: LocalSourceState,
    }
}

impl FileSourceStateStore {
    pub fn load(&self) -> Result<Option<LocalSourceState>> {
        self.file().load_or(|| None)
    }

    pub fn reset(&self) -> Result<Option<LocalSourceState>> {
        self.file().take(|| self.load()).map(Option::flatten)
    }
}

json_file_store! {
    pub struct FileDeviceStore {
        noun: "device binding",
        read: BodyRead::CappedOpenAsRead(crate::CredentialFileCapRefused::DeviceBinding),
        saves: LocalDeviceBinding,
        default_path: default_device_path,
    }
}

impl FileDeviceStore {
    pub fn load(&self) -> Result<Option<LocalDeviceBinding>> {
        self.file().load_or(|| None)
    }

    pub fn load_with_credential_generation(&self) -> Result<Option<LocalDeviceCredentialBinding>> {
        self.file()
            .load_or_parsing_as("generation-bound device binding", || None)
    }

    pub fn save_with_credential_generation(
        &self,
        device: &LocalDeviceCredentialBinding,
    ) -> Result<()> {
        self.file().save(device)
    }

    pub fn reset(&self) -> Result<Option<LocalDeviceBinding>> {
        self.file().take(|| self.load()).map(Option::flatten)
    }
}

json_file_store! {
    pub struct FilePendingDeviceCredentialStore {
        noun: "pending device credential",
        read: BodyRead::Capped(crate::CredentialFileCapRefused::PendingDeviceCredential),
        saves: PendingDeviceCredentialPreparation,
        default_path: default_pending_device_credential_path,
    }
}

impl FilePendingDeviceCredentialStore {
    pub fn load(&self) -> Result<Option<PendingDeviceCredentialPreparation>> {
        self.file().load_or(|| None)
    }

    pub fn reset(&self) -> Result<Option<PendingDeviceCredentialPreparation>> {
        self.file().take(|| self.load()).map(Option::flatten)
    }
}

json_file_store! {
    pub struct FileMachineStore {
        noun: "machine binding",
        read: BodyRead::Uncapped,
        saves: LocalMachineBinding,
        default_path: default_machine_path,
    }
}

impl FileMachineStore {
    pub fn load(&self) -> Result<Option<LocalMachineBinding>> {
        self.file().load_or(|| None)
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
        self.file().take(|| self.load()).map(Option::flatten)
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
    fn connection_and_pending_credential_loads_enforce_64_kib_boundary() {
        let path = temp_path("retry-other-authority-size-bound");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for pending in [false, true] {
            let load = || {
                if pending {
                    FilePendingDeviceCredentialStore::new(&path)
                        .load()
                        .map(|v| v.is_none())
                } else {
                    FileConnectionStore::new(&path).load().map(|v| v.is_none())
                }
            };
            let mut bytes = b"null".to_vec();
            bytes.resize(64 * 1024, b' ');
            fs::write(&path, &bytes).unwrap();
            assert!(load().unwrap());
            bytes.push(b' ');
            fs::write(&path, &bytes).unwrap();
            let error = load().unwrap_err();
            assert!(format!("{error:#}").contains("exceeds 64 KiB"));
            assert!(error
                .chain()
                .filter_map(|e| e.downcast_ref::<std::io::Error>())
                .any(|e| e
                    .get_ref()
                    .is_some_and(|e| e.is::<crate::CredentialFileCapRefused>())));
            fs::remove_file(&path).unwrap();
            assert!(load().unwrap());
        }
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn device_binding_loads_enforce_64_kib_boundary() {
        let path = temp_path("device-size-bound");
        let store = FileDeviceStore::new(&path);
        let binding = LocalDeviceCredentialBinding {
            device: LocalDeviceBinding {
                device_id: "synthetic-device".into(),
                machine_id: None,
                sources: vec!["pi".into()],
            },
            credential_generation: 1,
        };
        store.save_with_credential_generation(&binding).unwrap();
        let mut bytes = serde_json::to_vec(&binding).unwrap();
        bytes.resize(64 * 1024, b' ');
        fs::write(&path, &bytes).unwrap();
        assert_eq!(store.load().unwrap(), Some(binding.device.clone()));
        assert_eq!(
            store.load_with_credential_generation().unwrap(),
            Some(binding)
        );
        bytes.push(b' ');
        fs::write(&path, &bytes).unwrap();
        for error in [
            store.load().unwrap_err(),
            store.load_with_credential_generation().unwrap_err(),
        ] {
            assert!(format!("{error:#}").contains("exceeds 64 KiB"));
        }
        fs::remove_file(path).unwrap();
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
            can_reconnect: None,
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
