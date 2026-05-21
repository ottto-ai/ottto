use anyhow::{Context, Result};
use ottto_protocol::LocalAccountBinding;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const ACCOUNT_FILE_NAME: &str = "account.json";
pub const CONNECTION_FILE_NAME: &str = "connection.json";
pub const DEVICE_FILE_NAME: &str = "device.json";
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

pub fn default_machine_path() -> PathBuf {
    default_support_dir().join(MACHINE_FILE_NAME)
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
    #[serde(default = "default_connection_api_base_url")]
    pub api_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeviceBinding {
    pub device_id: String,
    pub machine_id: Option<String>,
    pub sources: Vec<String>,
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
            fs::create_dir_all(parent)
                .with_context(|| format!("create account dir {}", parent.display()))?;
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
            fs::create_dir_all(parent)
                .with_context(|| format!("create connection dir {}", parent.display()))?;
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
            fs::create_dir_all(parent)
                .with_context(|| format!("create device dir {}", parent.display()))?;
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
            fs::create_dir_all(parent)
                .with_context(|| format!("create machine dir {}", parent.display()))?;
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

fn write_user_only(path: &Path, body: &[u8]) -> Result<()> {
    fs::write(path, body).with_context(|| format!("write account binding {}", path.display()))?;
    set_user_only_permissions(path)
}

#[cfg(unix)]
fn set_user_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod account binding {}", path.display()))
}

#[cfg(not(unix))]
fn set_user_only_permissions(_path: &Path) -> Result<()> {
    Ok(())
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
