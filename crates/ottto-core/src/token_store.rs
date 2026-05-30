use crate::account_store::default_support_dir;
use crate::{OTTTO_CONTROL_TOKEN_ENV, OTTTO_SECRET_FALLBACK_DIR_ENV};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Duration;
use thiserror::Error;

pub const OTTTO_KEYCHAIN_SERVICE: &str = "net.ottto.service";
pub const OTTTO_LEGACY_KEYCHAIN_SERVICE: &str = "net.ottto.locald";
pub const OTTTO_KEYCHAIN_ACCOUNT: &str = "control-token";
pub const OTTTO_SETUP_RUN_TOKEN_ACCOUNT: &str = "setup-run-token";
pub const OTTTO_RELAY_DEVICE_SECRET_ACCOUNT: &str = "relay-device-secret";
pub const CONTROL_TOKEN_FILE_NAME: &str = "control-token";

#[derive(Debug, Error)]
pub enum TokenStoreError {
    #[error("control token is missing")]
    Missing,
    #[error("control token store failed: {0}")]
    Store(String),
    #[error("control token is not valid UTF-8")]
    InvalidUtf8,
}

pub trait ControlTokenStore {
    fn load(&self) -> Result<String, TokenStoreError>;
    fn save(&self, token: &str) -> Result<(), TokenStoreError>;
    fn delete(&self) -> Result<(), TokenStoreError>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryTokenStore {
    values: Arc<Mutex<BTreeMap<String, String>>>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ControlTokenStore for MemoryTokenStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        self.values
            .lock()
            .map_err(|_| TokenStoreError::Store("memory token lock poisoned".to_string()))?
            .get(OTTTO_KEYCHAIN_ACCOUNT)
            .cloned()
            .ok_or(TokenStoreError::Missing)
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        self.values
            .lock()
            .map_err(|_| TokenStoreError::Store("memory token lock poisoned".to_string()))?
            .insert(OTTTO_KEYCHAIN_ACCOUNT.to_string(), token.to_string());
        Ok(())
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        self.values
            .lock()
            .map_err(|_| TokenStoreError::Store("memory token lock poisoned".to_string()))?
            .remove(OTTTO_KEYCHAIN_ACCOUNT);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeychainTokenStore;

#[derive(Debug, Clone)]
pub struct KeychainSecretStore {
    account: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileControlTokenStore {
    path: PathBuf,
}

impl FileControlTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_path() -> PathBuf {
        default_support_dir().join(CONTROL_TOKEN_FILE_NAME)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for FileControlTokenStore {
    fn default() -> Self {
        Self::new(Self::default_path())
    }
}

impl ControlTokenStore for FileControlTokenStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        match fs::read_to_string(&self.path) {
            Ok(value) => {
                let token = value.trim().to_string();
                if token.is_empty() {
                    Err(TokenStoreError::Missing)
                } else {
                    Ok(token)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(TokenStoreError::Missing)
            }
            Err(error) => Err(TokenStoreError::Store(error.to_string())),
        }
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| TokenStoreError::Store(error.to_string()))?;
            set_user_only_directory_permissions(parent)?;
        }
        write_secret_file_0600(&self.path, token.as_bytes())
            .map_err(|error| TokenStoreError::Store(error.to_string()))
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(TokenStoreError::Store(error.to_string())),
        }
    }
}

impl KeychainSecretStore {
    pub const fn new(account: &'static str) -> Self {
        Self { account }
    }
}

#[cfg(target_os = "macos")]
impl ControlTokenStore for KeychainTokenStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).load()
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).save(token)
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).delete()
    }
}

#[cfg(target_os = "macos")]
impl ControlTokenStore for KeychainSecretStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        match load_file_secret(self.account) {
            Ok(token) => return Ok(token),
            Err(TokenStoreError::Missing) => {}
            Err(error) => return Err(error),
        }
        match run_keychain_with_timeout(self.account, "load", keychain_load) {
            Ok(token) => Ok(token),
            Err(TokenStoreError::Missing) => Err(TokenStoreError::Missing),
            Err(error) => match load_file_secret(self.account) {
                Ok(token) => Ok(token),
                Err(TokenStoreError::Missing) => Err(error),
                Err(file_error) => Err(file_error),
            },
        }
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        let token = token.to_string();
        let keychain_token = token.clone();
        match run_keychain_with_timeout(self.account, "save", move |account| {
            keychain_save(account, &keychain_token)
        }) {
            Ok(()) => {
                // Keep the owner-only fallback as a mirror. Dev/preview ad-hoc
                // signatures can churn between installs, and macOS may then
                // deny the new helper access to a Keychain item it created
                // before the update. Stable builds still use Keychain first.
                let _ = save_file_secret(self.account, &token);
                Ok(())
            }
            Err(error) => match save_file_secret(self.account, &token) {
                Ok(()) => Ok(()),
                Err(file_error) => Err(TokenStoreError::Store(format!(
                    "{error}; file fallback failed: {file_error}"
                ))),
            },
        }
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        let keychain_result = run_keychain_with_timeout(self.account, "delete", keychain_delete);
        let file_result = delete_file_secret(self.account);
        match (keychain_result, file_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(TokenStoreError::Missing), Ok(())) => Ok(()),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Ok(())) => Err(error),
            (Err(keychain_error), Err(file_error)) => Err(TokenStoreError::Store(format!(
                "{keychain_error}; file fallback failed: {file_error}"
            ))),
        }
    }
}

#[cfg(target_os = "macos")]
const KEYCHAIN_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

#[cfg(target_os = "macos")]
fn run_keychain_with_timeout<T, F>(
    account: &'static str,
    operation: &'static str,
    work: F,
) -> Result<T, TokenStoreError>
where
    T: Send + 'static,
    F: FnOnce(&'static str) -> Result<T, TokenStoreError> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(work(account));
    });
    receiver
        .recv_timeout(KEYCHAIN_OPERATION_TIMEOUT)
        .map_err(|_| {
            TokenStoreError::Store(format!("keychain {operation} timed out for {account}"))
        })?
}

#[cfg(target_os = "macos")]
fn keychain_load(account: &'static str) -> Result<String, TokenStoreError> {
    use security_framework::passwords::get_generic_password;
    use security_framework_sys::base::errSecItemNotFound;

    let bytes = match get_generic_password(OTTTO_KEYCHAIN_SERVICE, account) {
        Ok(bytes) => bytes,
        Err(error) if error.code() == errSecItemNotFound => {
            return Err(TokenStoreError::Missing);
        }
        Err(error) => return Err(TokenStoreError::Store(error.to_string())),
    };
    String::from_utf8(bytes).map_err(|_| TokenStoreError::InvalidUtf8)
}

#[cfg(target_os = "macos")]
fn keychain_save(account: &'static str, token: &str) -> Result<(), TokenStoreError> {
    use security_framework::passwords::set_generic_password;

    set_generic_password(OTTTO_KEYCHAIN_SERVICE, account, token.as_bytes())
        .map_err(|error| TokenStoreError::Store(error.to_string()))
}

#[cfg(target_os = "macos")]
fn keychain_delete(account: &'static str) -> Result<(), TokenStoreError> {
    use security_framework::passwords::delete_generic_password;
    use security_framework_sys::base::errSecItemNotFound;

    match delete_generic_password(OTTTO_KEYCHAIN_SERVICE, account) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == errSecItemNotFound => Ok(()),
        Err(error) => match keychain_delete_with_security_cli(account) {
            Ok(()) => Ok(()),
            Err(cli_error) => Err(TokenStoreError::Store(format!(
                "{error}; security CLI delete fallback failed: {cli_error}"
            ))),
        },
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete_with_security_cli(account: &'static str) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-s",
            OTTTO_KEYCHAIN_SERVICE,
            "-a",
            account,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success()
        || security_cli_delete_reports_missing(output.status.code(), &output.stderr)
    {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let message = if stderr.is_empty() { stdout } else { stderr };
    Err(if message.is_empty() {
        format!("security exited with status {}", output.status)
    } else {
        message
    })
}

#[cfg(target_os = "macos")]
fn security_cli_delete_reports_missing(exit_code: Option<i32>, stderr: &[u8]) -> bool {
    if exit_code == Some(44) {
        return true;
    }
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    stderr.contains("could not be found") || stderr.contains("item not found")
}

#[cfg(not(target_os = "macos"))]
impl ControlTokenStore for KeychainTokenStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).load()
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).save(token)
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        KeychainSecretStore::new(OTTTO_KEYCHAIN_ACCOUNT).delete()
    }
}

#[cfg(not(target_os = "macos"))]
impl ControlTokenStore for KeychainSecretStore {
    fn load(&self) -> Result<String, TokenStoreError> {
        load_file_secret(self.account)
    }

    fn save(&self, token: &str) -> Result<(), TokenStoreError> {
        save_file_secret(self.account, token)
    }

    fn delete(&self) -> Result<(), TokenStoreError> {
        delete_file_secret(self.account)
    }
}

pub fn client_control_token() -> Result<String, TokenStoreError> {
    if let Ok(token) = std::env::var(OTTTO_CONTROL_TOKEN_ENV) {
        return Ok(token);
    }

    match FileControlTokenStore::default().load() {
        Ok(token) => Ok(token),
        Err(TokenStoreError::Missing) if cfg!(debug_assertions) => {
            Ok("local-development-control-token".to_string())
        }
        Err(error) => Err(error),
    }
}

pub fn load_or_create_control_token() -> Result<String, TokenStoreError> {
    if let Ok(token) = std::env::var(OTTTO_CONTROL_TOKEN_ENV) {
        return Ok(token);
    }

    let store = FileControlTokenStore::default();
    match store.load() {
        Ok(token) => Ok(token),
        Err(TokenStoreError::Missing) => {
            let token = generate_control_token().map_err(TokenStoreError::Store)?;
            store.save(&token)?;
            Ok(token)
        }
        Err(error) => Err(error),
    }
}

pub fn generate_control_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Writes `bytes` to `path` so the secret is never exposed through a
/// world-readable or symlink-followable window.
///
/// A fresh temp file is created in the same directory with `create_new` +
/// mode `0o600`: `create_new` fails if anything (including a pre-planted
/// symlink) already exists at the temp path, so a squatter cannot redirect the
/// write to another target. The temp file is then `rename`d over `path`, which
/// is atomic and preserves the `0o600` mode while overwriting any existing
/// secret. On any failure after creation the temp file is removed.
///
/// Shared with `account_store.rs` (same crate); each caller maps the
/// `io::Error` to its own error type.
#[cfg(unix)]
pub(crate) fn write_secret_file_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut attempt = 0_u32;
    let (mut file, tmp_path) = loop {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let tmp_name = format!(
            ".{}.tmp.{}.{nanos}.{attempt}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("secret"),
            std::process::id(),
        );
        let tmp_path = path.with_file_name(tmp_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => break (file, tmp_path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    };

    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    drop(file);

    if let Err(error) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_secret_file_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Restricts a created secret directory to owner-only (`0o700`) so the secrecy
/// of the files inside does not silently depend on an ancestor (`~/Library`)
/// the daemon never controls. Shared with `account_store.rs`.
#[cfg(unix)]
pub(crate) fn restrict_secret_dir_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn restrict_secret_dir_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn set_user_only_directory_permissions(path: &Path) -> Result<(), TokenStoreError> {
    restrict_secret_dir_to_owner(path).map_err(|error| TokenStoreError::Store(error.to_string()))
}

fn load_file_secret(account: &str) -> Result<String, TokenStoreError> {
    match fs::read_to_string(file_secret_path(account)) {
        Ok(value) => {
            let token = value.trim().to_string();
            if token.is_empty() {
                Err(TokenStoreError::Missing)
            } else {
                Ok(token)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(TokenStoreError::Missing),
        Err(error) => Err(TokenStoreError::Store(error.to_string())),
    }
}

fn save_file_secret(account: &str, token: &str) -> Result<(), TokenStoreError> {
    let path = file_secret_path(account);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| TokenStoreError::Store(error.to_string()))?;
        set_user_only_directory_permissions(parent)?;
    }
    write_secret_file_0600(&path, token.as_bytes())
        .map_err(|error| TokenStoreError::Store(error.to_string()))
}

fn delete_file_secret(account: &str) -> Result<(), TokenStoreError> {
    match fs::remove_file(file_secret_path(account)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TokenStoreError::Store(error.to_string())),
    }
}

fn file_secret_path(account: &str) -> PathBuf {
    file_secret_dir().join(secret_file_name(account))
}

fn file_secret_dir() -> PathBuf {
    std::env::var_os(OTTTO_SECRET_FALLBACK_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_support_dir().join("secrets"))
}

fn secret_file_name(account: &str) -> String {
    account
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_token_store_round_trips() {
        let store = MemoryTokenStore::new();
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));

        store.save("secret-token").expect("save token");
        assert_eq!(store.load().expect("load token"), "secret-token");

        store.delete().expect("delete token");
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }

    #[test]
    fn generated_tokens_are_hex_and_unguessable_length() {
        let token = generate_control_token().expect("token");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn file_control_token_store_round_trips_with_user_only_permissions() {
        let path =
            std::env::temp_dir().join(format!("ottto-control-token-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let store = FileControlTokenStore::new(&path);

        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
        store.save("token_from_file").expect("save token");
        assert_eq!(store.load().expect("load token"), "token_from_file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        store.delete().expect("delete token");
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }

    #[test]
    fn file_secret_store_round_trips_with_sanitized_names_and_user_only_permissions() {
        let dir =
            std::env::temp_dir().join(format!("ottto-secret-fallback-test-{}", std::process::id()));
        let previous = std::env::var_os(OTTTO_SECRET_FALLBACK_DIR_ENV);
        std::env::set_var(OTTTO_SECRET_FALLBACK_DIR_ENV, &dir);

        let account = "setup/run:token";
        assert_eq!(secret_file_name(account), "setup_run_token");
        assert!(matches!(
            load_file_secret(account),
            Err(TokenStoreError::Missing)
        ));

        save_file_secret(account, "secret-value").expect("save fallback secret");
        assert_eq!(
            load_file_secret(account).expect("load fallback secret"),
            "secret-value"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(file_secret_path(account))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        delete_file_secret(account).expect("delete fallback secret");
        assert!(matches!(
            load_file_secret(account),
            Err(TokenStoreError::Missing)
        ));
        let _ = fs::remove_dir_all(&dir);
        if let Some(previous) = previous {
            std::env::set_var(OTTTO_SECRET_FALLBACK_DIR_ENV, previous);
        } else {
            std::env::remove_var(OTTTO_SECRET_FALLBACK_DIR_ENV);
        }
    }

    #[cfg(unix)]
    #[test]
    fn overwriting_existing_secret_file_keeps_user_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "ottto-control-token-overwrite-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let store = FileControlTokenStore::new(&path);

        store.save("first_value").expect("save first");
        store.save("second_value").expect("overwrite");
        assert_eq!(store.load().expect("load"), "second_value");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn writing_secret_does_not_follow_symlink_at_final_path() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-control-token-symlink-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create dir");

        let target = dir.join("attacker-target");
        fs::write(&target, "untouched").expect("seed target");
        let link = dir.join("control-token");
        std::os::unix::fs::symlink(&target, &link).expect("plant symlink");

        let store = FileControlTokenStore::new(&link);
        store
            .save("real_secret")
            .expect("save through symlink path");

        // The symlink's original target must NOT have received the secret; the
        // rename replaced the symlink itself with a fresh regular file.
        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "untouched"
        );
        assert!(!fs::symlink_metadata(&link)
            .expect("link metadata")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_to_string(&link).expect("read link path"),
            "real_secret"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_secret_dir() {
        use std::os::unix::fs::PermissionsExt;

        // Exercise directory hardening via the explicit-path store so the test
        // never mutates the process-global `OTTTO_SECRET_FALLBACK_DIR_ENV` and
        // cannot race the env-driven fallback test running in parallel.
        let dir = std::env::temp_dir().join(format!(
            "ottto-control-token-dirmode-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let store = FileControlTokenStore::new(dir.join(CONTROL_TOKEN_FILE_NAME));

        store.save("off-box-secret").expect("save secret");
        let mode = fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_cli_missing_item_exit_is_clean_delete() {
        assert!(security_cli_delete_reports_missing(Some(44), b""));
        assert!(security_cli_delete_reports_missing(
            Some(1),
            b"The specified item could not be found in the keychain."
        ));
        assert!(!security_cli_delete_reports_missing(
            Some(1),
            b"permission denied"
        ));
    }
}
