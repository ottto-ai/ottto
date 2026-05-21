use ottto_protocol::SourceKind;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const TELEMETRY_KEY_SERVICE_PREFIX: &str = "ottto-telemetry-key-";
pub const CODEX_TELEMETRY_KEY_SERVICE: &str = "ottto-telemetry-key-codex";
pub const CLAUDE_CODE_TELEMETRY_KEY_SERVICE: &str = "ottto-telemetry-key-claude_code";
pub const TELEMETRY_KEY_FILE_STORE_ENV: &str = "OTTTO_TELEMETRY_KEY_STORE_DIR";

fn is_directory_not_empty(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOTEMPTY)
}

#[derive(Debug)]
pub enum TelemetryKeychainError {
    UnsupportedSource(SourceKind),
    EmptyKeyId,
    Missing,
    InvalidUtf8,
    Io { path: PathBuf, source: io::Error },
    Store(String),
}

impl fmt::Display for TelemetryKeychainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetryKeychainError::UnsupportedSource(source) => {
                write!(
                    formatter,
                    "telemetry key storage is unsupported for {source:?}"
                )
            }
            TelemetryKeychainError::EmptyKeyId => write!(formatter, "telemetry key id is required"),
            TelemetryKeychainError::Missing => write!(formatter, "telemetry key is missing"),
            TelemetryKeychainError::InvalidUtf8 => {
                write!(formatter, "telemetry key is not valid UTF-8")
            }
            TelemetryKeychainError::Io { path, source } => {
                write!(
                    formatter,
                    "telemetry key file operation failed for {}: {source}",
                    path.display()
                )
            }
            TelemetryKeychainError::Store(message) => {
                write!(formatter, "telemetry key store operation failed: {message}")
            }
        }
    }
}

impl std::error::Error for TelemetryKeychainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TelemetryKeychainError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryKeyRef {
    pub source: SourceKind,
    pub key_id: String,
}

impl TelemetryKeyRef {
    pub fn target(&self) -> String {
        format!(
            "{}/{}",
            telemetry_key_service(&self.source).expect("validated source"),
            self.key_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryKeyStore {
    file_root: PathBuf,
    keychain_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryKeySweepResult {
    pub removed: Vec<TelemetryKeyRef>,
    pub missing: Vec<TelemetryKeyRef>,
    pub warnings: Vec<String>,
}

impl TelemetryKeyStore {
    pub fn production() -> Self {
        if let Some(root) = std::env::var_os(TELEMETRY_KEY_FILE_STORE_ENV) {
            return Self::file_only(PathBuf::from(root));
        }
        Self {
            file_root: ottto_core::default_support_dir().join("telemetry-keys"),
            keychain_enabled: cfg!(target_os = "macos"),
        }
    }

    pub fn file_only(root: impl Into<PathBuf>) -> Self {
        Self {
            file_root: root.into(),
            keychain_enabled: false,
        }
    }

    pub fn save(
        &self,
        source: &SourceKind,
        key_id: &str,
        secret: &str,
    ) -> Result<(), TelemetryKeychainError> {
        let reference = key_ref(source, key_id)?;
        if self.keychain_enabled {
            save_keychain_secret(&reference.source, &reference.key_id, secret)?;
            if let Err(error) = self.save_index_file(&reference) {
                let _ = delete_keychain_secret(&reference.source, &reference.key_id);
                return Err(error);
            }
            return Ok(());
        }
        self.save_file_secret(&reference, secret)
    }

    pub fn load(
        &self,
        source: &SourceKind,
        key_id: &str,
    ) -> Result<String, TelemetryKeychainError> {
        let reference = key_ref(source, key_id)?;
        if self.keychain_enabled {
            return load_keychain_secret(&reference.source, &reference.key_id);
        }
        self.load_file_secret(&reference)
    }

    pub fn delete(
        &self,
        source: &SourceKind,
        key_id: &str,
    ) -> Result<bool, TelemetryKeychainError> {
        let reference = key_ref(source, key_id)?;
        if self.keychain_enabled {
            let removed_keychain = delete_keychain_secret(&reference.source, &reference.key_id)?;
            let removed_index = self.delete_index_file(&reference)?;
            return Ok(removed_keychain || removed_index);
        }
        self.delete_file_secret(&reference)
    }

    pub fn latest_key_id(
        &self,
        source: &SourceKind,
    ) -> Result<Option<String>, TelemetryKeychainError> {
        let mut key_ids = self
            .indexed_refs()?
            .into_iter()
            .filter(|reference| reference.source == *source)
            .map(|reference| reference.key_id)
            .collect::<Vec<_>>();
        key_ids.sort();
        Ok(key_ids.pop())
    }

    pub fn sweep_all(&self) -> Result<TelemetryKeySweepResult, TelemetryKeychainError> {
        let mut result = TelemetryKeySweepResult {
            removed: Vec::new(),
            missing: Vec::new(),
            warnings: Vec::new(),
        };
        for reference in self.indexed_refs()? {
            match self.delete(&reference.source, &reference.key_id) {
                Ok(true) => result.removed.push(reference),
                Ok(false) => result.missing.push(reference),
                Err(error) => result
                    .warnings
                    .push(format!("failed to remove telemetry key: {error}")),
            }
        }
        for service in [
            CODEX_TELEMETRY_KEY_SERVICE,
            CLAUDE_CODE_TELEMETRY_KEY_SERVICE,
        ] {
            let path = self.file_root.join(service);
            match fs::remove_dir(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if is_directory_not_empty(&error) => {}
                Err(error) => result.warnings.push(format!(
                    "failed to remove telemetry key directory {}: {error}",
                    path.display()
                )),
            }
        }
        match fs::remove_dir(&self.file_root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if is_directory_not_empty(&error) => {}
            Err(error) => result.warnings.push(format!(
                "failed to remove telemetry key root {}: {error}",
                self.file_root.display()
            )),
        }
        Ok(result)
    }

    fn save_index_file(&self, reference: &TelemetryKeyRef) -> Result<(), TelemetryKeychainError> {
        let path = self.file_path(reference);
        self.ensure_file_parent(&path)?;
        fs::write(&path, b"").map_err(|source| TelemetryKeychainError::Io {
            path: path.clone(),
            source,
        })?;
        set_user_only_permissions(&path)
    }

    fn save_file_secret(
        &self,
        reference: &TelemetryKeyRef,
        secret: &str,
    ) -> Result<(), TelemetryKeychainError> {
        let path = self.file_path(reference);
        self.ensure_file_parent(&path)?;
        fs::write(&path, secret).map_err(|source| TelemetryKeychainError::Io {
            path: path.clone(),
            source,
        })?;
        set_user_only_permissions(&path)
    }

    fn load_file_secret(
        &self,
        reference: &TelemetryKeyRef,
    ) -> Result<String, TelemetryKeychainError> {
        let path = self.file_path(reference);
        match fs::read_to_string(&path) {
            Ok(secret) => Ok(secret),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(TelemetryKeychainError::Missing)
            }
            Err(error) => Err(TelemetryKeychainError::Io {
                path,
                source: error,
            }),
        }
    }

    fn delete_index_file(
        &self,
        reference: &TelemetryKeyRef,
    ) -> Result<bool, TelemetryKeychainError> {
        self.delete_file_secret(reference)
    }

    fn delete_file_secret(
        &self,
        reference: &TelemetryKeyRef,
    ) -> Result<bool, TelemetryKeychainError> {
        let path = self.file_path(reference);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(TelemetryKeychainError::Io {
                path,
                source: error,
            }),
        }
    }

    fn indexed_refs(&self) -> Result<Vec<TelemetryKeyRef>, TelemetryKeychainError> {
        let mut refs = Vec::new();
        for source in [SourceKind::Codex, SourceKind::ClaudeCode] {
            let service = telemetry_key_service(&source)?;
            let directory = self.file_root.join(service);
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(TelemetryKeychainError::Io {
                        path: directory,
                        source: error,
                    })
                }
            };
            for entry in entries {
                let entry = entry.map_err(|source| TelemetryKeychainError::Io {
                    path: directory.clone(),
                    source,
                })?;
                if !entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(file_name) = entry.file_name().to_str().map(|value| value.to_string())
                else {
                    continue;
                };
                refs.push(TelemetryKeyRef {
                    source: source.clone(),
                    key_id: unsanitize_file_component(&file_name),
                });
            }
        }
        Ok(refs)
    }

    fn file_path(&self, reference: &TelemetryKeyRef) -> PathBuf {
        self.file_root
            .join(telemetry_key_service(&reference.source).expect("validated source"))
            .join(sanitize_file_component(&reference.key_id))
    }

    fn ensure_file_parent(&self, path: &Path) -> Result<(), TelemetryKeychainError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        fs::create_dir_all(&self.file_root).map_err(|source| TelemetryKeychainError::Io {
            path: self.file_root.clone(),
            source,
        })?;
        set_user_only_directory_permissions(&self.file_root)?;
        fs::create_dir_all(parent).map_err(|source| TelemetryKeychainError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        set_user_only_directory_permissions(parent)
    }
}

pub fn telemetry_key_service(source: &SourceKind) -> Result<&'static str, TelemetryKeychainError> {
    match source {
        SourceKind::Codex => Ok(CODEX_TELEMETRY_KEY_SERVICE),
        SourceKind::ClaudeCode => Ok(CLAUDE_CODE_TELEMETRY_KEY_SERVICE),
        SourceKind::Pi => Err(TelemetryKeychainError::UnsupportedSource(source.clone())),
    }
}

pub fn key_ref(
    source: &SourceKind,
    key_id: &str,
) -> Result<TelemetryKeyRef, TelemetryKeychainError> {
    let key_id = key_id.trim();
    if key_id.is_empty() {
        return Err(TelemetryKeychainError::EmptyKeyId);
    }
    telemetry_key_service(source)?;
    Ok(TelemetryKeyRef {
        source: source.clone(),
        key_id: key_id.to_string(),
    })
}

fn sanitize_file_component(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn unsanitize_file_component(value: &str) -> String {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(hex);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(target_os = "macos")]
fn save_keychain_secret(
    source: &SourceKind,
    key_id: &str,
    secret: &str,
) -> Result<(), TelemetryKeychainError> {
    use security_framework::passwords::set_generic_password;

    let service = telemetry_key_service(source)?;
    let _ = delete_keychain_secret(source, key_id);
    set_generic_password(service, key_id, secret.as_bytes())
        .map_err(|error| TelemetryKeychainError::Store(error.to_string()))
}

#[cfg(not(target_os = "macos"))]
fn save_keychain_secret(
    _source: &SourceKind,
    _key_id: &str,
    _secret: &str,
) -> Result<(), TelemetryKeychainError> {
    Err(TelemetryKeychainError::Store(
        "macOS Keychain is unavailable on this platform".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn load_keychain_secret(
    source: &SourceKind,
    key_id: &str,
) -> Result<String, TelemetryKeychainError> {
    use security_framework::passwords::get_generic_password;
    use security_framework_sys::base::errSecItemNotFound;

    let service = telemetry_key_service(source)?;
    match get_generic_password(service, key_id) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| TelemetryKeychainError::InvalidUtf8),
        Err(error) if error.code() == errSecItemNotFound => Err(TelemetryKeychainError::Missing),
        Err(error) => Err(TelemetryKeychainError::Store(error.to_string())),
    }
}

#[cfg(not(target_os = "macos"))]
fn load_keychain_secret(
    _source: &SourceKind,
    _key_id: &str,
) -> Result<String, TelemetryKeychainError> {
    Err(TelemetryKeychainError::Missing)
}

#[cfg(target_os = "macos")]
fn delete_keychain_secret(
    source: &SourceKind,
    key_id: &str,
) -> Result<bool, TelemetryKeychainError> {
    use security_framework::passwords::delete_generic_password;
    use security_framework_sys::base::errSecItemNotFound;

    let service = telemetry_key_service(source)?;
    match delete_generic_password(service, key_id) {
        Ok(()) => Ok(true),
        Err(error) if error.code() == errSecItemNotFound => Ok(false),
        Err(error) => match keychain_delete_with_security_cli(service, key_id) {
            Ok(removed) => Ok(removed),
            Err(cli_error) => Err(TelemetryKeychainError::Store(format!(
                "{error}; security CLI delete fallback failed: {cli_error}"
            ))),
        },
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete_with_security_cli(service: &str, key_id: &str) -> Result<bool, String> {
    let output = std::process::Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", service, "-a", key_id])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(true);
    }
    if security_cli_delete_reports_missing(output.status.code(), &output.stderr) {
        return Ok(false);
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
fn delete_keychain_secret(
    _source: &SourceKind,
    _key_id: &str,
) -> Result<bool, TelemetryKeychainError> {
    Ok(false)
}

fn set_user_only_permissions(path: &Path) -> Result<(), TelemetryKeychainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| TelemetryKeychainError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn set_user_only_directory_permissions(path: &Path) -> Result<(), TelemetryKeychainError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, permissions).map_err(|source| TelemetryKeychainError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_root(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("ottto-telemetry-key-tests")
            .join(format!("{}-{name}-{counter}", std::process::id()))
    }

    #[test]
    fn service_names_are_source_scoped() {
        assert_eq!(
            telemetry_key_service(&SourceKind::Codex).expect("codex"),
            "ottto-telemetry-key-codex"
        );
        assert_eq!(
            telemetry_key_service(&SourceKind::ClaudeCode).expect("claude"),
            "ottto-telemetry-key-claude_code"
        );
    }

    #[test]
    fn pi_is_not_a_keychain_telemetry_source() {
        assert!(matches!(
            telemetry_key_service(&SourceKind::Pi),
            Err(TelemetryKeychainError::UnsupportedSource(SourceKind::Pi))
        ));
    }

    #[test]
    fn empty_key_id_is_rejected() {
        assert!(matches!(
            key_ref(&SourceKind::Codex, "  "),
            Err(TelemetryKeychainError::EmptyKeyId)
        ));
    }

    #[test]
    fn file_only_store_saves_loads_and_deletes_key() {
        let store = TelemetryKeyStore::file_only(test_root("roundtrip"));

        store
            .save(&SourceKind::Codex, "key_123", "transit_secret_for_tests")
            .expect("save");
        assert_eq!(
            store.load(&SourceKind::Codex, "key_123").expect("load"),
            "transit_secret_for_tests"
        );
        assert!(store.delete(&SourceKind::Codex, "key_123").expect("delete"));
        assert!(matches!(
            store.load(&SourceKind::Codex, "key_123"),
            Err(TelemetryKeychainError::Missing)
        ));
    }

    #[test]
    fn file_only_delete_is_idempotent() {
        let store = TelemetryKeyStore::file_only(test_root("delete-idempotent"));

        assert!(!store
            .delete(&SourceKind::ClaudeCode, "missing_key")
            .expect("delete"));
    }

    #[test]
    fn latest_key_id_returns_highest_indexed_key_for_source() {
        let store = TelemetryKeyStore::file_only(test_root("latest-key"));
        store
            .save(&SourceKind::Codex, "key_001", "otel_secret_1")
            .expect("save first");
        store
            .save(&SourceKind::Codex, "key_002", "otel_secret_2")
            .expect("save second");
        store
            .save(&SourceKind::ClaudeCode, "key_999", "otel_secret_3")
            .expect("save other source");

        assert_eq!(
            store.latest_key_id(&SourceKind::Codex).unwrap(),
            Some("key_002".to_string())
        );
    }

    #[test]
    fn key_id_with_path_separators_stays_inside_store_root() {
        let root = test_root("sanitize");
        let store = TelemetryKeyStore::file_only(&root);

        store
            .save(&SourceKind::Codex, "../key/123", "secret")
            .expect("save");

        let service_dir = root.join(CODEX_TELEMETRY_KEY_SERVICE);
        let entries = fs::read_dir(service_dir)
            .expect("read service dir")
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].path().to_string_lossy().contains("../"));
    }

    #[test]
    fn sweep_all_removes_all_indexed_source_keys() {
        let root = test_root("sweep");
        let store = TelemetryKeyStore::file_only(&root);
        store
            .save(&SourceKind::Codex, "codex_key", "secret")
            .expect("save codex");
        store
            .save(&SourceKind::ClaudeCode, "claude_key", "secret")
            .expect("save claude");

        let result = store.sweep_all().expect("sweep");

        assert_eq!(result.removed.len(), 2);
        assert!(result.warnings.is_empty());
        assert!(matches!(
            store.load(&SourceKind::Codex, "codex_key"),
            Err(TelemetryKeychainError::Missing)
        ));
        assert!(matches!(
            store.load(&SourceKind::ClaudeCode, "claude_key"),
            Err(TelemetryKeychainError::Missing)
        ));
    }
}
