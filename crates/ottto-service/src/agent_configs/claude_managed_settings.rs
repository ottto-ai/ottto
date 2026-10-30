//! Env-only provisioning for daemon-owned Claude roots. Never follow links,
//! replace malformed settings, or adopt a user's external telemetry exporter.
use serde_json::{Map, Value};
use std::{fs::File, io, path::Path};

const SETTINGS_LIMIT: u64 = 1024 * 1024;
const MANAGED_KEYS: [&str; 13] = [
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_RESOURCE_ATTRIBUTES",
];

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Changed,
    Unchanged,
    OptedOut,
    ExternalTelemetry,
}

fn merge(settings: &mut Value, approved: &[(&str, String)]) -> io::Result<Option<Outcome>> {
    let object = settings
        .as_object_mut()
        .ok_or_else(|| invalid("settings is not an object"))?;
    let env = object
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    let env = env
        .as_object_mut()
        .ok_or_else(|| invalid("env is not an object"))?;
    if [
        "CLAUDE_CODE_ENABLE_TELEMETRY",
        "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    ]
    .iter()
    .any(|key| env.get(*key).is_some_and(|value| value != "1"))
        || [
            "OTEL_METRICS_EXPORTER",
            "OTEL_LOGS_EXPORTER",
            "OTEL_TRACES_EXPORTER",
        ]
        .iter()
        .any(|key| env.get(*key).is_some_and(|value| value == "none"))
    {
        return Ok(Some(Outcome::OptedOut));
    }
    let owned = env
        .get("OTEL_EXPORTER_OTLP_HEADERS")
        .is_some_and(|value| value == "X-Ottto-Local-Relay=claude_code");
    // Generic endpoints and signal-specific headers/protocols can override
    // the generated fields. They are user configuration, never our renderer's.
    let external_target = env.keys().any(|key| {
        key.starts_with("OTEL_EXPORTER_OTLP_")
            && !approved.iter().any(|(managed, _)| key == managed)
    });
    let external_endpoint = approved.iter().any(|(key, _)| {
        env.get(*key)
            .is_some_and(|value| owned_signal_endpoint(key, value) == Some(false))
    });
    let customized_owned_value = owned
        && approved.iter().any(|(key, _)| {
            env.get(*key)
                .is_some_and(|value| !owned_relay_value(key, value))
        });
    if external_target
        || external_endpoint
        || customized_owned_value
        || (!owned
            && approved.iter().any(|(key, value)| {
                env.get(*key)
                    .is_some_and(|current| current != value.as_str())
            }))
    {
        return Ok(Some(Outcome::ExternalTelemetry));
    }
    for (key, value) in approved {
        env.insert((*key).to_owned(), Value::String(value.clone()));
    }
    Ok(None)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn owned_signal_endpoint(key: &str, value: &Value) -> Option<bool> {
    key.strip_prefix("OTEL_EXPORTER_OTLP_")?
        .strip_suffix("_ENDPOINT")?;
    Some(signal_endpoint_port(key, value).is_some())
}

fn signal_endpoint_port(key: &str, value: &Value) -> Option<u16> {
    let signal = key
        .strip_prefix("OTEL_EXPORTER_OTLP_")?
        .strip_suffix("_ENDPOINT")?;
    let suffix = format!("/v1/{}", signal.to_ascii_lowercase());
    let base = value.as_str()?.strip_suffix(&suffix)?;
    base.strip_prefix("http://127.0.0.1:")
        .or_else(|| base.strip_prefix("http://localhost:"))?
        .parse::<u16>()
        .ok()
}

fn owned_relay_value(key: &str, value: &Value) -> bool {
    if let Some(owned) = owned_signal_endpoint(key, value) {
        return owned;
    }
    let Some(value) = value.as_str() else {
        return false;
    };
    match key {
        "CLAUDE_CODE_ENABLE_TELEMETRY" | "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA" => value == "1",
        "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS" => value == "10000",
        "OTEL_METRICS_EXPORTER" | "OTEL_LOGS_EXPORTER" | "OTEL_TRACES_EXPORTER" => value == "otlp",
        "OTEL_EXPORTER_OTLP_PROTOCOL" => value == "http/protobuf",
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL" => value == "http/json",
        "OTEL_EXPORTER_OTLP_HEADERS" => value == "X-Ottto-Local-Relay=claude_code",
        "OTEL_RESOURCE_ATTRIBUTES" => value
            .strip_prefix("service.name=claude-code,ottto.source=claude_code,ottto.machine_id=")
            .is_some_and(|machine| !machine.is_empty() && !machine.contains(',')),
        _ => false,
    }
}

pub(crate) fn approved_relay_port(body: &str) -> Option<u16> {
    let settings: Value = serde_json::from_str(body).ok()?;
    let env = settings.get("env")?.as_object()?;
    if env
        .keys()
        .any(|key| key.starts_with("OTEL_EXPORTER_OTLP_") && !MANAGED_KEYS.contains(&key.as_str()))
        || MANAGED_KEYS.iter().any(|key| {
            env.get(*key)
                .map_or(true, |value| !owned_relay_value(key, value))
        })
    {
        return None;
    }
    let key = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT";
    let port = signal_endpoint_port(key, env.get(key)?)?;
    for key in [
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ] {
        if signal_endpoint_port(key, env.get(key)?) != Some(port) {
            return None;
        }
    }
    Some(port)
}

fn disable(settings: &mut Value, default_root: bool) -> io::Result<Option<Outcome>> {
    let object = settings
        .as_object_mut()
        .ok_or_else(|| invalid("settings is not an object"))?;
    if default_root && !object.contains_key("env") {
        object.insert(
            "env".into(),
            serde_json::json!({"CLAUDE_CODE_ENABLE_TELEMETRY":"0"}),
        );
        return Ok(None);
    }
    let Some(env) = object.get_mut("env") else {
        return Ok(Some(Outcome::Unchanged));
    };
    let env = env
        .as_object_mut()
        .ok_or_else(|| invalid("env is not an object"))?;
    if env
        .get("OTEL_EXPORTER_OTLP_HEADERS")
        .map_or(true, |value| value != "X-Ottto-Local-Relay=claude_code")
    {
        if default_root {
            // Explicit source Disable persists the off switch even when no
            // Ottto fields are present. External/user env entries stay intact.
            env.insert(
                "CLAUDE_CODE_ENABLE_TELEMETRY".into(),
                Value::String("0".into()),
            );
            return Ok(None);
        }
        return Ok(Some(Outcome::ExternalTelemetry));
    }
    let external_collector = env.iter().any(|(key, value)| {
        key.starts_with("OTEL_EXPORTER_OTLP_")
            && (!MANAGED_KEYS.contains(&key.as_str())
                || owned_signal_endpoint(key, value) == Some(false))
    });
    for key in MANAGED_KEYS {
        // An external collector may rely on even canonical protocol/exporter
        // values. Clear only our routing/header in that case; keep its settings.
        let shared_external_setting = external_collector
            && owned_signal_endpoint(key, &Value::Null).is_none()
            && key != "OTEL_EXPORTER_OTLP_HEADERS";
        if !shared_external_setting
            && env
                .get(key)
                .is_some_and(|value| owned_relay_value(key, value))
        {
            env.remove(key);
        }
    }
    if default_root {
        env.insert(
            "CLAUDE_CODE_ENABLE_TELEMETRY".into(),
            Value::String("0".into()),
        );
    }
    Ok(None)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        ffi::CString,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::Component,
        sync::atomic::{AtomicU64, Ordering},
    };
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Directory(File);
    impl Directory {
        fn open(path: &Path, private: bool) -> io::Result<Self> {
            if !path.is_absolute() {
                return Err(invalid("settings directory must be absolute"));
            }
            let fd = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            let mut directory = Self(file(fd)?);
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => {
                        use std::os::unix::ffi::OsStrExt;
                        let name = CString::new(name.as_bytes())
                            .map_err(|_| invalid("invalid directory component"))?;
                        directory = Self(directory.open_file(
                            &name,
                            libc::O_RDONLY | libc::O_DIRECTORY,
                            0,
                        )?);
                    }
                    _ => return Err(invalid("settings directory must be normalized")),
                }
            }
            let metadata = directory.0.metadata()?;
            if private
                && (metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o777 != 0o700)
            {
                return Err(invalid("managed settings directory must be owner-only"));
            }
            Ok(directory)
        }
        fn open_file(&self, name: &std::ffi::CStr, flags: i32, mode: u32) -> io::Result<File> {
            file(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    mode as libc::c_uint,
                )
            })
        }
        fn read(&self) -> io::Result<Option<Vec<u8>>> {
            self.read_named(c"settings.json")
        }
        fn read_named(&self, name: &std::ffi::CStr) -> io::Result<Option<Vec<u8>>> {
            let mut file = match self.open_file(name, libc::O_RDONLY, 0) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            check_file(&file)?;
            let mut body = Vec::new();
            (&mut file)
                .take(SETTINGS_LIMIT + 1)
                .read_to_end(&mut body)?;
            if body.len() as u64 > SETTINGS_LIMIT {
                return Err(invalid("settings exceeds size limit"));
            }
            Ok(Some(body))
        }
        fn same_root(&self, root: &Path, private: bool) -> io::Result<bool> {
            let current = Self::open(root, private)?.0.metadata()?;
            let original = self.0.metadata()?;
            Ok(current.dev() == original.dev() && current.ino() == original.ino())
        }
    }

    fn file(fd: i32) -> io::Result<File> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    fn check_file(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
        {
            return Err(invalid("settings must be an owner-controlled regular file"));
        }
        if metadata.len() > SETTINGS_LIMIT {
            return Err(invalid("settings exceeds size limit"));
        }
        Ok(())
    }

    pub(super) fn read_settings(path: &Path) -> io::Result<Option<String>> {
        if path.file_name() != Some(std::ffi::OsStr::new("settings.json")) {
            return Err(invalid("unexpected settings file name"));
        }
        read_settings_file(path)
    }

    pub(super) fn read_settings_file(path: &Path) -> io::Result<Option<String>> {
        use std::os::unix::ffi::OsStrExt;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("settings has no file name"))?;
        let name =
            CString::new(name.as_bytes()).map_err(|_| invalid("invalid settings file name"))?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("settings has no parent"))?;
        let directory = match Directory::open(parent, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        directory
            .read_named(&name)?
            .map(|body| String::from_utf8(body).map_err(|_| invalid("settings is not UTF-8")))
            .transpose()
    }

    pub(super) fn reconcile(root: &Path, approved: &[(&str, String)]) -> io::Result<Outcome> {
        reconcile_before_commit(root, approved, || {})
    }

    pub(super) fn disable_settings(root: &Path, default_root: bool) -> io::Result<Outcome> {
        update(
            root,
            !default_root,
            true,
            |settings| disable(settings, default_root),
            || {},
        )
    }

    fn reconcile_before_commit(
        root: &Path,
        approved: &[(&str, String)],
        before_commit: impl FnOnce(),
    ) -> io::Result<Outcome> {
        update(
            root,
            true,
            false,
            |settings| merge(settings, approved),
            before_commit,
        )
    }

    fn update(
        root: &Path,
        private: bool,
        skip_missing: bool,
        transform: impl FnOnce(&mut Value) -> io::Result<Option<Outcome>>,
        before_commit: impl FnOnce(),
    ) -> io::Result<Outcome> {
        let _thread_guard = WRITE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let directory = match Directory::open(root, private) {
            Ok(directory) => directory,
            Err(error) if private && skip_missing && error.kind() == io::ErrorKind::NotFound => {
                return Ok(Outcome::Unchanged)
            }
            Err(error) if !private && error.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::ffi::OsStrExt;
                let parent = root
                    .parent()
                    .ok_or_else(|| invalid("settings directory has no parent"))?;
                let parent = Directory::open(parent, false)?;
                let name = CString::new(
                    root.file_name()
                        .ok_or_else(|| invalid("settings directory has no name"))?
                        .as_bytes(),
                )
                .map_err(|_| invalid("invalid settings directory name"))?;
                if unsafe { libc::mkdirat(parent.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                Directory::open(root, false)?
            }
            Err(error) => return Err(error),
        };
        // Serialize Ottto writers across threads/processes without locking or
        // opening provider-owned files. Claude edits are rechecked before commit.
        let lock = directory.open_file(
            c".ottto-telemetry-settings.lock",
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;
        check_file(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = directory.read()?;
        let mut settings: Value = match &original {
            Some(body) => {
                serde_json::from_slice(body).map_err(|_| invalid("malformed settings JSON"))?
            }
            None => Value::Object(Map::new()),
        };
        let before = settings.clone();
        if let Some(outcome) = transform(&mut settings)? {
            return Ok(outcome);
        }
        if before == settings {
            return Ok(Outcome::Unchanged);
        }
        let mut body = serde_json::to_vec_pretty(&settings)
            .map_err(|_| invalid("cannot serialize settings"))?;
        body.push(b'\n');
        if body.len() as u64 > SETTINGS_LIMIT {
            return Err(invalid("updated settings exceeds size limit"));
        }
        let name = CString::new(format!(
            ".ottto-settings-{}-{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("safe temp name");
        let mut temporary =
            directory.open_file(&name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        let result = (|| {
            temporary.write_all(&body)?;
            temporary.sync_all()?;
            before_commit();
            if !directory.same_root(root, private)? || directory.read()? != original {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "settings changed during provisioning",
                ));
            }
            if unsafe {
                libc::renameat(
                    directory.0.as_raw_fd(),
                    name.as_ptr(),
                    directory.0.as_raw_fd(),
                    c"settings.json".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            directory.0.sync_all()?;
            Ok(Outcome::Changed)
        })();
        unsafe {
            libc::unlinkat(directory.0.as_raw_fd(), name.as_ptr(), 0);
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            os::unix::fs::{symlink, PermissionsExt},
        };
        fn root() -> std::path::PathBuf {
            let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
            let root = parent.join(format!(
                "ottto-managed-settings-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            root
        }
        fn env() -> Vec<(&'static str, String)> {
            vec![
                ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".into()),
                (
                    "OTEL_EXPORTER_OTLP_HEADERS",
                    "X-Ottto-Local-Relay=claude_code".into(),
                ),
                (
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                    "http://127.0.0.1:48123/v1/logs".into(),
                ),
            ]
        }
        #[test]
        fn create_repair_reconnect_preserves_user_settings_and_bytes_on_replay() {
            let root = root();
            let path = root.join("settings.json");
            assert_eq!(reconcile(&root, &env()).unwrap(), Outcome::Changed);
            let mut settings: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            settings["statusLine"] = serde_json::json!({"command":"user-status"});
            settings["permissions"] = serde_json::json!({"allow":["Read"]});
            settings["env"]["USER_FLAG"] = Value::String("keep".into());
            settings["env"]["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] =
                Value::String("http://127.0.0.1:48122/v1/logs".into());
            fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
            assert_eq!(reconcile(&root, &env()).unwrap(), Outcome::Changed);
            let bytes = fs::read(&path).unwrap();
            let repaired: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(repaired["statusLine"], settings["statusLine"]);
            assert_eq!(repaired["permissions"], settings["permissions"]);
            assert_eq!(repaired["env"]["USER_FLAG"], "keep");
            assert_eq!(reconcile(&root, &env()).unwrap(), Outcome::Unchanged);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn optout_external_telemetry_and_malformed_settings_survive() {
            let root = root();
            let path = root.join("settings.json");
            for body in [
                r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"0"}}"#,
                r#"{"env":{"OTEL_LOGS_EXPORTER":"none"}}"#,
                r#"{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"user-secret"}}"#,
                "{broken",
                "[]",
                r#"{"env":[]}"#,
            ] {
                fs::write(&path, body).unwrap();
                let _ = reconcile(&root, &env());
                assert_eq!(fs::read_to_string(&path).unwrap(), body);
            }
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn disable_preserves_enhanced_and_signal_optouts() {
            let root = root();
            let path = root.join("settings.json");
            for (key, value) in [
                ("CLAUDE_CODE_ENABLE_TELEMETRY", "0"),
                ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "0"),
                ("OTEL_LOGS_EXPORTER", "none"),
            ] {
                fs::remove_file(&path).ok();
                reconcile(&root, &env()).unwrap();
                let mut settings: Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                settings["env"][key] = Value::String(value.into());
                fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
                assert_eq!(reconcile(&root, &env()).unwrap(), Outcome::OptedOut);
                disable_settings(&root, false).unwrap();
                let disabled: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                assert_eq!(disabled["env"][key], value);
                assert_eq!(reconcile(&root, &env()).unwrap(), Outcome::OptedOut);
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn generic_and_signal_external_exporters_are_preserved() {
            let root = root();
            let path = root.join("settings.json");
            for body in [
                r#"{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example"}}"#,
                r#"{"env":{"OTEL_EXPORTER_OTLP_LOGS_HEADERS":"user-auth"}}"#,
                r#"{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code","OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"https://collector.example/v1/logs"}}"#,
            ] {
                fs::write(&path, body).unwrap();
                assert_eq!(
                    reconcile(&root, &env()).unwrap(),
                    Outcome::ExternalTelemetry
                );
                assert_eq!(fs::read_to_string(&path).unwrap(), body);
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn disable_and_remove_preserve_external_signal_endpoint_values() {
            let root = root();
            let path = root.join("settings.json");
            for default_root in [false, true] {
                let body = serde_json::json!({"env":{
                    "CLAUDE_CODE_ENABLE_TELEMETRY":"1",
                    "OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code",
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"https://collector.example/v1/logs",
                    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL":"grpc",
                    "OTEL_EXPORTER_OTLP_PROTOCOL":"grpc",
                    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://127.0.0.1:48123/v1/metrics",
                    "USER_FLAG":"keep"}});
                fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
                assert_eq!(
                    disable_settings(&root, default_root).unwrap(),
                    Outcome::Changed
                );
                let cleared: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                assert_eq!(
                    cleared["env"]["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"],
                    body["env"]["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]
                );
                assert_eq!(cleared["env"]["USER_FLAG"], "keep");
                assert_eq!(cleared["env"]["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"], "grpc");
                assert_eq!(cleared["env"]["OTEL_EXPORTER_OTLP_PROTOCOL"], "grpc");
                assert!(cleared["env"]
                    .get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
                    .is_none());
                assert!(cleared["env"].get("OTEL_EXPORTER_OTLP_HEADERS").is_none());
                assert_eq!(
                    disable_settings(&root, default_root).unwrap(),
                    if default_root {
                        Outcome::Unchanged
                    } else {
                        Outcome::ExternalTelemetry
                    }
                );
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn cleanup_preserves_custom_values_and_external_collector_protocols() {
            let root = root();
            let path = root.join("settings.json");
            for endpoint in [
                "http://127.0.0.1:48123/v1/logs",
                "https://collector.example/v1/logs",
            ] {
                for default_root in [false, true] {
                    let body = serde_json::json!({"env":{
                        "OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code",
                        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":endpoint,
                        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL":"grpc",
                        "OTEL_EXPORTER_OTLP_PROTOCOL":"grpc",
                        "OTEL_LOGS_EXPORTER":"console",
                        "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS":"25000",
                        "OTEL_RESOURCE_ATTRIBUTES":"deployment.environment=user"}});
                    fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
                    assert_eq!(
                        disable_settings(&root, default_root).unwrap(),
                        Outcome::Changed
                    );
                    let cleared: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    for key in [
                        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
                        "OTEL_EXPORTER_OTLP_PROTOCOL",
                        "OTEL_LOGS_EXPORTER",
                        "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS",
                        "OTEL_RESOURCE_ATTRIBUTES",
                    ] {
                        assert_eq!(cleared["env"][key], body["env"][key]);
                    }
                }
            }
            for default_root in [false, true] {
                let body = serde_json::json!({"env":{
                    "OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code",
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"https://collector.example/v1/logs",
                    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL":"http/json",
                    "OTEL_EXPORTER_OTLP_PROTOCOL":"http/protobuf",
                    "OTEL_LOGS_EXPORTER":"otlp"}});
                fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
                disable_settings(&root, default_root).unwrap();
                let cleared: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                for key in [
                    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
                    "OTEL_EXPORTER_OTLP_PROTOCOL",
                    "OTEL_LOGS_EXPORTER",
                ] {
                    assert_eq!(cleared["env"][key], body["env"][key]);
                }
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn local_user_collector_paths_survive_provision_disable_and_remove() {
            let root = root();
            let path = root.join("settings.json");
            for endpoint in [
                "http://127.0.0.1:4318/collector/v1/logs",
                "http://localhost:4318/collector/v1/logs",
                "http://127.0.0.1:4318/v1/logs?tenant=user",
                "http://127.0.0.1:4318/v1/logs#user",
            ] {
                let body = serde_json::json!({"env":{
                    "CLAUDE_CODE_ENABLE_TELEMETRY":"1",
                    "OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code",
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":endpoint,
                    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://localhost:48123/v1/metrics"}});
                let bytes = serde_json::to_vec(&body).unwrap();
                fs::write(&path, &bytes).unwrap();
                assert_eq!(
                    reconcile(&root, &env()).unwrap(),
                    Outcome::ExternalTelemetry
                );
                assert_eq!(fs::read(&path).unwrap(), bytes);
                for default_root in [false, true] {
                    fs::write(&path, &bytes).unwrap();
                    assert_eq!(
                        disable_settings(&root, default_root).unwrap(),
                        Outcome::Changed
                    );
                    let cleared: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    assert_eq!(cleared["env"]["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"], endpoint);
                    assert!(cleared["env"]
                        .get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
                        .is_none());
                }
            }
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn links_hardlinks_oversize_and_concurrent_edit_are_rejected() {
            let root = root();
            let path = root.join("settings.json");
            let outside = root.join("outside.json");
            fs::write(&outside, "{}").unwrap();
            symlink(&outside, &path).unwrap();
            assert!(reconcile(&root, &env()).is_err());
            assert_eq!(fs::read_to_string(&outside).unwrap(), "{}");
            fs::remove_file(&path).unwrap();
            fs::hard_link(&outside, &path).unwrap();
            assert!(reconcile(&root, &env()).is_err());
            fs::remove_file(&path).unwrap();
            fs::write(&path, vec![b' '; SETTINGS_LIMIT as usize + 1]).unwrap();
            assert!(reconcile(&root, &env()).is_err());
            fs::write(&path, "{}").unwrap();
            assert!(reconcile_before_commit(&root, &env(), || fs::write(
                &path,
                r#"{"user":"concurrent"}"#
            )
            .unwrap())
            .is_err());
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                r#"{"user":"concurrent"}"#
            );
            assert!(!fs::read_dir(&root).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
            let alias = root.with_extension("alias");
            symlink(&root, &alias).unwrap();
            assert!(reconcile(&alias, &env()).is_err());
            fs::remove_file(alias).unwrap();
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn parent_links_root_replacement_and_concurrent_writers_are_fenced() {
            let parent = root();
            let child = parent.join("managed");
            fs::create_dir(&child).unwrap();
            fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
            let alias = parent.with_extension("alias");
            symlink(&parent, &alias).unwrap();
            assert!(reconcile(&alias.join("managed"), &env()).is_err());
            assert!(!child.join("settings.json").exists());
            let previous = parent.join("previous");
            assert!(reconcile_before_commit(&child, &env(), || {
                fs::rename(&child, &previous).unwrap();
                fs::create_dir(&child).unwrap();
                fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
            })
            .is_err());
            assert!(!child.join("settings.json").exists());
            assert!(!previous.join("settings.json").exists());
            let writers: Vec<_> = (0..8)
                .map(|_| {
                    let root = child.clone();
                    std::thread::spawn(move || reconcile(&root, &env()).unwrap())
                })
                .collect();
            let outcomes: Vec<_> = writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .collect();
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| **outcome == Outcome::Changed)
                    .count(),
                1
            );
            assert_eq!(reconcile(&child, &env()).unwrap(), Outcome::Unchanged);
            fs::remove_file(alias).unwrap();
            fs::remove_dir_all(parent).unwrap();
        }
    }
}

pub(crate) fn read_settings(path: &Path) -> io::Result<Option<String>> {
    #[cfg(unix)]
    {
        unix::read_settings(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed settings require no-follow filesystem support",
        ))
    }
}

/// Read a retained settings backup with the normal owner, size and no-follow checks.
pub(crate) fn read_settings_backup(path: &Path) -> io::Result<Option<String>> {
    #[cfg(unix)]
    {
        unix::read_settings_file(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed settings require no-follow filesystem support",
        ))
    }
}

pub(crate) fn reconcile(root: &Path, approved: &[(&str, String)]) -> io::Result<Outcome> {
    #[cfg(unix)]
    {
        unix::reconcile(root, approved)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, approved);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed settings require no-follow filesystem support",
        ))
    }
}

pub(crate) fn disable_settings(root: &Path, default_root: bool) -> io::Result<Outcome> {
    #[cfg(unix)]
    {
        unix::disable_settings(root, default_root)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, default_root);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed settings require no-follow filesystem support",
        ))
    }
}
