use ottto_protocol::{AgentInstallationDetection, SourceKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VERSION_TIMEOUT: Duration = Duration::from_secs(3);
const CODEX_INSTALL_DOCS_URL: &str = "https://help.openai.com/en/articles/11096431";
const CLAUDE_CODE_INSTALL_DOCS_URL: &str = "https://code.claude.com/docs/en/installation";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectionSpec {
    binary_name: &'static str,
    version_args: &'static [&'static str],
    config_path: Option<PathBuf>,
    installed_when_config_parent_exists: bool,
    install_docs_url: Option<&'static str>,
}

pub fn detect_agent_installation(source: &SourceKind) -> AgentInstallationDetection {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let spec = detection_spec(source, &home);
    let binary_path = crate::command_env::executable_path(spec.binary_name);
    let version = binary_path
        .as_deref()
        .and_then(|path| capture_version(path, spec.version_args));
    detect_agent_installation_with_paths(source, spec, binary_path, version)
}

fn detect_agent_installation_with_paths(
    source: &SourceKind,
    spec: DetectionSpec,
    binary_path: Option<PathBuf>,
    version: Option<String>,
) -> AgentInstallationDetection {
    let config_path = spec.config_path.as_ref().and_then(|path| {
        if path.exists() {
            Some(path.display().to_string())
        } else if spec.installed_when_config_parent_exists {
            path.parent()
                .filter(|parent| parent.exists())
                .map(|parent| parent.display().to_string())
        } else {
            None
        }
    });
    let installed = binary_path.is_some()
        || (spec.installed_when_config_parent_exists && config_path.is_some());

    AgentInstallationDetection {
        source: source.clone(),
        installed,
        version: version.filter(|value| !value.trim().is_empty()),
        config_path,
        binary_path: binary_path.map(|path| path.display().to_string()),
        install_docs_url: spec.install_docs_url.map(str::to_string),
    }
}

fn detection_spec(source: &SourceKind, home: &Path) -> DetectionSpec {
    match source {
        SourceKind::Codex => DetectionSpec {
            binary_name: "codex",
            version_args: &["--version"],
            config_path: Some(home.join(".codex").join("config.toml")),
            installed_when_config_parent_exists: true,
            install_docs_url: Some(CODEX_INSTALL_DOCS_URL),
        },
        SourceKind::ClaudeCode => DetectionSpec {
            binary_name: "claude",
            version_args: &["--version"],
            config_path: Some(home.join(".claude").join("settings.json")),
            installed_when_config_parent_exists: false,
            install_docs_url: Some(CLAUDE_CODE_INSTALL_DOCS_URL),
        },
        SourceKind::Pi => DetectionSpec {
            binary_name: "pi",
            version_args: &["--version"],
            config_path: Some(home.join(".pi")),
            installed_when_config_parent_exists: true,
            install_docs_url: None,
        },
    }
}

fn capture_version(binary_path: &Path, args: &[&str]) -> Option<String> {
    let start = Instant::now();
    let mut child = Command::new(binary_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().ok()?;
                if !status.success() {
                    return None;
                }
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return [stdout, stderr]
                    .into_iter()
                    .find(|value| !value.is_empty())
                    .map(|value| value.lines().next().unwrap_or("").trim().to_string())
                    .filter(|value| !value.is_empty());
            }
            Ok(None) if start.elapsed() >= VERSION_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_home(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("ottto-agent-detection-tests")
            .join(format!("{}-{name}-{counter}", std::process::id()))
    }

    #[test]
    fn codex_config_directory_counts_as_installed() {
        let home = test_home("codex-config");
        fs::create_dir_all(home.join(".codex")).expect("codex dir");

        let detected = detect_agent_installation_with_paths(
            &SourceKind::Codex,
            detection_spec(&SourceKind::Codex, &home),
            None,
            None,
        );

        assert!(detected.installed);
        assert_eq!(
            detected.config_path,
            Some(home.join(".codex").display().to_string())
        );
        assert_eq!(detected.version, None);
        assert_eq!(
            detected.install_docs_url.as_deref(),
            Some(CODEX_INSTALL_DOCS_URL)
        );
    }

    #[test]
    fn codex_config_file_is_reported_when_present() {
        let home = test_home("codex-config-file");
        let path = home.join(".codex").join("config.toml");
        fs::create_dir_all(path.parent().expect("parent")).expect("codex dir");
        fs::write(&path, "model = \"gpt-5.4\"\n").expect("config");

        let detected = detect_agent_installation_with_paths(
            &SourceKind::Codex,
            detection_spec(&SourceKind::Codex, &home),
            None,
            None,
        );

        assert!(detected.installed);
        assert_eq!(detected.config_path, Some(path.display().to_string()));
    }

    #[test]
    fn claude_requires_binary_even_if_settings_file_exists() {
        let home = test_home("claude-settings");
        let path = home.join(".claude").join("settings.json");
        fs::create_dir_all(path.parent().expect("parent")).expect("claude dir");
        fs::write(&path, "{}").expect("settings");

        let detected = detect_agent_installation_with_paths(
            &SourceKind::ClaudeCode,
            detection_spec(&SourceKind::ClaudeCode, &home),
            None,
            None,
        );

        assert!(!detected.installed);
        assert_eq!(detected.config_path, Some(path.display().to_string()));
        assert_eq!(
            detected.install_docs_url.as_deref(),
            Some(CLAUDE_CODE_INSTALL_DOCS_URL)
        );
    }

    #[test]
    fn binary_path_and_version_are_reported() {
        let home = test_home("binary-version");
        let binary = home.join("bin").join("codex");

        let detected = detect_agent_installation_with_paths(
            &SourceKind::Codex,
            detection_spec(&SourceKind::Codex, &home),
            Some(binary.clone()),
            Some("codex 0.124.0".to_string()),
        );

        assert!(detected.installed);
        assert_eq!(detected.binary_path, Some(binary.display().to_string()));
        assert_eq!(detected.version.as_deref(), Some("codex 0.124.0"));
    }
}
