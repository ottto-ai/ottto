use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_SEARCH_PATH_ENV: &str = "OTTTO_COMMAND_SEARCH_PATH";
const INTERACTIVE_SHELL_ENV_TIMEOUT: Duration = Duration::from_secs(3);
const PROVIDER_ENV_KEYS: &[&str] = &[
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_CLOUD_REGION",
    "GCLOUD_PROJECT",
    "GCP_PROJECT",
    "CLOUDSDK_CONFIG",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "VERTEXAI_PROJECT",
    "VERTEXAI_LOCATION",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
];

pub(crate) fn executable_path(program: &str) -> Option<PathBuf> {
    executable_search_dirs_for_program(program)
        .into_iter()
        .find_map(|dir| {
            let candidate = dir.join(program);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
}

fn executable_search_dirs_for_program(program: &str) -> Vec<PathBuf> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return executable_search_dirs_from(Some(path_var), None, false);
    }
    executable_search_dirs_for_program_with_home(program, env::var_os("HOME"))
}

fn executable_search_dirs_for_program_with_home(
    program: &str,
    home: Option<OsString>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if program == "codex" {
        push_unique(
            &mut dirs,
            PathBuf::from("/Applications/Codex.app/Contents/Resources"),
        );
        if let Some(home) = home.as_ref().filter(|home| !home.is_empty()) {
            push_unique(
                &mut dirs,
                PathBuf::from(home)
                    .join("Applications")
                    .join("Codex.app")
                    .join("Contents")
                    .join("Resources"),
            );
        }
    }
    for dir in executable_search_dirs_from(env::var_os("PATH"), home, true) {
        push_unique(&mut dirs, dir);
    }
    dirs
}

pub(crate) fn path_env() -> Option<OsString> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return path_env_from_override(Some(path_var));
    }
    path_env_from(env::var_os("PATH"), env::var_os("HOME"))
}

pub(crate) fn provider_env() -> BTreeMap<String, OsString> {
    let current = current_provider_env();
    let missing_shell_env = (current.len() < PROVIDER_ENV_KEYS.len())
        .then(interactive_shell_provider_env)
        .flatten();
    provider_env_from_sources(&current, missing_shell_env.as_ref())
}

fn current_provider_env() -> BTreeMap<String, OsString> {
    PROVIDER_ENV_KEYS
        .iter()
        .filter_map(|key| {
            let value = env::var_os(key)?;
            non_empty_env_value(value).map(|value| ((*key).to_string(), value))
        })
        .collect()
}

fn provider_env_from_sources(
    current: &BTreeMap<String, OsString>,
    shell: Option<&BTreeMap<String, OsString>>,
) -> BTreeMap<String, OsString> {
    let mut values = BTreeMap::new();
    for key in PROVIDER_ENV_KEYS {
        if let Some(value) = current
            .get(*key)
            .cloned()
            .or_else(|| shell.and_then(|shell| shell.get(*key).cloned()))
            .and_then(non_empty_env_value)
        {
            values.insert((*key).to_string(), value);
        }
    }
    values
}

fn interactive_shell_provider_env() -> Option<BTreeMap<String, OsString>> {
    let home = env::var_os("HOME")?;
    let path = path_env_from(None, Some(home.clone()))?;
    let mut command = Command::new("/bin/zsh");
    command
        .args(["-lic", "/usr/bin/env"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = command.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let output = child.wait_with_output().ok()?;
                if !output.status.success() {
                    return None;
                }
                return Some(parse_provider_env_output(&output.stdout));
            }
            Ok(None) if start.elapsed() >= INTERACTIVE_SHELL_ENV_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn parse_provider_env_output(output: &[u8]) -> BTreeMap<String, OsString> {
    let mut values = BTreeMap::new();
    let text = String::from_utf8_lossy(output);
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if PROVIDER_ENV_KEYS.contains(&key) {
            if let Some(value) = non_empty_env_value(OsString::from(value)) {
                values.insert(key.to_string(), value);
            }
        }
    }
    values
}

fn non_empty_env_value(value: OsString) -> Option<OsString> {
    (!value.is_empty()).then_some(value)
}

fn path_env_from(path_var: Option<OsString>, home: Option<OsString>) -> Option<OsString> {
    env::join_paths(executable_search_dirs_from(path_var, home, true)).ok()
}

fn path_env_from_override(path_var: Option<OsString>) -> Option<OsString> {
    env::join_paths(path_var.map(|value| executable_search_dirs_from(Some(value), None, false))?)
        .ok()
}

fn executable_search_dirs_from(
    path_var: Option<OsString>,
    home: Option<OsString>,
    include_default_dirs: bool,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(path_var) = path_var {
        for dir in env::split_paths(&path_var) {
            push_unique(&mut dirs, dir);
        }
    }
    if let Some(home) = home {
        if !home.as_os_str().is_empty() {
            push_home_cli_dirs(&mut dirs, &PathBuf::from(home));
        }
    }
    if include_default_dirs {
        for dir in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ] {
            push_unique(&mut dirs, PathBuf::from(dir));
        }
    }
    dirs
}

/// Add the home-relative CLI install locations the daemon must search even
/// though it runs without the user's interactive-shell `PATH`. Agent CLIs
/// (`claude`, `codex`, `pi`) install to several well-known per-user prefixes:
///
/// - `~/.local/bin` — Claude Code's native installer symlinks `claude` here
///   (target under `~/.local/share/claude/versions/*`); also the generic
///   XDG-style user bin.
/// - `~/.npm-global/bin` — a common `npm config set prefix` global override.
/// - `~/.nvm/versions/node/<version>/bin` — every installed nvm Node version's
///   global bin, where an `npm i -g @anthropic-ai/claude-code` lands when Node
///   is managed by nvm and never reaches the launchd `PATH`.
/// - `~/.claude/local` — Claude Code's legacy local-install shim location.
///
/// Without these, a launchd/XPC daemon whose `PATH` is the minimal system
/// default declares a genuinely-installed CLI "not installed", which then
/// surfaces as a phantom "not installed or not executable" verification
/// failure. Order is deepest-user-preference first, then broader prefixes.
fn push_home_cli_dirs(dirs: &mut Vec<PathBuf>, home: &Path) {
    push_unique(dirs, home.join(".local/bin"));
    push_unique(dirs, home.join(".npm-global/bin"));
    for bin in nvm_node_bin_dirs(home) {
        push_unique(dirs, bin);
    }
    push_unique(dirs, home.join(".claude/local"));
}

/// Enumerate `~/.nvm/versions/node/<version>/bin` for every installed Node
/// version. A missing or unreadable nvm directory yields an empty list (the
/// user simply has no nvm-managed Node), so this never fails the search.
fn nvm_node_bin_dirs(home: &Path) -> Vec<PathBuf> {
    let versions_root = home.join(".nvm/versions/node");
    let Ok(entries) = std::fs::read_dir(&versions_root) else {
        return Vec::new();
    };
    let mut bins: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path().join("bin"))
        .filter(|bin| bin.is_dir())
        .collect();
    // Deterministic order so PATH assembly and detection are stable across runs.
    bins.sort();
    bins
}

fn push_unique(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
    if !dirs.iter().any(|existing| existing == &dir) {
        dirs.push(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scratch_home(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("ottto-command-env-tests")
            .join(format!("{}-{name}-{counter}", std::process::id()))
    }

    #[test]
    fn path_env_includes_launchd_safe_cli_locations() {
        let path_env = path_env_from(
            Some(OsString::from("/usr/bin:/bin")),
            Some(OsString::from("/Users/tester")),
        )
        .expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();

        assert_eq!(dirs.first(), Some(&PathBuf::from("/usr/bin")));
        assert!(dirs.contains(&PathBuf::from("/Users/tester/.local/bin")));
        assert!(dirs.contains(&PathBuf::from("/opt/homebrew/bin")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/bin")));
    }

    #[test]
    fn search_dirs_include_per_user_cli_install_locations() {
        let dirs = executable_search_dirs_from(
            Some(OsString::from("/usr/bin")),
            Some(OsString::from("/Users/tester")),
            true,
        );

        // Native Claude installer symlink dir and common npm global prefixes
        // must be searched even when the daemon PATH omits them.
        assert!(dirs.contains(&PathBuf::from("/Users/tester/.local/bin")));
        assert!(dirs.contains(&PathBuf::from("/Users/tester/.npm-global/bin")));
        assert!(dirs.contains(&PathBuf::from("/Users/tester/.claude/local")));
    }

    #[test]
    fn search_dirs_enumerate_nvm_node_bins_when_present() {
        let home = scratch_home("nvm");
        let node_bin = home.join(".nvm/versions/node/v22.19.0/bin");
        fs::create_dir_all(&node_bin).expect("nvm node bin");
        // A stray non-directory entry alongside the versions must be ignored.
        fs::write(home.join(".nvm/versions/node/README"), "x").ok();

        let dirs = executable_search_dirs_from(
            Some(OsString::from("/usr/bin")),
            Some(home.as_os_str().to_os_string()),
            true,
        );

        assert!(
            dirs.contains(&node_bin),
            "nvm-managed node global bin must be searched: {dirs:?}"
        );

        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_nvm_dir_yields_no_node_bins() {
        let home = scratch_home("no-nvm");
        assert!(nvm_node_bin_dirs(&home).is_empty());
    }

    #[test]
    fn executable_path_finds_binary_off_launchd_path() {
        let home = scratch_home("off-path");
        let bin_dir = home.join(".local/bin");
        fs::create_dir_all(&bin_dir).expect("local bin");
        let claude = bin_dir.join("claude");
        fs::write(&claude, "#!/bin/sh\n").expect("write claude shim");

        // Simulate the launchd PATH that omits ~/.local/bin entirely.
        let dirs = executable_search_dirs_from(
            Some(OsString::from("/usr/bin:/bin")),
            Some(home.as_os_str().to_os_string()),
            true,
        );
        let found = dirs
            .iter()
            .map(|dir| dir.join("claude"))
            .find(|candidate| candidate.is_file());

        assert_eq!(found, Some(claude));

        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn codex_executable_prefers_desktop_bundle_locations() {
        let dirs = executable_search_dirs_for_program_with_home(
            "codex",
            Some(OsString::from("/Users/tester")),
        );

        assert_eq!(
            dirs.first(),
            Some(&PathBuf::from("/Applications/Codex.app/Contents/Resources"))
        );
        assert_eq!(
            dirs.get(1),
            Some(&PathBuf::from(
                "/Users/tester/Applications/Codex.app/Contents/Resources"
            ))
        );
    }

    #[test]
    fn path_env_deduplicates_candidate_dirs() {
        let path_env = path_env_from(
            Some(OsString::from(
                "/opt/homebrew/bin:/usr/bin:/opt/homebrew/bin",
            )),
            None,
        )
        .expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();

        assert_eq!(
            dirs.iter()
                .filter(|dir| dir.as_path() == Path::new("/opt/homebrew/bin"))
                .count(),
            1
        );
    }

    #[test]
    fn command_search_override_does_not_append_default_dirs() {
        let override_path = OsString::from("/tmp/ottto-only-bin");

        let dirs = executable_search_dirs_from(Some(override_path.clone()), None, false);
        assert_eq!(dirs, vec![PathBuf::from("/tmp/ottto-only-bin")]);

        let path_env = path_env_from_override(Some(override_path)).expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();
        assert_eq!(dirs, vec![PathBuf::from("/tmp/ottto-only-bin")]);
    }

    #[test]
    fn provider_env_prefers_current_process_and_fills_from_shell() {
        let mut current = BTreeMap::new();
        current.insert(
            "GOOGLE_CLOUD_PROJECT".to_string(),
            OsString::from("current-project"),
        );
        let mut shell = BTreeMap::new();
        shell.insert(
            "GOOGLE_CLOUD_PROJECT".to_string(),
            OsString::from("shell-project"),
        );
        shell.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            OsString::from("/tmp/google.json"),
        );

        let env = provider_env_from_sources(&current, Some(&shell));

        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("current-project"))
        );
        assert_eq!(
            env.get("GOOGLE_APPLICATION_CREDENTIALS"),
            Some(&OsString::from("/tmp/google.json"))
        );
    }

    #[test]
    fn provider_env_ignores_unallowlisted_and_empty_values() {
        let current = BTreeMap::new();
        let mut shell = BTreeMap::new();
        shell.insert("PASSWORD".to_string(), OsString::from("secret"));
        shell.insert("GOOGLE_CLOUD_LOCATION".to_string(), OsString::new());
        shell.insert("GEMINI_API_KEY".to_string(), OsString::from("gemini-key"));

        let env = provider_env_from_sources(&current, Some(&shell));

        assert!(!env.contains_key("PASSWORD"));
        assert!(!env.contains_key("GOOGLE_CLOUD_LOCATION"));
        assert_eq!(
            env.get("GEMINI_API_KEY"),
            Some(&OsString::from("gemini-key"))
        );
    }

    #[test]
    fn parse_provider_env_output_keeps_only_allowlisted_keys() {
        let env = parse_provider_env_output(
            b"GOOGLE_CLOUD_PROJECT=ottto\nPATH=/tmp\nVERTEXAI_LOCATION=us-central1\nMALICIOUS=value\n",
        );

        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("ottto"))
        );
        assert_eq!(
            env.get("VERTEXAI_LOCATION"),
            Some(&OsString::from("us-central1"))
        );
        assert!(!env.contains_key("PATH"));
        assert!(!env.contains_key("MALICIOUS"));
    }
}
