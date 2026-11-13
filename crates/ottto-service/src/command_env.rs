use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::sync::Mutex;
#[cfg(unix)]
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_SEARCH_PATH_ENV: &str = "OTTTO_COMMAND_SEARCH_PATH";
#[cfg(unix)]
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
    first_program_in(executable_search_dirs_for_program(program), program)
}

/// Interactive launches search in agent status's order: Codex desktop bundles,
/// then the inherited daemon PATH and native/npm prefixes. Claude Desktop's
/// private CLI is excluded.
pub(crate) fn interactive_cli_path(program: &str, home: &Path) -> Option<PathBuf> {
    if program == "claude" {
        return claude_default_login_executable_path(home);
    }
    let home = Some(home.as_os_str().to_owned());
    let dirs = match env::var_os(COMMAND_SEARCH_PATH_ENV) {
        Some(path_var) => executable_search_dirs_from(Some(path_var), home, true),
        None => executable_search_dirs_for_program_with_home(program, home),
    };
    dirs.into_iter()
        .map(|dir| dir.join(program))
        .find(|path| is_absolute_executable(path))
}

/// The daemon may locate a CLI outside launchd's minimal PATH. Its shebang
/// interpreter must be found in the same install's bin directory at probe time.
pub(crate) fn interactive_probe_path(home: &Path, program: &Path) -> Option<OsString> {
    let mut dirs = Vec::new();
    if let Some(parent) = program.parent().filter(|parent| parent.is_absolute()) {
        dirs.push(parent.into());
    }
    for dir in executable_search_dirs_from(
        env::var_os(COMMAND_SEARCH_PATH_ENV).or_else(|| env::var_os("PATH")),
        Some(home.as_os_str().to_owned()),
        true,
    ) {
        if dir.is_absolute() {
            push_unique(&mut dirs, dir);
        }
    }
    env::join_paths(dirs).ok()
}

fn first_program_in(dirs: impl IntoIterator<Item = PathBuf>, program: &str) -> Option<PathBuf> {
    dirs.into_iter().find_map(|dir| {
        let candidate = dir.join(program);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    })
}

/// Hardened Claude-only resolver. Every candidate comes from an absolute
/// search directory, remains an absolute path even when the file is an
/// official-install symlink, and must be executable by at least one class.
pub(crate) fn claude_executable_path(effective_home: &Path) -> Option<PathBuf> {
    claude_search_dirs(effective_home)
        .into_iter()
        .map(|dir| dir.join("claude"))
        .find(|candidate| is_absolute_executable(candidate))
}

/// Resolve a CLI that can consume the default login, without automatically
/// discovering Desktop's private bundle. Keep the launchd-safe native/npm
/// prefixes: absence from the service PATH alone does not mean absent CLI.
pub(crate) fn claude_default_login_executable_path(effective_home: &Path) -> Option<PathBuf> {
    let (path_var, home, include_default_dirs) = match env::var_os(COMMAND_SEARCH_PATH_ENV) {
        Some(path_var) => (Some(path_var), None, false),
        None => (
            env::var_os("PATH"),
            Some(effective_home.as_os_str().to_os_string()),
            true,
        ),
    };
    claude_default_login_executable_from(path_var, home, include_default_dirs)
}

fn claude_default_login_executable_from(
    path_var: Option<OsString>,
    home: Option<OsString>,
    include_default_dirs: bool,
) -> Option<PathBuf> {
    executable_search_dirs_from(path_var, home, include_default_dirs)
        .into_iter()
        .map(|dir| dir.join("claude"))
        .find(|candidate| is_absolute_executable(candidate))
}

pub(crate) fn claude_path_env(effective_home: &Path) -> Option<OsString> {
    env::join_paths(claude_search_dirs(effective_home)).ok()
}

fn claude_search_dirs(effective_home: &Path) -> Vec<PathBuf> {
    let dirs = if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        executable_search_dirs_from(Some(path_var), None, false)
    } else {
        executable_search_dirs_for_program_with_home(
            "claude",
            Some(effective_home.as_os_str().to_os_string()),
        )
    };
    dirs.into_iter().filter(|dir| dir.is_absolute()).collect()
}

#[cfg(unix)]
fn is_absolute_executable(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    candidate.is_absolute()
        && std::fs::metadata(candidate).ok().is_some_and(|metadata| {
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
        })
}

#[cfg(not(unix))]
fn is_absolute_executable(candidate: &Path) -> bool {
    candidate.is_absolute() && candidate.is_file()
}

fn executable_search_dirs_for_program(program: &str) -> Vec<PathBuf> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return executable_search_dirs_from(Some(path_var), None, false);
    }
    executable_search_dirs_for_program_with_home(program, env::var_os("HOME"))
}

/// App bundles that vendor the `codex` CLI. The standalone Codex desktop app
/// and the ChatGPT desktop app both ship it; on a Mac where Codex is used only
/// through a desktop app this is the only `codex` binary on disk.
const CODEX_DESKTOP_BUNDLES: &[&str] = &["Codex.app", "ChatGPT.app"];

/// Where a desktop bundle keeps `codex`, relative to `Contents/Resources`,
/// oldest layout first: directly in `Resources`; then the `codex-cli` folder
/// with its `bin/codex` launcher and the `CodexCLI.app` binary it launches.
const CODEX_BUNDLE_LAYOUTS: &[&[&str]] = &[
    &[],
    &["codex-cli", "bin"],
    &["codex-cli", "CodexCLI.app", "Contents", "MacOS"],
];

/// Every desktop-bundle directory that may hold `codex`, for each
/// applications root in order.
fn codex_desktop_bundle_dirs(application_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for bundle in CODEX_DESKTOP_BUNDLES {
        for root in application_roots {
            let resources = root.join(bundle).join("Contents").join("Resources");
            for layout in CODEX_BUNDLE_LAYOUTS {
                push_unique(
                    &mut dirs,
                    layout
                        .iter()
                        .fold(resources.clone(), |dir, part| dir.join(part)),
                );
            }
        }
    }
    dirs
}

fn executable_search_dirs_for_program_with_home(
    program: &str,
    home: Option<OsString>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if program == "codex" {
        let mut application_roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = home.as_ref().filter(|home| !home.is_empty()) {
            application_roots.push(PathBuf::from(home).join("Applications"));
        }
        for dir in codex_desktop_bundle_dirs(&application_roots) {
            push_unique(&mut dirs, dir);
        }
    }
    for dir in executable_search_dirs_from(env::var_os("PATH"), home.clone(), true) {
        push_unique(&mut dirs, dir);
    }
    if program == "claude" {
        if let Some(home) = home.as_ref().filter(|home| !home.is_empty()) {
            for dir in claude_desktop_vendored_bin_dirs(&PathBuf::from(home)) {
                push_unique(&mut dirs, dir);
            }
        }
    }
    dirs
}

/// Enumerate the Claude desktop app's vendored Claude Code binary directories:
/// `~/Library/Application Support/Claude/claude-code/<version>/claude.app/Contents/MacOS`.
/// The desktop app downloads a complete Claude Code CLI per version; on a Mac
/// where Claude Code is used only through the desktop app this is the only
/// `claude` binary on disk. Listed after PATH and the per-user CLI prefixes so
/// an explicit CLI install always wins; versions are ordered newest first so a
/// stale leftover download never shadows the current one. A missing root
/// simply yields no directories.
fn claude_desktop_vendored_bin_dirs(home: &Path) -> Vec<PathBuf> {
    let root = home
        .join("Library")
        .join("Application Support")
        .join("Claude")
        .join("claude-code");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut versioned: Vec<(Vec<u64>, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let bin_dir = entry
                .path()
                .join("claude.app")
                .join("Contents")
                .join("MacOS");
            bin_dir.is_dir().then(|| {
                (
                    version_sort_key(&entry.file_name().to_string_lossy()),
                    bin_dir,
                )
            })
        })
        .collect();
    versioned.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    versioned.into_iter().map(|(_, dir)| dir).collect()
}

/// Numeric components of a version-shaped directory name (`2.1.202` →
/// `[2, 1, 202]`) for a newest-first sort. Non-numeric fragments are skipped so
/// unexpected names sort last instead of failing enumeration.
fn version_sort_key(name: &str) -> Vec<u64> {
    name.split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

pub(crate) fn path_env() -> Option<OsString> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return path_env_from_override(Some(path_var));
    }
    path_env_from(env::var_os("PATH"), env::var_os("HOME"))
}

pub(crate) fn provider_env() -> BTreeMap<String, OsString> {
    provider_env_with_refresh(false)
}

pub(crate) fn provider_env_with_refresh(refresh: bool) -> BTreeMap<String, OsString> {
    let current = current_provider_env();
    let missing_shell_env = (refresh || current.len() < PROVIDER_ENV_KEYS.len())
        .then(|| cached_shell_provider_env(refresh))
        .flatten();
    provider_env_from_sources(&current, missing_shell_env.as_ref())
}

type ShellEnv = BTreeMap<String, OsString>;
type ShellEnvCache = Mutex<Option<(Option<OsString>, Instant, Option<ShellEnv>)>>;

fn cached_shell_provider_env(refresh: bool) -> Option<ShellEnv> {
    #[cfg(not(test))]
    static CACHE: ShellEnvCache = Mutex::new(None);
    #[cfg(not(test))]
    let (cache, now) = (&CACHE, Instant::now);
    #[cfg(test)]
    let (cache, now) = (test_shell_env::cache(), test_shell_env::now);
    let home = env::var_os("HOME");
    let requested = now();
    // Hold the lock through the bounded import; waiters share success or failure.
    let mut cached = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cached.as_ref().is_none_or(|(key, at, _)| {
        key != &home
            || now().saturating_duration_since(*at) >= Duration::from_secs(1800)
            || (refresh && *at < requested)
    }) {
        let shell = interactive_shell_provider_env();
        *cached = Some((home, now(), shell));
    }
    cached.as_ref()?.2.clone()
}

/// The environment a stdio MCP server or the Claude CLI is spawned with,
/// resolved ONCE per harvest cycle. The daemon runs under launchd with a
/// minimal `PATH` (`/usr/bin:/bin:…`), so a bare `Command::new("npx")` cannot
/// find the common MCP launchers (`npx`/`uvx`/`node`) and every such server
/// would falsely report `reachable:false`. We resolve a launchd-safe `PATH` and
/// the user's provider env exactly as the daemon spawns its other agent
/// subprocesses, so the harvest sees the same servers an interactive shell
/// (and the reference harvester) does.
#[derive(Clone)]
pub(crate) struct SpawnEnv {
    pub(crate) path: Option<OsString>,
    pub(crate) provider: BTreeMap<String, OsString>,
}

impl SpawnEnv {
    /// Resolve once per cycle (`provider_env` may briefly consult a login shell).
    pub(crate) fn resolve() -> Self {
        Self {
            path: path_env(),
            provider: provider_env(),
        }
    }
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

#[cfg(not(unix))]
fn interactive_shell_provider_env() -> Option<BTreeMap<String, OsString>> {
    None
}

#[cfg(unix)]
fn interactive_shell_provider_env() -> Option<BTreeMap<String, OsString>> {
    #[cfg(test)]
    if let Some(output) = test_shell_env::output() {
        return output.as_deref().map(parse_provider_env_output);
    }
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

    read_shell_env(command, INTERACTIVE_SHELL_ENV_TIMEOUT)
}

#[cfg(unix)]
fn read_shell_env(mut command: Command, timeout: Duration) -> Option<BTreeMap<String, OsString>> {
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let deadline = Instant::now() + timeout;
    // setsid is async-signal-safe and prevents access to the caller's controlling tty.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take().expect("piped shell stdout");
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    let nonblocking = flags >= 0
        && unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0;
    let mut ready = libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let mut output = Vec::new();
    let mut complete = false;
    while nonblocking && Instant::now() < deadline {
        let mut buffer = [0; 8192];
        match stdout.read(&mut buffer) {
            Ok(0) => match crate::process_guard::exited(&child) {
                Ok(true) => {
                    complete = Instant::now() < deadline;
                    break;
                }
                Ok(false) => thread::sleep(
                    Duration::from_millis(50)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            },
            Ok(n) if output.len() + n <= 1024 * 1024 => {
                output.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let millis = deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis();
                let result = unsafe { libc::poll(&mut ready, 1, millis.min(50) as libc::c_int) };
                if result < 0 && std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            _ => break,
        }
    }
    let status = crate::process_guard::stop_group_and_reap(
        child,
        deadline.saturating_duration_since(Instant::now()),
    );
    drop(stdout);
    (complete && status.ok()?.success()).then(|| parse_provider_env_output(&output))
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
pub(crate) mod test_shell_env {
    use super::{Instant, ShellEnvCache};
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;

    thread_local! {
        static OUTPUT: RefCell<Option<Option<Vec<u8>>>> = const { RefCell::new(None) };
        static CALLS: RefCell<usize> = const { RefCell::new(0) };
        static CACHE: RefCell<Arc<ShellEnvCache>> = RefCell::new(Arc::default());
        static NOW: Cell<Option<Instant>> = const { Cell::new(None) };
        static BEFORE_OUTPUT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(super) fn cache() -> Arc<ShellEnvCache> {
        CACHE.with_borrow(Arc::clone)
    }

    pub(super) fn now() -> Instant {
        NOW.get().unwrap_or_else(Instant::now)
    }

    pub(crate) fn set_output(output: Option<&[u8]>) {
        OUTPUT.set(Some(output.map(<[u8]>::to_vec)));
    }

    pub(crate) fn set_now(now: Instant) {
        NOW.set(Some(now));
    }

    pub(super) fn share_cache(cache: Arc<ShellEnvCache>) {
        CACHE.set(cache);
    }

    pub(super) fn before_output(hook: impl FnOnce() + 'static) {
        BEFORE_OUTPUT.set(Some(Box::new(hook)));
    }

    pub(super) fn output() -> Option<Option<Vec<u8>>> {
        if let Some(hook) = BEFORE_OUTPUT.take() {
            hook();
        }
        OUTPUT.with_borrow(|output| {
            if output.is_some() {
                CALLS.with_borrow_mut(|calls| *calls += 1);
            }
            output.clone()
        })
    }

    /// Inject the existing parser's shell stdout, or an import failure, on this thread.
    pub(crate) fn with_output<T>(output: Option<&[u8]>, run: impl FnOnce() -> T) -> (T, usize) {
        struct Restore(
            Option<Option<Vec<u8>>>,
            usize,
            Arc<ShellEnvCache>,
            Option<Instant>,
            Option<Box<dyn FnOnce()>>,
        );
        impl Drop for Restore {
            fn drop(&mut self) {
                OUTPUT.set(self.0.take());
                CALLS.set(self.1);
                CACHE.set(self.2.clone());
                NOW.set(self.3);
                BEFORE_OUTPUT.set(self.4.take());
            }
        }
        let _restore = Restore(
            OUTPUT.replace(Some(output.map(<[u8]>::to_vec))),
            CALLS.replace(0),
            CACHE.replace(Arc::default()),
            NOW.replace(None),
            BEFORE_OUTPUT.replace(None),
        );
        let result = run();
        (result, CALLS.with_borrow(|calls| *calls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_scratch;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const SHELL_PROJECT: &[u8] = b"GOOGLE_CLOUD_PROJECT=shell-project\n";

    #[test]
    #[serial_test::serial]
    fn shell_cache_reuses_import_within_ttl() {
        let (_, calls) = test_shell_env::with_output(Some(SHELL_PROJECT), || {
            let start = Instant::now();
            test_shell_env::set_now(start);
            let first = cached_shell_provider_env(false);
            test_shell_env::set_now(start + Duration::from_secs(1799));
            test_shell_env::set_output(Some(b"GOOGLE_CLOUD_PROJECT=changed\n"));
            assert_eq!(cached_shell_provider_env(false), first);
        });
        assert_eq!(calls, 1);
    }

    #[test]
    #[serial_test::serial]
    fn shell_cache_reimports_at_ttl_boundary() {
        let (_, calls) = test_shell_env::with_output(Some(SHELL_PROJECT), || {
            let start = Instant::now();
            test_shell_env::set_now(start);
            cached_shell_provider_env(false);
            test_shell_env::set_now(start + Duration::from_secs(1800));
            test_shell_env::set_output(Some(b"GOOGLE_CLOUD_PROJECT=changed\n"));
            let value = cached_shell_provider_env(false).unwrap();
            assert_eq!(value["GOOGLE_CLOUD_PROJECT"], "changed");
        });
        assert_eq!(calls, 2);
    }

    #[test]
    #[serial_test::serial]
    fn shell_cache_retains_failure_for_full_ttl() {
        let (_, calls) = test_shell_env::with_output(None, || {
            let start = Instant::now();
            test_shell_env::set_now(start);
            assert!(cached_shell_provider_env(false).is_none());
            test_shell_env::set_output(Some(SHELL_PROJECT));
            test_shell_env::set_now(start + Duration::from_secs(1799));
            assert!(cached_shell_provider_env(false).is_none());
            test_shell_env::set_now(start + Duration::from_secs(1800));
            assert!(cached_shell_provider_env(false).is_some());
        });
        assert_eq!(calls, 2);
    }

    #[test]
    #[serial_test::serial]
    fn shell_cache_home_change_is_a_miss() {
        let (_, calls) = test_shell_env::with_output(Some(SHELL_PROJECT), || {
            cached_shell_provider_env(false);
            test_shell_env::cache().lock().unwrap().as_mut().unwrap().0 =
                Some(OsString::from("different-synthetic-home"));
            test_shell_env::set_output(Some(b"GOOGLE_CLOUD_PROJECT=changed\n"));
            assert_eq!(
                cached_shell_provider_env(false).unwrap()["GOOGLE_CLOUD_PROJECT"],
                "changed"
            );
        });
        assert_eq!(calls, 2);
    }

    #[test]
    #[serial_test::serial]
    fn shell_cache_concurrent_callers_share_one_import() {
        use std::sync::{mpsc, Arc, Barrier};
        let cache = Arc::new(ShellEnvCache::default());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let importer_cache = cache.clone();
        let importer = std::thread::spawn(move || {
            test_shell_env::with_output(Some(SHELL_PROJECT), || {
                test_shell_env::share_cache(importer_cache);
                test_shell_env::before_output(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                cached_shell_provider_env(false).unwrap()
            })
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let (done_tx, done_rx) = mpsc::channel();
        let workers = (0..7)
            .map(|_| {
                let cache = cache.clone();
                let barrier = barrier.clone();
                let done = done_tx.clone();
                std::thread::spawn(move || {
                    test_shell_env::with_output(Some(SHELL_PROJECT), || {
                        test_shell_env::share_cache(cache);
                        barrier.wait();
                        let result = cached_shell_provider_env(false).unwrap();
                        done.send(()).unwrap();
                        result
                    })
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let waiting = done_rx.recv_timeout(Duration::from_millis(50)).is_err();
        release_tx.send(()).unwrap();
        let (_, mut calls) = importer.join().unwrap();
        for worker in workers {
            let (value, imports) = worker.join().unwrap();
            assert_eq!(value["GOOGLE_CLOUD_PROJECT"], "shell-project");
            calls += imports;
        }
        assert!(
            waiting,
            "callers must wait until the in-flight import completes"
        );
        assert_eq!(calls, 1);
    }

    #[test]
    #[serial_test::serial]
    fn shell_cache_overlapping_refresh_shares_completed_import() {
        let (_, calls) = test_shell_env::with_output(Some(SHELL_PROJECT), || {
            let start = Instant::now();
            test_shell_env::set_now(start);
            cached_shell_provider_env(false);
            // A refresh that began no later than this completed fill shares it.
            assert_eq!(
                cached_shell_provider_env(true),
                cached_shell_provider_env(false)
            );
            test_shell_env::set_now(start + Duration::from_secs(1));
            test_shell_env::set_output(None);
            assert!(cached_shell_provider_env(true).is_none());
            assert!(cached_shell_provider_env(false).is_none());
        });
        assert_eq!(calls, 2);
    }

    fn scratch_home(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join("ottto-command-env-tests")
            .join(test_scratch::unique_name(name))
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

    /// Resolve through the same lookup `executable_path` uses; whatever it
    /// finds must also be runnable.
    fn codex_resolved_in(dirs: &[PathBuf]) -> Option<PathBuf> {
        let found = first_program_in(dirs.iter().cloned(), "codex");
        if let Some(path) = &found {
            assert!(
                is_absolute_executable(path),
                "{} is not executable",
                path.display()
            );
        }
        found
    }

    #[test]
    fn codex_resolver_finds_old_and_new_desktop_bundle_layouts() {
        let root = scratch_home("codex-bundle-layouts");
        let write_codex = |dir: PathBuf| {
            fs::create_dir_all(&dir).expect("layout dir");
            let codex = dir.join("codex");
            fs::write(&codex, "#!/bin/sh\n").expect("codex");
            fs::set_permissions(&codex, fs::Permissions::from_mode(0o755)).expect("chmod codex");
            codex
        };

        // Old layout: `Resources/codex`.
        let old_root = root.join("old");
        let old = write_codex(old_root.join("ChatGPT.app/Contents/Resources"));
        assert_eq!(
            codex_resolved_in(&codex_desktop_bundle_dirs(&[old_root])),
            Some(old)
        );

        // New layout: the `bin/codex` launcher wins over the binary it runs.
        let new_root = root.join("new");
        let launcher = write_codex(new_root.join("ChatGPT.app/Contents/Resources/codex-cli/bin"));
        let binary = write_codex(
            new_root.join("ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS"),
        );
        let new_dirs = codex_desktop_bundle_dirs(std::slice::from_ref(&new_root));
        assert_eq!(codex_resolved_in(&new_dirs), Some(launcher.clone()));

        // A bundle that ships only the inner app binary still resolves.
        fs::remove_file(&launcher).expect("remove launcher");
        assert_eq!(codex_resolved_in(&new_dirs), Some(binary));

        // Nothing installed: nothing resolved from bundles.
        assert_eq!(
            codex_resolved_in(&codex_desktop_bundle_dirs(&[root.join("empty")])),
            None
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn claude_search_dirs_include_desktop_vendored_binaries_newest_first() {
        let home = scratch_home("claude-desktop");
        let vendored_root = home.join("Library/Application Support/Claude/claude-code");
        let old_bin = vendored_root.join("2.1.9/claude.app/Contents/MacOS");
        let new_bin = vendored_root.join("2.1.202/claude.app/Contents/MacOS");
        fs::create_dir_all(&old_bin).expect("old vendored dir");
        fs::create_dir_all(&new_bin).expect("new vendored dir");
        // A stray non-version entry must not break enumeration.
        fs::write(vendored_root.join("README"), "x").ok();

        let dirs = executable_search_dirs_for_program_with_home(
            "claude",
            Some(home.as_os_str().to_os_string()),
        );

        let new_pos = dirs.iter().position(|dir| dir == &new_bin);
        let old_pos = dirs.iter().position(|dir| dir == &old_bin);
        assert!(new_pos.is_some(), "newest vendored dir searched: {dirs:?}");
        assert!(old_pos.is_some(), "older vendored dir searched: {dirs:?}");
        assert!(new_pos < old_pos, "2.1.202 must outrank 2.1.9: {dirs:?}");
        // Vendored desktop dirs are a fallback: explicit CLI installs win.
        let local_bin_pos = dirs
            .iter()
            .position(|dir| dir == &home.join(".local/bin"))
            .expect("home cli dir present");
        assert!(local_bin_pos < new_pos.expect("new pos"));

        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn default_login_resolver_ignores_desktop_fallback_but_finds_off_path_cli() {
        let home = scratch_home("default-login-cli");
        let desktop_bin = home.join(
            "Library/Application Support/Claude/claude-code/2.1.202/claude.app/Contents/MacOS",
        );
        fs::create_dir_all(&desktop_bin).expect("desktop bin");
        let desktop_cli = desktop_bin.join("claude");
        fs::write(&desktop_cli, "#!/bin/sh\n").expect("desktop cli");
        fs::set_permissions(&desktop_cli, fs::Permissions::from_mode(0o755)).expect("chmod");
        let resolve = || {
            claude_default_login_executable_from(
                Some(home.join("service-bin").into_os_string()),
                Some(home.as_os_str().to_os_string()),
                false,
            )
        };
        assert_eq!(
            resolve(),
            None,
            "Desktop's bundled CLI does not require default login"
        );
        assert!(claude_desktop_vendored_bin_dirs(&home).contains(&desktop_bin));
        let bin = home.join(".nvm/versions/node/v22.19.0/bin");
        fs::create_dir_all(&bin).expect("cli prefix");
        let cli = bin.join("claude");
        symlink(&desktop_cli, &cli).expect("executable shim");
        assert_eq!(resolve(), Some(cli.clone()), "off-PATH nvm CLI");
        fs::remove_file(&cli).expect("remove shim");
        fs::write(&cli, "non executable").expect("write inert file");
        assert_eq!(resolve(), None, "inert nvm file is not a CLI");
        fs::remove_file(cli).expect("remove inert file");
        // An explicit search override is authoritative and may point at a bundle.
        assert_eq!(
            claude_default_login_executable_from(Some(desktop_bin.into_os_string()), None, false),
            Some(desktop_cli),
        );
        assert_eq!(
            claude_default_login_executable_from(Some(OsString::from("relative")), None, false),
            None,
        );
        fs::remove_dir_all(home).expect("cleanup");
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

    struct FakeShell {
        home: PathBuf,
    }

    impl FakeShell {
        fn new() -> Self {
            let home = scratch_home("provider-shell");
            fs::create_dir_all(&home).expect("fake shell directory");
            Self { home }
        }

        fn run(&self, script: &str, timeout: Duration) -> Option<BTreeMap<String, OsString>> {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script, "fake-shell"])
                .arg(self.home.join("child-pid"))
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            read_shell_env(command, timeout)
        }

        fn child_running(&self) -> bool {
            let pid = fs::read_to_string(self.home.join("child-pid")).expect("child started");
            let status = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", pid.trim()])
                .output()
                .expect("child status");
            let status = String::from_utf8_lossy(&status.stdout);
            // An orphan killed in the group can await init's reaping as a zombie.
            !status.trim().is_empty() && !status.trim().starts_with('Z')
        }

        fn assert_child_stopped(&self) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.child_running() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            assert!(!self.child_running(), "shell group child survived");
        }
    }

    impl Drop for FakeShell {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.home).ok();
        }
    }

    #[test]
    fn provider_shell_bounds_inherited_stdout_after_shell_exit() {
        let shell = FakeShell::new();
        let start = Instant::now();
        let result = shell.run(
            "/bin/sleep 10 & echo $! > \"$1\"; printf 'GOOGLE_CLOUD_PROJECT=shell-project\\n'",
            Duration::from_millis(300),
        );
        assert!(result.is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
        shell.assert_child_stopped();
    }

    #[test]
    #[ignore = "fake session leader invoked only by provider shell tests"]
    fn provider_shell_session_fixture() {
        assert_eq!(unsafe { libc::getsid(0) }, unsafe { libc::getpid() });
        assert_eq!(unsafe { libc::getpgrp() }, unsafe { libc::getpid() });
        println!("\nGOOGLE_CLOUD_PROJECT=session-leader");
    }

    #[test]
    fn provider_shell_starts_its_own_session_and_group() {
        let shell = FakeShell::new();
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            "exec '{executable}' --ignored --exact command_env::tests::provider_shell_session_fixture --nocapture --test-threads=1"
        );
        assert_eq!(
            shell
                .run(&script, INTERACTIVE_SHELL_ENV_TIMEOUT)
                .expect("shell is the session leader")
                .get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("session-leader"))
        );
    }

    #[test]
    fn provider_shell_success_stops_redirected_background_job() {
        let shell = FakeShell::new();
        let result = shell.run(
            "/bin/sleep 10 >/dev/null 2>&1 & echo $! > \"$1\"; printf 'GOOGLE_CLOUD_PROJECT=shell-project\\n'",
            INTERACTIVE_SHELL_ENV_TIMEOUT,
        );
        shell.assert_child_stopped();
        assert_eq!(
            result.expect("complete env").get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("shell-project"))
        );
    }

    #[test]
    fn provider_shell_nonzero_exit_stops_redirected_background_job() {
        let shell = FakeShell::new();
        assert!(shell.run(
            "/bin/sleep 10 >/dev/null 2>&1 & echo $! > \"$1\"; printf 'GOOGLE_CLOUD_PROJECT=failed\\n'; exit 7",
            INTERACTIVE_SHELL_ENV_TIMEOUT,
        ).is_none());
        shell.assert_child_stopped();
    }

    #[test]
    fn provider_shell_drains_more_than_a_pipe_buffer() {
        let shell = FakeShell::new();
        let result = shell.run(
            "i=0; while [ $i -lt 8192 ]; do printf 'IGNORED=0123456789abcdef\\n'; i=$((i+1)); done; printf 'GOOGLE_CLOUD_PROJECT=shell-project\\n'",
            INTERACTIVE_SHELL_ENV_TIMEOUT,
        );
        assert_eq!(
            result
                .expect("large env parsed")
                .get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("shell-project"))
        );
    }

    #[test]
    fn provider_shell_rejects_excess_output() {
        let shell = FakeShell::new();
        let start = Instant::now();
        assert!(shell
            .run(
                "printf 'GOOGLE_CLOUD_PROJECT=partial\\n'; exec /usr/bin/head -c 1048577 /dev/zero",
                Duration::from_secs(15),
            )
            .is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn provider_shell_accepts_exact_byte_bound() {
        let shell = FakeShell::new();
        let line = "GOOGLE_CLOUD_PROJECT=shell-project\n";
        let script = format!(
            "printf 'GOOGLE_CLOUD_PROJECT=shell-project\\n'; exec /usr/bin/head -c {} /dev/zero",
            1024 * 1024 - line.len()
        );
        assert_eq!(
            shell
                .run(&script, INTERACTIVE_SHELL_ENV_TIMEOUT)
                .expect("complete environment at the bound")
                .get("GOOGLE_CLOUD_PROJECT"),
            Some(&OsString::from("shell-project"))
        );
    }

    #[test]
    #[ignore = "finite escaped child invoked only by provider shell tests"]
    fn provider_shell_escaped_writer_fixture() {
        let Some(pid_file) = env::var_os("OTTTO_PROVIDER_SHELL_PIPE_FIXTURE").map(PathBuf::from)
        else {
            return;
        };
        assert!(unsafe { libc::setsid() } >= 0);
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        fs::write(&pid_file, std::process::id().to_string()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            if unsafe { libc::write(libc::STDOUT_FILENO, b"x".as_ptr().cast(), 1) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPIPE)
            {
                fs::write(pid_file.with_extension("closed"), []).unwrap();
                std::process::exit(0);
            }
            thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(1);
    }

    #[test]
    fn provider_shell_closes_pipe_on_escaped_writer() {
        let shell = FakeShell::new();
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            "export OTTTO_PROVIDER_SHELL_PIPE_FIXTURE=\"$1\"; '{executable}' --ignored --exact command_env::tests::provider_shell_escaped_writer_fixture --nocapture --test-threads=1 & while [ ! -s \"$1\" ]; do /bin/sleep 0.01; done"
        );
        let start = Instant::now();
        assert!(shell.run(&script, Duration::from_millis(700)).is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
        shell.assert_child_stopped();
        assert!(
            shell.home.join("child-pid.closed").exists(),
            "escaped writer did not observe EPIPE"
        );
    }

    #[test]
    fn provider_shell_timeout_kills_its_group_after_stdout_closes() {
        let shell = FakeShell::new();
        let start = Instant::now();
        let result = shell.run(
            "exec 1>&-; /bin/sleep 10 & echo $! > \"$1\"; exec /bin/sleep 10",
            Duration::from_millis(300),
        );
        assert!(result.is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
        shell.assert_child_stopped();
    }

    #[test]
    fn provider_shell_normal_output_and_failure_are_unchanged() {
        let shell = FakeShell::new();
        let output =
            "printf 'GOOGLE_CLOUD_PROJECT=shell-project\\nIGNORED=value\\nGEMINI_API_KEY=\\n'";
        let expected = BTreeMap::from([(
            "GOOGLE_CLOUD_PROJECT".to_string(),
            OsString::from("shell-project"),
        )]);
        assert_eq!(
            shell.run(output, INTERACTIVE_SHELL_ENV_TIMEOUT),
            Some(expected)
        );
        assert!(shell.run("exit 1", INTERACTIVE_SHELL_ENV_TIMEOUT).is_none());
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
}
