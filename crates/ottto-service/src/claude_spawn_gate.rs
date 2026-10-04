//! The single choke point for spawning the Claude Code CLI.
//!
//! Claude Code refreshes an OAuth login inside almost any command that starts
//! within five minutes of the access token's expiry (or after it), and a 401
//! forces a refresh regardless of the clock. A command that exits, or is
//! killed, before the rotated token is saved leaves the stored refresh token
//! spent; the next run gets `invalid_grant` and Claude Code blanks the login
//! (anthropics/claude-code#95822). Short daemon spawns (`auth status` on every
//! pass, `doctor` upkeep, a killed `-p /context`) signed users out this way.
//!
//! This module is the only code that may build a `claude` `Command`
//! (`claude_spawn_gate::tests::no_claude_spawn_outside_the_gate` enforces it):
//!
//! - `VersionProbe`: exactly `["--version"]`. Claude Code prints and returns
//!   before any login code for this exact argv.
//! - `BrowserLogin`: exactly `["auth", "login", "--claudeai"]`, only in an
//!   Ottto-managed auth root. A user-started sign-in is never blocked.
//! - `CredentialUsing`: the `-p /context` footprint read and the Verify smoke
//!   prompt only. Admission re-reads the target's stored credential right
//!   before the spawn and refuses unless the access token stays valid for the
//!   CLI refresh window, a safety margin and the command's whole runtime.
//!
//! Everything else (`auth status`, `doctor`, `setup-token`, `mcp serve`, ...)
//! cannot be spawned.

use ottto_core::ClaudeConfigDirSlot;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use time::{Duration as TimeDuration, OffsetDateTime};

/// Claude Code refreshes when `now + 5 min >= expiresAt`.
pub(crate) const CLI_REFRESH_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Launch latency, MCP start-up and clock skew on top of the refresh window.
pub(crate) const SAFETY_MARGIN: Duration = Duration::from_secs(10 * 60);
/// A stored access deadline further out than this is a clock or format
/// anomaly, not a login Claude Code issued.
pub(crate) const IMPLAUSIBLE_EXPIRY_HORIZON: Duration = Duration::from_secs(24 * 60 * 60);
/// Another Claude Code process holding its refresh lock this recently is
/// refreshing now.
pub(crate) const REFRESH_LOCK_FRESHNESS: Duration = Duration::from_secs(60);
/// A permit must be spawned promptly after its credential read.
const PERMIT_SPAWN_WINDOW: Duration = Duration::from_secs(1);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Claude Code's advisory refresh lock inside the config directory.
const REFRESH_LOCK_FILE: &str = ".oauth_refresh.lock";

/// The exact Verify smoke argv (`claude -p <prompt> ...`).
pub(crate) fn claude_smoke_argv() -> [&'static str; 6] {
    [
        "-p",
        crate::control::SMOKE_PROMPT,
        "--name",
        "ottto test",
        "--disallowedTools",
        "*",
    ]
}

/// The official browser sign-in argv.
pub(crate) const CLAUDE_BROWSER_LOGIN_ARGV: [&str; 3] = ["auth", "login", "--claudeai"];

const CONTEXT_ARGV: [&str; 4] = ["-p", "/context", "--output-format", "json"];
const STRICT_MCP_FLAG: &str = "--strict-mcp-config";

/// The `/context` footprint argv, with `--strict-mcp-config` unless the user's
/// MCP servers should load for this one sampled workspace.
pub(crate) fn claude_context_argv(include_mcp_servers: bool) -> Vec<&'static str> {
    let mut argv = CONTEXT_ARGV.to_vec();
    if !include_mcp_servers {
        argv.push(STRICT_MCP_FLAG);
    }
    argv
}

/// Token-carrying variables that would make the child use a credential other
/// than the target's stored login, or none the gate evaluated.
const STRIPPED_TOKEN_ENV: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
];
const STRIPPED_TOKEN_ENV_PREFIX: &str = "CLAUDE_CODE_OAUTH_";
/// Presentation-only variables a caller may add to an admitted command.
const TERMINAL_ENV: &[&str] = &["TERM", "NO_COLOR", "FORCE_COLOR"];

/// Which Claude login the child will use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaudeSpawnTarget {
    /// `CLAUDE_CONFIG_DIR` unset: the default `~/.claude` login.
    Default,
    /// One exact registered config dir.
    Registered(ClaudeConfigDirSlot),
}

impl ClaudeSpawnTarget {
    fn slot(&self) -> ClaudeConfigDirSlot {
        match self {
            Self::Default => ClaudeConfigDirSlot::Default,
            Self::Registered(slot) => slot.clone(),
        }
    }

    fn config_dir(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Registered(slot) => slot.config_dir(),
        }
    }

    /// Short, non-reversible label for logs; never the path.
    fn log_label(&self) -> String {
        match self.config_dir() {
            None => "default".to_string(),
            Some(dir) => {
                let digest = Sha256::digest(dir.as_bytes());
                format!("slot:{}", &format!("{digest:x}")[..12])
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeSpawnClass {
    /// argv must equal `["--version"]`.
    VersionProbe { max_runtime: Duration },
    /// argv must equal `["auth", "login", "--claudeai"]`; managed roots only.
    BrowserLogin,
    /// Allowlisted credential-using argv only; admitted near expiry never.
    CredentialUsing { max_runtime: Duration },
}

impl ClaudeSpawnClass {
    fn label(self) -> &'static str {
        match self {
            Self::VersionProbe { .. } => "version_probe",
            Self::BrowserLogin => "browser_login",
            Self::CredentialUsing { .. } => "credential_using",
        }
    }

    fn max_runtime(self) -> Option<Duration> {
        match self {
            Self::VersionProbe { max_runtime } | Self::CredentialUsing { max_runtime } => {
                Some(max_runtime)
            }
            Self::BrowserLogin => None,
        }
    }
}

/// Secret-free view of a stored credential for admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeGateCredential {
    /// No stored OAuth login: nothing can be refreshed.
    Absent,
    /// The read failed or the item is malformed: fail closed.
    ReadFailed,
    Present {
        has_refresh_token: bool,
        access_expires_at: Option<OffsetDateTime>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeSpawnRefusal {
    ArgvNotAllowed,
    TargetNotAllowed,
    MissingBinary,
    NoEffectiveUser,
    CredentialReadFailed,
    AccessExpiryUnknown,
    TooCloseToExpiry,
    ImplausibleExpiry,
    RefreshInProgress,
    NetworkDisabled,
}

impl ClaudeSpawnRefusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::ArgvNotAllowed => "argv_not_allowed",
            Self::TargetNotAllowed => "target_not_allowed",
            Self::MissingBinary => "missing_binary",
            Self::NoEffectiveUser => "no_effective_user",
            Self::CredentialReadFailed => "credential_read_failed",
            Self::AccessExpiryUnknown => "access_expiry_unknown",
            Self::TooCloseToExpiry => "too_close_to_expiry",
            Self::ImplausibleExpiry => "implausible_expiry",
            Self::RefreshInProgress => "refresh_in_progress",
            Self::NetworkDisabled => "network_disabled",
        }
    }

    /// Claude Code itself must refresh this login first; a later attempt can
    /// succeed without any user action beyond using Claude Code.
    pub(crate) fn waits_for_claude_refresh(self) -> bool {
        matches!(self, Self::TooCloseToExpiry | Self::RefreshInProgress)
    }
}

/// Evidence admission reads. Production reads the keychain/credentials file,
/// the refresh lock and the network sentinel; tests inject fakes.
pub(crate) trait ClaudeSpawnEvidence {
    fn credential(&self, slot: &ClaudeConfigDirSlot) -> ClaudeGateCredential;
    fn refresh_lock_modified(&self, config_dir: &Path) -> Option<SystemTime>;
    fn network_disabled(&self) -> bool;
    fn now(&self) -> OffsetDateTime;
}

struct ProductionEvidence;

impl ClaudeSpawnEvidence for ProductionEvidence {
    fn credential(&self, slot: &ClaudeConfigDirSlot) -> ClaudeGateCredential {
        crate::agent_status::read_claude_spawn_gate_credential(slot)
    }

    fn refresh_lock_modified(&self, config_dir: &Path) -> Option<SystemTime> {
        // Read-only: the lock belongs to Claude Code and is never touched.
        std::fs::metadata(config_dir.join(REFRESH_LOCK_FILE))
            .and_then(|metadata| metadata.modified())
            .ok()
    }

    fn network_disabled(&self) -> bool {
        crate::agent_status::claude_oauth_usage_network_disabled()
    }

    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Decide whether a credential-using child may start now. Pure: every input is
/// passed in, so the boundaries are tested with a fake clock.
pub(crate) fn evaluate_credential_spawn(
    credential: ClaudeGateCredential,
    refresh_lock_modified: Option<SystemTime>,
    network_disabled: bool,
    now: OffsetDateTime,
    max_runtime: Duration,
) -> Result<(), ClaudeSpawnRefusal> {
    if network_disabled {
        return Err(ClaudeSpawnRefusal::NetworkDisabled);
    }
    match credential {
        ClaudeGateCredential::ReadFailed => return Err(ClaudeSpawnRefusal::CredentialReadFailed),
        // No refresh token: no refresh is possible, so none can be lost.
        ClaudeGateCredential::Absent
        | ClaudeGateCredential::Present {
            has_refresh_token: false,
            ..
        } => return Ok(()),
        ClaudeGateCredential::Present {
            has_refresh_token: true,
            access_expires_at: None,
        } => return Err(ClaudeSpawnRefusal::AccessExpiryUnknown),
        ClaudeGateCredential::Present {
            has_refresh_token: true,
            access_expires_at: Some(expires_at),
        } => {
            let remaining = expires_at - now;
            if remaining > duration_to_time(IMPLAUSIBLE_EXPIRY_HORIZON) {
                return Err(ClaudeSpawnRefusal::ImplausibleExpiry);
            }
            let required = duration_to_time(CLI_REFRESH_WINDOW + SAFETY_MARGIN + max_runtime);
            if remaining < required {
                return Err(ClaudeSpawnRefusal::TooCloseToExpiry);
            }
        }
    }
    if let Some(modified) = refresh_lock_modified {
        let modified = OffsetDateTime::from(modified);
        // A lock stamped in the future (clock jump) is treated as fresh.
        if now - modified < duration_to_time(REFRESH_LOCK_FRESHNESS) {
            return Err(ClaudeSpawnRefusal::RefreshInProgress);
        }
    }
    Ok(())
}

fn duration_to_time(duration: Duration) -> TimeDuration {
    TimeDuration::try_from(duration).unwrap_or(TimeDuration::MAX)
}

fn argv_allowed(class: ClaudeSpawnClass, argv: &[&str]) -> bool {
    match class {
        ClaudeSpawnClass::VersionProbe { .. } => argv == ["--version"],
        ClaudeSpawnClass::BrowserLogin => argv == CLAUDE_BROWSER_LOGIN_ARGV,
        ClaudeSpawnClass::CredentialUsing { .. } => {
            argv == CONTEXT_ARGV
                || (argv.len() == CONTEXT_ARGV.len() + 1
                    && argv[..CONTEXT_ARGV.len()] == CONTEXT_ARGV
                    && argv[CONTEXT_ARGV.len()] == STRICT_MCP_FLAG)
                || argv == claude_smoke_argv()
        }
    }
}

/// An admitted `claude` command. Callers may set standard streams, the working
/// directory and presentation-only variables, then must spawn it within one
/// second of admission. The binary path and the credential environment are
/// owned here.
pub(crate) struct ClaudeSpawnPermit {
    command: Command,
    class: ClaudeSpawnClass,
    admitted_at: Instant,
}

impl std::fmt::Debug for ClaudeSpawnPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaudeSpawnPermit")
            .field("class", &self.class.label())
            .finish_non_exhaustive()
    }
}

impl ClaudeSpawnPermit {
    pub(crate) fn stdin(&mut self, stdio: Stdio) -> &mut Self {
        self.command.stdin(stdio);
        self
    }

    pub(crate) fn stdout(&mut self, stdio: Stdio) -> &mut Self {
        self.command.stdout(stdio);
        self
    }

    pub(crate) fn stderr(&mut self, stdio: Stdio) -> &mut Self {
        self.command.stderr(stdio);
        self
    }

    pub(crate) fn current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.command.current_dir(dir);
        self
    }

    /// The user's provider variables (for example `ANTHROPIC_API_KEY` or a
    /// Vertex project), resolved once per cycle by the caller. Only the
    /// allowlisted provider keys are applied; token and config-dir variables
    /// stay as admission set them.
    pub(crate) fn provider_env(
        &mut self,
        values: &std::collections::BTreeMap<String, OsString>,
    ) -> &mut Self {
        for (key, value) in values {
            if crate::command_env::is_provider_env_key(key)
                && !STRIPPED_TOKEN_ENV.contains(&key.as_str())
                && !key.starts_with(STRIPPED_TOKEN_ENV_PREFIX)
            {
                self.command.env(key, value);
            }
        }
        self
    }

    /// Presentation-only variables (`TERM`, `NO_COLOR`, `FORCE_COLOR`).
    pub(crate) fn terminal_env(&mut self, key: &'static str, value: &'static str) -> &mut Self {
        debug_assert!(TERMINAL_ENV.contains(&key), "not a presentation variable");
        if TERMINAL_ENV.contains(&key) {
            self.command.env(key, value);
        }
        self
    }

    /// Spawn the admitted command. The returned deadline uses both a monotonic
    /// and a wall clock, so a Mac that sleeps while the child runs still kills
    /// it once the real time budget is gone.
    pub(crate) fn spawn(mut self) -> std::io::Result<ClaudeChild> {
        if self.admitted_at.elapsed() > PERMIT_SPAWN_WINDOW {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Claude spawn permit expired before spawn",
            ));
        }
        let child = self.command.spawn()?;
        let deadline = self.class.max_runtime().map(ClaudeDeadline::after);
        Ok(ClaudeChild { child, deadline })
    }

    #[cfg(test)]
    pub(crate) fn command_for_tests(&self) -> &Command {
        &self.command
    }
}

/// Monotonic plus wall-clock deadline for an admitted child (`Instant` does
/// not advance while the Mac sleeps).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeDeadline {
    monotonic: Instant,
    wall: SystemTime,
}

impl ClaudeDeadline {
    fn after(runtime: Duration) -> Self {
        Self {
            monotonic: Instant::now() + runtime,
            wall: SystemTime::now() + runtime,
        }
    }

    pub(crate) fn passed(&self) -> bool {
        Instant::now() >= self.monotonic || SystemTime::now() >= self.wall
    }
}

pub(crate) struct ClaudeChild {
    child: Child,
    deadline: Option<ClaudeDeadline>,
}

impl ClaudeChild {
    /// The child plus its runtime deadline (`None` for a browser sign-in,
    /// whose supervisor owns cancellation).
    pub(crate) fn into_parts(self) -> (Child, Option<ClaudeDeadline>) {
        (self.child, self.deadline)
    }
}

/// Output of an admitted child run to completion with piped streams.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClaudeCapturedOutput {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Run an admitted command with null stdin and piped output, killing it at its
/// class deadline.
pub(crate) fn run_to_completion(mut permit: ClaudeSpawnPermit) -> ClaudeCapturedOutput {
    permit
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let Ok(child) = permit.spawn() else {
        return ClaudeCapturedOutput::default();
    };
    let (mut child, deadline) = child.into_parts();
    let stdout = child.stdout.take().map(spawn_pipe_reader);
    let stderr = child.stderr.take().map(spawn_pipe_reader);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return ClaudeCapturedOutput {
                    success: status.success(),
                    stdout: collect_pipe(stdout),
                    stderr: collect_pipe(stderr),
                };
            }
            Ok(None) if deadline.is_some_and(|deadline| deadline.passed()) => {
                let _ = child.kill();
                let _ = child.wait();
                return ClaudeCapturedOutput {
                    success: false,
                    stdout: collect_pipe(stdout),
                    stderr: collect_pipe(stderr),
                };
            }
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return ClaudeCapturedOutput::default();
            }
        }
    }
}

fn spawn_pipe_reader<R>(mut pipe: R) -> mpsc::Receiver<String>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = String::new();
        let _ = pipe.read_to_string(&mut output);
        let _ = sender.send(output);
    });
    receiver
}

fn collect_pipe(reader: Option<mpsc::Receiver<String>>) -> String {
    reader
        .and_then(|receiver| receiver.recv_timeout(PIPE_DRAIN_TIMEOUT).ok())
        .unwrap_or_default()
}

/// Admit one `claude` spawn. This is the only way to obtain a `claude`
/// `Command` in this crate.
pub(crate) fn admit(
    target: ClaudeSpawnTarget,
    class: ClaudeSpawnClass,
    argv: &[&str],
) -> Result<ClaudeSpawnPermit, ClaudeSpawnRefusal> {
    admit_with(target, class, argv, &ProductionEvidence)
}

fn admit_with(
    target: ClaudeSpawnTarget,
    class: ClaudeSpawnClass,
    argv: &[&str],
    evidence: &dyn ClaudeSpawnEvidence,
) -> Result<ClaudeSpawnPermit, ClaudeSpawnRefusal> {
    let mut evaluated = None;
    let decision = admit_decision(&target, class, argv, evidence, &mut evaluated);
    log_decision(&target, class, &decision, evaluated, evidence.now());
    decision.map(|command| ClaudeSpawnPermit {
        command,
        class,
        admitted_at: Instant::now(),
    })
}

fn admit_decision(
    target: &ClaudeSpawnTarget,
    class: ClaudeSpawnClass,
    argv: &[&str],
    evidence: &dyn ClaudeSpawnEvidence,
    evaluated: &mut Option<ClaudeGateCredential>,
) -> Result<Command, ClaudeSpawnRefusal> {
    if !argv_allowed(class, argv) {
        return Err(ClaudeSpawnRefusal::ArgvNotAllowed);
    }
    if let ClaudeSpawnTarget::Registered(slot) = target {
        if slot.config_dir().is_none() {
            return Err(ClaudeSpawnRefusal::TargetNotAllowed);
        }
    }
    if class == ClaudeSpawnClass::BrowserLogin
        && !target
            .config_dir()
            .is_some_and(|dir| ottto_core::validate_managed_claude_auth_root(dir).is_ok())
    {
        return Err(ClaudeSpawnRefusal::TargetNotAllowed);
    }
    // Build the command before reading the credential so the read-to-spawn
    // gap stays as short as possible.
    let command = build_command(target, class, argv)?;
    if let ClaudeSpawnClass::CredentialUsing { max_runtime } = class {
        let slot = target.slot();
        let lock_dir = slot
            .credentials_path(&crate::agent_status::home_dir())
            .parent()
            .map(Path::to_path_buf);
        let credential = evidence.credential(&slot);
        *evaluated = Some(credential);
        evaluate_credential_spawn(
            credential,
            lock_dir
                .as_deref()
                .and_then(|dir| evidence.refresh_lock_modified(dir)),
            evidence.network_disabled(),
            evidence.now(),
            max_runtime,
        )?;
    }
    Ok(command)
}

fn build_command(
    target: &ClaudeSpawnTarget,
    class: ClaudeSpawnClass,
    argv: &[&str],
) -> Result<Command, ClaudeSpawnRefusal> {
    let (account_name, home) = crate::agent_status::claude_spawn_user_identity()
        .ok_or(ClaudeSpawnRefusal::NoEffectiveUser)?;
    let program = resolve_claude_binary(&home).ok_or(ClaudeSpawnRefusal::MissingBinary)?;
    let mut command = Command::new(program);
    command.args(argv);
    match class {
        ClaudeSpawnClass::BrowserLogin => {
            // The exact sanitized environment the official login always ran
            // with: no ambient provider or token variables survive.
            command
                .env_clear()
                .env("HOME", &home)
                .env("USER", account_name);
            for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
                if let Some(value) = std::env::var_os(locale_key) {
                    command.env(locale_key, value);
                }
            }
            if let Some(path_env) = claude_path_env(&home) {
                command.env("PATH", path_env);
            }
        }
        ClaudeSpawnClass::VersionProbe { .. } => {
            if let Some(path_env) = crate::command_env::path_env() {
                command.env("PATH", path_env);
            }
        }
        ClaudeSpawnClass::CredentialUsing { .. } => {
            if let Some(path_env) = crate::command_env::path_env() {
                command.env("PATH", path_env);
            }
        }
    }
    // The evaluated credential is exactly the one the child uses.
    match target.config_dir() {
        Some(config_dir) => {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        None => {
            command.env_remove("CLAUDE_CONFIG_DIR");
        }
    }
    for key in STRIPPED_TOKEN_ENV {
        command.env_remove(key);
    }
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with(STRIPPED_TOKEN_ENV_PREFIX))
        {
            command.env_remove(key);
        }
    }
    Ok(command)
}

/// Hardened resolver: every candidate comes from an absolute search
/// directory, stays absolute even through an official-install symlink, and
/// must be executable.
fn resolve_claude_binary(home: &Path) -> Option<PathBuf> {
    crate::command_env::claude_search_dirs_for_gate(home)
        .into_iter()
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("claude"))
        .find(|candidate| crate::command_env::is_absolute_executable(candidate))
}

fn claude_path_env(home: &Path) -> Option<OsString> {
    std::env::join_paths(
        crate::command_env::claude_search_dirs_for_gate(home)
            .into_iter()
            .filter(|dir| dir.is_absolute()),
    )
    .ok()
}

fn effective_home() -> Option<PathBuf> {
    crate::agent_status::claude_spawn_user_identity().map(|(_, home)| home)
}

/// Whether Claude Code's CLI is installed, without spawning it.
pub(crate) fn claude_binary_present() -> bool {
    claude_binary_display_path().is_some()
}

/// Where the Claude Code CLI is installed, for display only. Never spawned.
pub(crate) fn claude_binary_display_path() -> Option<PathBuf> {
    resolve_claude_binary(&effective_home()?)
}

/// Whether a user-configured MCP server would run the Claude Code CLI itself
/// (`claude mcp serve`, a direct path into an install, or the npm package).
/// Such a server is never spawned: it would be a credential-using `claude`
/// outside this gate.
pub(crate) fn is_claude_cli_mcp_server(command: &str, args: &[String]) -> bool {
    let path = Path::new(command);
    let basename_is_claude = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "claude");
    let resolved = if path.is_absolute() {
        std::fs::canonicalize(path).ok()
    } else {
        crate::command_env::executable_path(command).and_then(|p| std::fs::canonicalize(p).ok())
    };
    let resolves_into_install = resolved.is_some_and(|resolved| {
        let text = resolved.to_string_lossy();
        text.contains("/claude/versions/") || text.contains("claude.app/Contents/MacOS/")
    });
    let npm_package = std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .any(|value| value.contains("@anthropic-ai/claude-code"));
    basename_is_claude || resolves_into_install || npm_package
}

/// Skip reason logged for a refused Claude-CLI MCP server.
pub(crate) const CLAUDE_CLI_MCP_SERVER_SKIPPED: &str = "claude_cli_mcp_server_skipped";

fn log_decision(
    target: &ClaudeSpawnTarget,
    class: ClaudeSpawnClass,
    decision: &Result<Command, ClaudeSpawnRefusal>,
    evaluated: Option<ClaudeGateCredential>,
    now: OffsetDateTime,
) {
    // Version probes run on every status pass; log only their refusals.
    if matches!(class, ClaudeSpawnClass::VersionProbe { .. }) && decision.is_ok() {
        return;
    }
    // The bucket comes from the one admission read; logging never re-reads.
    let bucket = evaluated.map_or("not_evaluated", |credential| expiry_bucket(credential, now));
    match decision {
        Ok(_) => eprintln!(
            "claude_spawn_gate decision=admitted class={} target={} expiry_bucket={bucket}",
            class.label(),
            target.log_label()
        ),
        Err(refusal) => eprintln!(
            "claude_spawn_gate decision=refused class={} reason={} target={} expiry_bucket={bucket}",
            class.label(),
            refusal.code(),
            target.log_label()
        ),
    }
}

/// Coarse seconds-to-expiry bucket for logs; never the deadline itself.
fn expiry_bucket(credential: ClaudeGateCredential, now: OffsetDateTime) -> &'static str {
    match credential {
        ClaudeGateCredential::Absent => "absent",
        ClaudeGateCredential::ReadFailed => "unreadable",
        ClaudeGateCredential::Present {
            has_refresh_token: false,
            ..
        } => "no_refresh_token",
        ClaudeGateCredential::Present {
            access_expires_at: None,
            ..
        } => "unknown",
        ClaudeGateCredential::Present {
            access_expires_at: Some(expires_at),
            ..
        } => {
            let remaining = (expires_at - now).whole_seconds();
            match remaining {
                i64::MIN..=0 => "expired",
                1..=900 => "lt_15m",
                901..=3_600 => "lt_1h",
                3_601..=28_800 => "lt_8h",
                _ => "gt_8h",
            }
        }
    }
}

/// Shared fixture for spawn-site tests in other modules: throwaway HOME and
/// support dirs, a fake `claude` that logs every spawn as
/// `<CLAUDE_CONFIG_DIR>|<args>`, and a fake `security` that serves only the
/// default login item this fixture writes. Never the real CLI or keychain.
#[cfg(test)]
pub(crate) mod test_support {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use time::{Duration as TimeDuration, OffsetDateTime};

    struct Guard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn guard(key: &'static str, value: &Path) -> Guard {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Guard { key, previous }
    }

    pub(crate) struct FakeClaudeEnv {
        pub(crate) root: PathBuf,
        pub(crate) bin: PathBuf,
        spawn_log: PathBuf,
        item: PathBuf,
        _guards: Vec<Guard>,
    }

    impl FakeClaudeEnv {
        pub(crate) fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ottto-fake-claude-{label}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            let bin = root.join("bin");
            let home = root.join("home");
            let support = root.join("support");
            for dir in [&bin, &home, &support] {
                std::fs::create_dir_all(dir).expect("fixture dir");
            }
            let spawn_log = root.join("claude-spawns.log");
            let item = root.join("default-item.json");
            let claude = bin.join("claude");
            std::fs::write(
                &claude,
                format!(
                    "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR|$*\" >> '{}'\necho '{{}}'\nexit 0\n",
                    spawn_log.display()
                ),
            )
            .expect("fake claude");
            let security = bin.join("security");
            std::fs::write(
                &security,
                format!(
                    "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = 'Claude Code-credentials' ] && [ -f '{item}' ]; then /bin/cat '{item}'; exit 0; fi\ndone\nexit 44\n",
                    item = item.display()
                ),
            )
            .expect("fake security");
            for executable in [&claude, &security] {
                let mut permissions = std::fs::metadata(executable).expect("meta").permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(executable, permissions).expect("chmod");
            }
            let guards = vec![
                guard("HOME", &home),
                guard("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home),
                guard("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
                guard("OTTTO_COMMAND_SEARCH_PATH", &bin),
            ];
            Self {
                root,
                bin,
                spawn_log,
                item,
                _guards: guards,
            }
        }

        /// The default login as Claude Code stores it, expiring `expires_in`
        /// from now.
        pub(crate) fn default_login_expires_in(&self, expires_in: TimeDuration) {
            let now = OffsetDateTime::now_utc();
            let item = serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": "fixture-access",
                    "refreshToken": "fixture-refresh",
                    "expiresAt": (now + expires_in).unix_timestamp() * 1_000,
                    "refreshTokenExpiresAt": (now + TimeDuration::days(25)).unix_timestamp() * 1_000,
                    "scopes": ["user:inference"],
                    "subscriptionType": "max"
                }
            });
            std::fs::write(&self.item, item.to_string()).expect("write item");
        }

        pub(crate) fn spawns(&self) -> Vec<String> {
            std::fs::read_to_string(&self.spawn_log)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    impl Drop for FakeClaudeEnv {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000 + seconds).expect("timestamp")
    }

    fn present(expires_in: TimeDuration) -> ClaudeGateCredential {
        ClaudeGateCredential::Present {
            has_refresh_token: true,
            access_expires_at: Some(at(0) + expires_in),
        }
    }

    fn evaluate(
        credential: ClaudeGateCredential,
        runtime_secs: u64,
    ) -> Result<(), ClaudeSpawnRefusal> {
        evaluate_credential_spawn(
            credential,
            None,
            false,
            at(0),
            Duration::from_secs(runtime_secs),
        )
    }

    #[test]
    fn credential_spawn_refused_inside_the_refresh_window_plus_margin_and_runtime() {
        for runtime in [25_u64, 45, 120] {
            for offset in [
                TimeDuration::minutes(16),
                TimeDuration::minutes(15),
                TimeDuration::minutes(5),
                TimeDuration::seconds(1),
                TimeDuration::seconds(-1),
                TimeDuration::hours(-8),
            ] {
                // T-16 min is still inside 5 + 10 min + 120 s for /context MCP
                // and 45 s smoke? 15 min + runtime > 16 min only for >60 s.
                let result = evaluate(present(offset), runtime);
                let required = 15 * 60 + runtime as i64;
                if offset.whole_seconds() < required {
                    assert_eq!(
                        result,
                        Err(ClaudeSpawnRefusal::TooCloseToExpiry),
                        "runtime {runtime}s offset {offset}"
                    );
                } else {
                    assert_eq!(result, Ok(()), "runtime {runtime}s offset {offset}");
                }
            }
            let required = TimeDuration::seconds(15 * 60 + runtime as i64);
            assert_eq!(
                evaluate(present(required - TimeDuration::seconds(1)), runtime),
                Err(ClaudeSpawnRefusal::TooCloseToExpiry),
                "one second short of the boundary for {runtime}s"
            );
            assert_eq!(
                evaluate(present(required), runtime),
                Ok(()),
                "exact boundary for {runtime}s"
            );
            assert_eq!(
                evaluate(present(TimeDuration::minutes(30)), runtime),
                Ok(()),
                "T-30 min admitted for {runtime}s"
            );
        }
        // T-16 min refuses the 120 s MCP /context run (needs 17 min).
        assert_eq!(
            evaluate(present(TimeDuration::minutes(16)), 120),
            Err(ClaudeSpawnRefusal::TooCloseToExpiry)
        );
    }

    #[test]
    fn credential_spawn_fails_closed_on_unreadable_or_anomalous_credentials() {
        assert_eq!(
            evaluate(ClaudeGateCredential::ReadFailed, 25),
            Err(ClaudeSpawnRefusal::CredentialReadFailed)
        );
        assert_eq!(
            evaluate(
                ClaudeGateCredential::Present {
                    has_refresh_token: true,
                    access_expires_at: None,
                },
                25
            ),
            Err(ClaudeSpawnRefusal::AccessExpiryUnknown)
        );
        assert_eq!(
            evaluate(
                present(TimeDuration::hours(24) + TimeDuration::seconds(1)),
                25
            ),
            Err(ClaudeSpawnRefusal::ImplausibleExpiry)
        );
        assert_eq!(evaluate(present(TimeDuration::hours(24)), 25), Ok(()));
        assert_eq!(
            evaluate_credential_spawn(
                present(TimeDuration::hours(2)),
                None,
                true,
                at(0),
                Duration::from_secs(25)
            ),
            Err(ClaudeSpawnRefusal::NetworkDisabled)
        );
    }

    #[test]
    fn credential_spawn_admits_absent_and_cleared_credentials() {
        assert_eq!(evaluate(ClaudeGateCredential::Absent, 45), Ok(()));
        // The CLI-cleared shape: no refresh token, expiresAt 0.
        assert_eq!(
            evaluate(
                ClaudeGateCredential::Present {
                    has_refresh_token: false,
                    access_expires_at: Some(OffsetDateTime::UNIX_EPOCH),
                },
                45
            ),
            Ok(())
        );
    }

    #[test]
    fn fresh_refresh_lock_refuses_and_stale_lock_admits() {
        let fresh = SystemTime::from(at(-10));
        let stale = SystemTime::from(at(-61));
        let future = SystemTime::from(at(120));
        let run = |lock| {
            evaluate_credential_spawn(
                present(TimeDuration::hours(2)),
                Some(lock),
                false,
                at(0),
                Duration::from_secs(25),
            )
        };
        assert_eq!(run(fresh), Err(ClaudeSpawnRefusal::RefreshInProgress));
        assert_eq!(run(future), Err(ClaudeSpawnRefusal::RefreshInProgress));
        assert_eq!(run(stale), Ok(()));
    }

    struct FakeEvidence {
        credential: ClaudeGateCredential,
        reads: Cell<usize>,
    }

    impl ClaudeSpawnEvidence for FakeEvidence {
        fn credential(&self, _slot: &ClaudeConfigDirSlot) -> ClaudeGateCredential {
            self.reads.set(self.reads.get() + 1);
            self.credential
        }
        fn refresh_lock_modified(&self, _config_dir: &Path) -> Option<SystemTime> {
            None
        }
        fn network_disabled(&self) -> bool {
            false
        }
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::now_utc()
        }
    }

    fn fresh_evidence() -> FakeEvidence {
        FakeEvidence {
            credential: ClaudeGateCredential::Present {
                has_refresh_token: true,
                access_expires_at: Some(OffsetDateTime::now_utc() + TimeDuration::hours(3)),
            },
            reads: Cell::new(0),
        }
    }

    /// Sets one variable for a test and restores it on drop. Setting `HOME`
    /// also pins the effective-user home the gate resolves `claude` under.
    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Vec<Self> {
            let mut guards = vec![Self::set_one(key, value.as_ref())];
            if key == "HOME" {
                guards.push(Self::set_one(
                    "OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS",
                    value.as_ref(),
                ));
            }
            guards
        }

        fn set_one(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct GateFixture {
        root: PathBuf,
        _guards: Vec<EnvGuard>,
    }

    impl GateFixture {
        fn new(label: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let root = std::env::temp_dir().join(format!(
                "ottto-claude-gate-{label}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            let bin = root.join("bin");
            let home = root.join("home");
            let support = root.join("support");
            for dir in [&bin, &home, &support] {
                std::fs::create_dir_all(dir).expect("fixture dir");
            }
            let claude = bin.join("claude");
            std::fs::write(&claude, "#!/bin/sh\nexit 0\n").expect("fake claude");
            let mut permissions = std::fs::metadata(&claude).expect("meta").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&claude, permissions).expect("chmod");
            let guards = [
                EnvGuard::set("HOME", home.as_os_str()),
                EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support.as_os_str()),
                EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str()),
                EnvGuard::set("CLAUDE_CODE_OAUTH_TOKEN", "fixture-ambient-token"),
                EnvGuard::set("CLAUDE_CONFIG_DIR", "/tmp/ambient-claude-config"),
            ]
            .into_iter()
            .flatten()
            .collect();
            Self {
                root,
                _guards: guards,
            }
        }
    }

    impl Drop for GateFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn env_value(command: &Command, key: &str) -> Option<Option<OsString>> {
        command
            .get_envs()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.map(|value| value.to_os_string()))
    }

    #[test]
    #[serial_test::serial]
    fn argv_outside_the_allowlist_is_refused_even_with_a_fresh_credential() {
        let _fixture = GateFixture::new("allowlist");
        let evidence = fresh_evidence();
        let credential_using = ClaudeSpawnClass::CredentialUsing {
            max_runtime: Duration::from_secs(25),
        };
        for argv in [
            &["auth", "status", "--json"][..],
            &["doctor"],
            &["setup-token"],
            &["mcp", "serve"],
            &["-p", "/usage"],
            &["-p", "/context", "--output-format", "json", "--verbose"],
        ] {
            assert_eq!(
                admit_with(
                    ClaudeSpawnTarget::Default,
                    credential_using,
                    argv,
                    &evidence
                )
                .err(),
                Some(ClaudeSpawnRefusal::ArgvNotAllowed),
                "{argv:?}"
            );
        }
        let version = ClaudeSpawnClass::VersionProbe {
            max_runtime: Duration::from_secs(3),
        };
        for argv in [&["--version", "--verbose"][..], &["--version", "x"], &[]] {
            assert_eq!(
                admit_with(ClaudeSpawnTarget::Default, version, argv, &evidence).err(),
                Some(ClaudeSpawnRefusal::ArgvNotAllowed),
                "{argv:?}"
            );
        }
        assert!(admit_with(
            ClaudeSpawnTarget::Default,
            version,
            &["--version"],
            &evidence
        )
        .is_ok());
        // A browser sign-in is only for an Ottto-managed auth root.
        assert_eq!(
            admit_with(
                ClaudeSpawnTarget::Default,
                ClaudeSpawnClass::BrowserLogin,
                &CLAUDE_BROWSER_LOGIN_ARGV,
                &evidence
            )
            .err(),
            Some(ClaudeSpawnRefusal::TargetNotAllowed)
        );
        assert_eq!(
            evidence.reads.get(),
            0,
            "refused argv never reads the credential"
        );
    }

    #[test]
    #[serial_test::serial]
    fn admitted_command_uses_exactly_the_target_login() {
        let fixture = GateFixture::new("env");
        let evidence = fresh_evidence();
        let class = ClaudeSpawnClass::CredentialUsing {
            max_runtime: Duration::from_secs(25),
        };
        let slot_dir = fixture.root.join("slot");
        let slot =
            ClaudeConfigDirSlot::registered(slot_dir.to_string_lossy().to_string()).expect("slot");
        let permit = admit_with(
            ClaudeSpawnTarget::Registered(slot),
            class,
            &CONTEXT_ARGV,
            &evidence,
        )
        .expect("fresh credential admitted");
        let command = permit.command_for_tests();
        assert_eq!(
            env_value(command, "CLAUDE_CONFIG_DIR"),
            Some(Some(slot_dir.into_os_string()))
        );
        assert_eq!(env_value(command, "CLAUDE_CODE_OAUTH_TOKEN"), Some(None));
        assert_eq!(env_value(command, "ANTHROPIC_AUTH_TOKEN"), Some(None));
        assert_eq!(evidence.reads.get(), 1, "one fresh read per admission");

        let default = admit_with(
            ClaudeSpawnTarget::Default,
            class,
            &[&CONTEXT_ARGV[..], &[STRICT_MCP_FLAG]].concat(),
            &evidence,
        )
        .expect("default admitted");
        let command = default.command_for_tests();
        assert_eq!(env_value(command, "CLAUDE_CONFIG_DIR"), Some(None));
        assert_eq!(env_value(command, "CLAUDE_CODE_OAUTH_TOKEN"), Some(None));
        assert_eq!(evidence.reads.get(), 2);
    }

    #[test]
    #[serial_test::serial]
    fn near_expiry_credential_refuses_admission_through_the_reader() {
        let _fixture = GateFixture::new("near-expiry");
        let evidence = FakeEvidence {
            credential: ClaudeGateCredential::Present {
                has_refresh_token: true,
                access_expires_at: Some(OffsetDateTime::now_utc() + TimeDuration::minutes(10)),
            },
            reads: Cell::new(0),
        };
        let refusal = admit_with(
            ClaudeSpawnTarget::Default,
            ClaudeSpawnClass::CredentialUsing {
                max_runtime: Duration::from_secs(45),
            },
            &claude_smoke_argv(),
            &evidence,
        )
        .expect_err("refused near expiry");
        assert_eq!(refusal, ClaudeSpawnRefusal::TooCloseToExpiry);
        assert!(refusal.waits_for_claude_refresh());
    }

    #[test]
    fn mcp_servers_that_run_the_claude_cli_are_recognised() {
        assert!(is_claude_cli_mcp_server(
            "claude",
            &["mcp".into(), "serve".into()]
        ));
        assert!(is_claude_cli_mcp_server("/opt/homebrew/bin/claude", &[]));
        assert!(is_claude_cli_mcp_server(
            "npx",
            &[
                "-y".into(),
                "@anthropic-ai/claude-code".into(),
                "mcp".into()
            ]
        ));
        assert!(!is_claude_cli_mcp_server(
            "npx",
            &[
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into()
            ]
        ));
    }

    #[test]
    fn executable_path_never_resolves_claude() {
        assert_eq!(crate::command_env::executable_path("claude"), None);
        assert_eq!(
            crate::command_env::executable_path("/usr/local/bin/claude"),
            None
        );
    }

    /// T1: every non-test source line that could build or name a `claude`
    /// spawn must live in this module.
    #[test]
    fn no_claude_spawn_outside_the_gate() {
        const FORBIDDEN: &[&str] = &[
            "claude_executable_path(",
            "executable_path(\"claude\")",
            "Command::new(\"claude\")",
            "program: \"claude\"",
            "\"auth\", \"status\"",
            "\"doctor\"]",
            "\"-p\", \"/context\"",
            "\"login\", \"--claudeai\"",
        ];
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .to_path_buf();
        let mut files = Vec::new();
        for krate in ["ottto-service", "ottto-core", "ottto-cli"] {
            collect_rust_files(&crates.join(krate).join("src"), &mut files);
        }
        assert!(
            files.iter().any(|file| file.ends_with("agent_status.rs")),
            "the scan must cover the service crate"
        );
        let mut violations = Vec::new();
        for file in &files {
            if file.ends_with("claude_spawn_gate.rs") {
                continue;
            }
            let body = std::fs::read_to_string(file).expect("read source");
            for (number, line) in non_test_lines(&body) {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                for pattern in FORBIDDEN {
                    if code.contains(pattern) {
                        violations.push(format!("{}:{number}: {pattern}", file.display()));
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "claude spawn outside the gate: {violations:#?}"
        );
    }

    #[test]
    fn source_scan_skips_only_cfg_test_items() {
        let body = "fn a() { Command::new(\"claude\"); }\n#[cfg(test)]\nfn b() {\n    let x = \"}\";\n    Command::new(\"claude\");\n}\nfn c() {}\n#[cfg(test)]\nmod tests {\n    fn d() { Command::new(\"claude\"); }\n}\n";
        let kept = non_test_lines(body)
            .into_iter()
            .map(|(_, line)| line)
            .collect::<Vec<_>>();
        assert_eq!(
            kept,
            vec!["fn a() { Command::new(\"claude\"); }", "fn c() {}"]
        );
    }

    fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Lines outside `#[cfg(test)]` items. A `#[cfg(test)]` attribute skips
    /// the next item: through its terminating `;` or its balanced braces.
    /// Braces inside string and char literals are ignored.
    fn non_test_lines(body: &str) -> Vec<(usize, &str)> {
        let lines = body.lines().collect::<Vec<_>>();
        let mut kept = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            if lines[index].trim() == "#[cfg(test)]" {
                index += 1;
                let mut depth = 0_i64;
                let mut opened = false;
                while index < lines.len() {
                    let line = lines[index];
                    index += 1;
                    let delta = brace_delta(line);
                    depth += delta.0;
                    opened |= delta.1;
                    if (opened && depth <= 0) || (!opened && line.trim_end().ends_with(';')) {
                        break;
                    }
                }
                continue;
            }
            kept.push((index + 1, lines[index]));
            index += 1;
        }
        kept
    }

    /// Net brace depth change of one line, and whether it opened any brace.
    fn brace_delta(line: &str) -> (i64, bool) {
        let mut depth = 0;
        let mut opened = false;
        let mut in_string = false;
        let mut chars = line.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '\\' if in_string => {
                    chars.next();
                }
                '"' => in_string = !in_string,
                '\'' if !in_string => {
                    // Skip a char literal such as '{' or '\''.
                    let mut lookahead = chars.clone();
                    let first = lookahead.next();
                    let second = lookahead.next();
                    if first == Some('\\') {
                        chars.next();
                        chars.next();
                        chars.next();
                    } else if second == Some('\'') {
                        chars.next();
                        chars.next();
                    }
                }
                '/' if !in_string && chars.peek() == Some(&'/') => break,
                '{' if !in_string => {
                    depth += 1;
                    opened = true;
                }
                '}' if !in_string => depth -= 1,
                _ => {}
            }
        }
        (depth, opened)
    }
}
