//! Single-use, account-bound terminal launches. Paths and secrets stay local;
//! no launcher contains a folder, credential or provider command. The daemon
//! never runs doctor/auth/login as part of a launch.
mod binding;
mod preflight;
mod recent;
#[cfg(test)]
mod tests;

use binding::Binding;
use ottto_core::{
    generate_control_token,
    session_launch::{launch_user, quote_launch_executable},
};
use ottto_protocol::{
    SecretString, SessionLaunchBlockReasonV1 as Reason, SessionLaunchBlockV1 as Block,
    SessionLaunchConsumeResultV1, SessionLaunchExecPlanV1, SessionLaunchFolderV1,
    SessionLaunchOutcomeV1 as Outcome, SessionLaunchPrepareResultV1,
    SessionLaunchProviderV1 as Provider, SessionLaunchStateV1 as State, SessionLaunchStatusV1,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(120);
const MAX_PENDING: usize = 16;
// Deliberate evaluator compatibility ranges; review before expanding them.
const CLAUDE_CLI_MAJOR: u64 = 2; // >=2.0.0, <3.0.0
const CODEX_CLI_MAJOR: u64 = 0;
const CODEX_CLI_MIN_MINOR: u64 = 150; // >=0.150.0, <1.0.0

pub(super) fn block(reason: Reason) -> Block {
    Block {
        reason,
        ..Block::default()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ProgramIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    modified: Option<std::time::SystemTime>,
}
fn program_identity(path: &Path) -> Option<ProgramIdentity> {
    let metadata = fs::metadata(path).ok()?;
    (metadata.is_file() && metadata.mode() & 0o111 != 0).then(|| ProgramIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

struct Entry {
    binding: Binding,
    cwd: PathBuf,
    dev: u64,
    ino: u64,
    program: PathBuf,
    program_identity: ProgramIdentity,
    cli_version: String,
    path_env: String,
    secret: [u8; 32],
    created: Instant,
    created_wall: std::time::SystemTime,
    state: State,
    block: Option<Block>,
    attempt: Option<SecretString>,
    launcher: PathBuf,
    generation: (u64, Option<crate::account_nicknames::Generation>),
}

#[derive(Default)]
pub(crate) struct Registry {
    entries: BTreeMap<String, Entry>,
    recent: recent::Cache,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLaunchRegistry")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Registry {
    pub(crate) fn invalidate(&mut self) {
        for entry in self.entries.values_mut() {
            if entry.state == State::Pending {
                entry.state = State::Blocked;
                entry.block = Some(block(Reason::LaunchCancelled));
                let _ = fs::remove_file(&entry.launcher);
            }
        }
        self.recent = recent::Cache::default();
    }

    fn sweep(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            if entry.state == State::Pending && expired(entry, now) {
                entry.state = State::Expired;
                entry.block = Some(block(Reason::LaunchExpired));
                let _ = fs::remove_file(&entry.launcher);
            }
        }
        self.entries
            .retain(|_, entry| now.duration_since(entry.created) < TTL * 2);
    }

    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(crate) fn prepare(
        &mut self,
        provider: Provider,
        slot_id: &str,
        account: &str,
        organization: &str,
        folder: SessionLaunchFolderV1,
        ottto: Option<PathBuf>,
        support: &Path,
    ) -> SessionLaunchPrepareResultV1 {
        let result = self.prepare_inner(
            provider,
            slot_id,
            account,
            organization,
            folder,
            ottto,
            support,
        );
        result.unwrap_or_else(|error| SessionLaunchPrepareResultV1 {
            outcome: Some(Outcome::Blocked),
            block: Some(error),
            ..Default::default()
        })
    }

    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    fn prepare_inner(
        &mut self,
        provider: Provider,
        slot_id: &str,
        account: &str,
        organization: &str,
        folder: SessionLaunchFolderV1,
        ottto: Option<PathBuf>,
        support: &Path,
    ) -> Result<SessionLaunchPrepareResultV1, Block> {
        let user = launch_user().ok_or_else(|| block(Reason::SlotNotVerified))?;
        self.prepare_for_user(
            provider,
            slot_id,
            account,
            organization,
            folder,
            ottto,
            support,
            user,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
    fn prepare_for_user(
        &mut self,
        provider: Provider,
        slot_id: &str,
        account: &str,
        organization: &str,
        folder: SessionLaunchFolderV1,
        ottto: Option<PathBuf>,
        support: &Path,
        user: ottto_core::session_launch::LaunchUser,
    ) -> Result<SessionLaunchPrepareResultV1, Block> {
        let now = Instant::now();
        self.sweep(now);
        // Retrying a slot invalidates its older handoffs, including ones the
        // app may still have open in another terminal window.
        for entry in self.entries.values_mut().filter(|entry| {
            entry.binding.provider == provider
                && entry.binding.slot_id == slot_id
                && entry.state == State::Pending
        }) {
            entry.state = State::Blocked;
            entry.block = Some(block(Reason::LaunchCancelled));
            let _ = fs::remove_file(&entry.launcher);
        }
        let generation = crate::account_nicknames::launch_generation();
        if crate::control::identity_mutation_in_progress() {
            return Err(block(Reason::AccountMismatch));
        }
        let binding = binding::resolve(provider, slot_id, account, organization, user)?;
        let selected = match (folder.path, folder.recent_id) {
            (Some(path), None) => PathBuf::from(path),
            (None, Some(id)) => self
                .recent
                .resolve(&id)
                .ok_or_else(|| block(Reason::FolderInvalid))?,
            _ => return Err(block(Reason::FolderInvalid)),
        };
        let ValidatedFolder {
            path: cwd,
            dev,
            ino,
        } = validate_folder(&selected, &binding.user.home, support)?;
        preflight::evaluate(&binding, &cwd)?;
        let program = crate::command_env::interactive_cli_path(
            match provider {
                Provider::ClaudeCode => "claude",
                Provider::Codex => "codex",
                Provider::Unknown => return Err(block(Reason::Unknown)),
            },
            &binding.user.home,
        )
        .ok_or_else(|| block(Reason::CliNotFound))?;
        let probe_path = crate::command_env::interactive_probe_path(&binding.user.home, &program)
            .and_then(|path| path.into_string().ok())
            .ok_or_else(|| block(Reason::CliVersionUnsupported))?;
        let program = program
            .canonicalize()
            .map_err(|_| block(Reason::CliNotFound))?;
        let program_identity =
            program_identity(&program).ok_or_else(|| block(Reason::CliNotFound))?;
        let cli_version = supported_version(
            &program,
            &binding,
            &cwd,
            Some(std::ffi::OsStr::new(&probe_path)),
        )?;
        if self::program_identity(&program).as_ref() != Some(&program_identity) {
            return Err(block(Reason::CliChanged));
        }
        let ottto = ottto
            .filter(|path| executable(path))
            .ok_or_else(|| block(Reason::CliNotFound))?;
        if self
            .entries
            .values()
            .filter(|entry| entry.state == State::Pending)
            .count()
            >= MAX_PENDING
        {
            return Err(block(Reason::LaunchLimit));
        }
        // Bound terminal states as well as pending ones; retain recent statuses.
        while self.entries.len() >= 64 {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.state != State::Pending)
                .min_by_key(|(_, entry)| entry.created)
                .map(|(id, _)| id.clone());
            if let Some(id) = oldest {
                if let Some(entry) = self.entries.remove(&id) {
                    let _ = fs::remove_file(entry.launcher);
                }
            } else {
                break;
            }
        }
        if generation != crate::account_nicknames::launch_generation() {
            return Err(block(Reason::AccountMismatch));
        }
        let dir = launcher_directory(support, true)?;
        let secret = generate_control_token().map_err(|_| block(Reason::LauncherDirUnsafe))?;
        let (id, launcher) = write_launcher(&dir, support, &ottto, &secret)?;
        let expires =
            time::OffsetDateTime::now_utc() + time::Duration::seconds(TTL.as_secs() as i64);
        let response = SessionLaunchPrepareResultV1 {
            outcome: Some(Outcome::Ready),
            launch_id: Some(id.clone()),
            launcher_path: Some(launcher.to_string_lossy().into_owned()),
            expires_at: expires
                .format(&time::format_description::well_known::Rfc3339)
                .ok(),
            folder_label: cwd
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            cli_version: Some(cli_version.clone()),
            block: None,
        };
        self.entries.insert(
            id,
            Entry {
                binding,
                cwd,
                dev,
                ino,
                program,
                program_identity,
                cli_version,
                path_env: probe_path,
                secret: Sha256::digest(secret.as_bytes()).into(),
                created: Instant::now(),
                created_wall: std::time::SystemTime::now(),
                state: State::Pending,
                block: None,
                attempt: None,
                launcher,
                generation,
            },
        );
        Ok(response)
    }

    pub(crate) fn consume(&mut self, id: &str, secret: &str) -> SessionLaunchConsumeResultV1 {
        self.sweep(Instant::now());
        let Some(entry) = self.entries.get_mut(id) else {
            return consume_block(block(Reason::LaunchUnknown));
        };
        if entry.state != State::Pending {
            return consume_block(block(if entry.state == State::Expired {
                Reason::LaunchExpired
            } else if entry
                .block
                .as_ref()
                .is_some_and(|error| error.reason == Reason::LaunchCancelled)
            {
                Reason::LaunchCancelled
            } else {
                Reason::LaunchAlreadyUsed
            }));
        }
        // Atomic single-use claim before *any* check. A failed first attempt
        // cannot be retried with the same secret.
        entry.state = State::Blocked;
        let _ = fs::remove_file(&entry.launcher);
        let result = check_entry(entry, secret);
        match result {
            Ok(plan) => {
                let Ok(attempt) = generate_control_token() else {
                    entry.block = Some(block(Reason::ExecFailed));
                    return consume_block(block(Reason::ExecFailed));
                };
                let attempt = SecretString::new(attempt);
                entry.attempt = Some(attempt.clone());
                entry.state = State::Starting;
                SessionLaunchConsumeResultV1 {
                    state: Some(State::Starting),
                    plan: Some(plan),
                    attempt_id: Some(attempt),
                    block: None,
                }
            }
            Err(error) => {
                entry.block = Some(error.clone());
                consume_block(error)
            }
        }
    }

    pub(crate) fn status(&mut self, id: &str, cancel: bool) -> SessionLaunchStatusV1 {
        self.sweep(Instant::now());
        let Some(entry) = self.entries.get_mut(id) else {
            return SessionLaunchStatusV1 {
                state: Some(State::Unknown),
                block: Some(block(Reason::LaunchUnknown)),
            };
        };
        if cancel && entry.state == State::Pending {
            entry.state = State::Blocked;
            entry.block = Some(block(Reason::LaunchCancelled));
            let _ = fs::remove_file(&entry.launcher);
        }
        SessionLaunchStatusV1 {
            state: Some(entry.state),
            block: entry.block.clone(),
        }
    }

    pub(crate) fn report(
        &mut self,
        id: &str,
        attempt: &str,
        reason: Reason,
    ) -> SessionLaunchStatusV1 {
        if let Some(entry) = self.entries.get_mut(id) {
            if entry.state == State::Starting
                && entry.attempt.as_ref().is_some_and(|value| {
                    constant_eq(value.expose_secret().as_bytes(), attempt.as_bytes())
                })
                && matches!(
                    reason,
                    Reason::ExecFailed | Reason::ChdirFailed | Reason::FolderChanged
                )
            {
                entry.state = State::Blocked;
                entry.block = Some(block(reason));
                entry.attempt = None;
            }
        }
        self.status(id, false)
    }

    pub(crate) fn recent(
        &mut self,
        provider: Option<Provider>,
        slot_id: Option<&str>,
        limit: usize,
        support: &Path,
    ) -> ottto_protocol::SessionLaunchRecentFoldersV1 {
        self.recent.get(provider, slot_id, limit, support)
    }
}

/// A display nickname may be edited only for a currently verified local
/// login. Remembered/historical rows never become write authority.
pub(crate) fn nickname_target_is_current(pair: &ottto_protocol::AccountNicknamePairV1) -> bool {
    let Some(user) = launch_user() else {
        return false;
    };
    nickname_target_is_current_for_user(pair, user)
}

fn nickname_target_is_current_for_user(
    pair: &ottto_protocol::AccountNicknamePairV1,
    user: ottto_core::session_launch::LaunchUser,
) -> bool {
    let (Some(account), Some(org)) = (
        pair.account_identifier_hash.as_deref(),
        pair.organization_identifier_hash.as_deref(),
    ) else {
        return false;
    };
    let ids: Vec<String> = match pair.source {
        Provider::ClaudeCode => {
            match ottto_core::FileClaudeConfigSlotSettingsStore::default().load() {
                Ok(status) => std::iter::once(status.default_slot)
                    .chain(status.managed_slots)
                    .chain(status.external_slots)
                    .map(|slot| slot.slot_id)
                    .collect(),
                Err(_) => return false,
            }
        }
        Provider::Codex => match ottto_core::FileCodexAccountSlotSettingsStore::default()
            .load_for_session_launch()
        {
            Ok(status) => std::iter::once(status.default_slot)
                .chain(status.managed_slots)
                .map(|slot| slot.slot_id)
                .collect(),
            Err(_) => return false,
        },
        Provider::Unknown => return false,
    };
    ids.iter()
        .take(10)
        .any(|id| binding::resolve(pair.source, id, account, org, user.clone()).is_ok())
}

fn expired(entry: &Entry, now: Instant) -> bool {
    now.duration_since(entry.created) >= TTL
        || entry.created_wall.elapsed().is_ok_and(|age| age >= TTL)
}

fn consume_block(error: Block) -> SessionLaunchConsumeResultV1 {
    SessionLaunchConsumeResultV1 {
        state: Some(if error.reason == Reason::LaunchExpired {
            State::Expired
        } else {
            State::Blocked
        }),
        block: Some(error),
        ..Default::default()
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |result, (a, b)| result | (a ^ b)) == 0
}

fn check_entry(entry: &Entry, secret: &str) -> Result<SessionLaunchExecPlanV1, Block> {
    if !constant_eq(&entry.secret, &Sha256::digest(secret.as_bytes())) {
        return Err(block(Reason::LaunchUnknown));
    }
    if expired(entry, Instant::now()) {
        return Err(block(Reason::LaunchExpired));
    }
    if entry.generation != crate::account_nicknames::launch_generation()
        || crate::control::identity_mutation_in_progress()
    {
        return Err(block(Reason::AccountMismatch));
    }
    binding::recheck(&entry.binding)?;
    let metadata = fs::metadata(&entry.cwd).map_err(|_| block(Reason::FolderChanged))?;
    if metadata.dev() != entry.dev || metadata.ino() != entry.ino {
        return Err(block(Reason::FolderChanged));
    }
    preflight::evaluate(&entry.binding, &entry.cwd)?;
    if !executable(&entry.program) {
        return Err(block(Reason::CliChanged));
    }
    if program_identity(&entry.program).as_ref() != Some(&entry.program_identity) {
        return Err(block(Reason::CliChanged));
    }
    if parse_version(entry.cli_version.as_bytes(), entry.binding.provider).is_none() {
        return Err(block(Reason::CliVersionUnsupported));
    }
    let (env_unset, mut env_set) = environment(&entry.binding);
    env_set.insert("PATH".into(), entry.path_env.clone());
    Ok(SessionLaunchExecPlanV1 {
        program: Some(entry.program.to_string_lossy().into_owned()),
        argv: Some(Vec::new()),
        cwd: Some(entry.cwd.to_string_lossy().into_owned()),
        cwd_dev: Some(entry.dev),
        cwd_ino: Some(entry.ino),
        env_unset: Some(env_unset),
        env_set: Some(env_set),
    })
}

fn environment(binding: &Binding) -> (Vec<String>, BTreeMap<String, String>) {
    let unset = match binding.provider {
        Provider::ClaudeCode => preflight::CLAUDE_UNSET,
        _ => preflight::CODEX_UNSET,
    };
    let mut set = BTreeMap::from([
        (
            "HOME".into(),
            binding.user.home.to_string_lossy().into_owned(),
        ),
        ("USER".into(), binding.user.name.clone()),
        ("LOGNAME".into(), binding.user.name.clone()),
    ]);
    match &binding.claude_slot {
        Some(slot) => {
            if let Some(raw) = slot.config_dir() {
                set.insert("CLAUDE_CONFIG_DIR".into(), raw.into());
            }
        }
        None => {
            let root = binding.root.to_string_lossy().into_owned();
            set.insert("CODEX_HOME".into(), root.clone());
            set.insert("CODEX_SQLITE_HOME".into(), root);
        }
    }
    (unset.iter().map(|key| (*key).into()).collect(), set)
}

fn executable(path: &Path) -> bool {
    path.is_absolute()
        && fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
}

fn supported_version(
    program: &Path,
    binding: &Binding,
    cwd: &Path,
    path: Option<&std::ffi::OsStr>,
) -> Result<String, Block> {
    let (unset, set) = environment(binding);
    let mut command = Command::new(program);
    command
        .arg("--version")
        .current_dir(cwd)
        .env("PWD", cwd)
        .envs(set)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in unset {
        command.env_remove(key);
    }
    // Reapply selectors after scrubbing, exactly as the terminal executor does.
    command.envs(environment(binding).1);
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command
        .spawn()
        .map_err(|_| block(Reason::CliVersionUnsupported))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(block(Reason::CliVersionUnsupported));
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(4097).read_to_end(&mut bytes);
        let _ = sender.send((result.is_ok(), bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                unsafe {
                    libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(block(Reason::CliVersionUnsupported));
            }
        }
    };
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let (read, bytes) = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| block(Reason::CliVersionUnsupported))?;
    if !status.success() || !read || bytes.len() > 4096 {
        return Err(block(Reason::CliVersionUnsupported));
    }
    parse_version(&bytes, binding.provider).ok_or_else(|| block(Reason::CliVersionUnsupported))
}

fn parse_version(bytes: &[u8], provider: Provider) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    let version = match provider {
        Provider::ClaudeCode => text.strip_suffix(" (Claude Code)").unwrap_or(text),
        Provider::Codex => text
            .strip_prefix("codex-cli ")
            .or_else(|| text.strip_prefix("codex "))
            .unwrap_or(text),
        Provider::Unknown => return None,
    };
    let core = version.split(['-', '+']).next()?;
    let components = core.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let major = components[0].parse::<u64>().ok()?;
    if !version.contains('.')
        || version.chars().any(char::is_control)
        || match provider {
            Provider::ClaudeCode => major != CLAUDE_CLI_MAJOR,
            Provider::Codex => {
                major != CODEX_CLI_MAJOR || components[1].parse::<u64>().ok()? < CODEX_CLI_MIN_MINOR
            }
            Provider::Unknown => true,
        }
    {
        return None;
    }
    Some(version.into())
}

struct ValidatedFolder {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

fn validate_folder(path: &Path, home: &Path, support: &Path) -> Result<ValidatedFolder, Block> {
    if !path.is_absolute()
        || path
            .to_str()
            .map_or(true, |path| path.chars().any(char::is_control))
    {
        return Err(block(Reason::FolderInvalid));
    }
    let path = path
        .canonicalize()
        .map_err(|_| block(Reason::FolderMissing))?;
    if path
        .to_str()
        .map_or(true, |path| path.chars().any(char::is_control))
    {
        return Err(block(Reason::FolderInvalid));
    }
    if !path.is_dir() {
        return Err(block(Reason::FolderNotDirectory));
    }
    let home = home.canonicalize().unwrap_or_else(|_| home.into());
    let support = support.canonicalize().unwrap_or_else(|_| support.into());
    if path == Path::new("/") || path == home || path.starts_with(support) {
        return Err(block(Reason::FolderInvalid));
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| block(Reason::FolderInvalid))?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(block(Reason::FolderNotLocal));
    }
    let stat = unsafe { stat.assume_init() };
    #[cfg(target_os = "macos")]
    let local = stat.f_flags & libc::MNT_LOCAL as u32 != 0;
    #[cfg(target_os = "linux")]
    let local = !matches!(
        stat.f_type as u64,
        0x6969 | 0xff534d42 | 0xfe534d42 | 0x65735546 | 0x517b
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let local = false;
    if !local {
        return Err(block(Reason::FolderNotLocal));
    }
    let metadata = directory
        .metadata()
        .map_err(|_| block(Reason::FolderMissing))?;
    Ok(ValidatedFolder {
        path,
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn launcher_directory(support: &Path, create: bool) -> Result<File, Block> {
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(support)
        .map_err(|_| block(Reason::LauncherDirUnsafe))?;
    let meta = parent
        .metadata()
        .map_err(|_| block(Reason::LauncherDirUnsafe))?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err(block(Reason::LauncherDirUnsafe));
    }
    let name = c"session-launch";
    if create {
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(block(Reason::LauncherDirUnsafe));
        }
    }
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(block(Reason::LauncherDirUnsafe));
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory
        .metadata()
        .map_err(|_| block(Reason::LauncherDirUnsafe))?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(block(Reason::LauncherDirUnsafe));
    }
    Ok(directory)
}

fn write_launcher(
    dir: &File,
    support: &Path,
    ottto: &Path,
    secret: &str,
) -> Result<(String, PathBuf), Block> {
    let quoted = ottto
        .to_str()
        .and_then(quote_launch_executable)
        .ok_or_else(|| block(Reason::CliNotFound))?;
    for _ in 0..8 {
        let id = format!(
            "lch_{}",
            generate_control_token().map_err(|_| block(Reason::LauncherDirUnsafe))?
        );
        let filename = format!("ottto-{id}.command");
        let name = std::ffi::CString::new(filename.as_str())
            .map_err(|_| block(Reason::LauncherDirUnsafe))?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CLOEXEC,
                0o700,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(block(Reason::LauncherDirUnsafe));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let text = format!(
            "#!/bin/sh\nrm -f -- \"$0\"\nexec {quoted} launch-check --exec {id} {secret}\n"
        );
        if file
            .set_permissions(fs::Permissions::from_mode(0o700))
            .and_then(|_| file.write_all(text.as_bytes()))
            .and_then(|_| file.sync_all())
            .is_err()
        {
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
            }
            return Err(block(Reason::LauncherDirUnsafe));
        }
        return Ok((id, support.join("session-launch").join(filename)));
    }
    Err(block(Reason::LauncherDirUnsafe))
}

/// Called only after the daemon's state-directory lock is held, before any
/// local control listener. Restart invalidates every old in-memory secret.
pub fn recover_at_startup() {
    let support = ottto_core::default_support_dir();
    let Ok(directory) = launcher_directory(&support, false) else {
        return;
    };
    let Ok(entries) = fs::read_dir(support.join("session-launch")) else {
        return;
    };
    for entry in entries.take(256).flatten() {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("ottto-lch_") && name.ends_with(".command"))
        {
            if let Ok(name) = std::ffi::CString::new(name.as_encoded_bytes()) {
                unsafe {
                    libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
                }
            }
        }
    }
}
