//! Quiet window for short Claude Code runs.
//!
//! Claude Code refreshes an OAuth login inside any command that starts within
//! five minutes of the access token's expiry (or after it). A short command
//! that exits, or is killed, before the rotated token is saved leaves the
//! refresh token spent, and Claude Code then signs the login out
//! (anthropics/claude-code#95822).
//!
//! The daemon's own short Claude runs (the `-p /context` footprint read and the
//! Verify smoke) therefore never start from 15 minutes before the access
//! token's expiry until the background refresher (`claude_refresher`) has
//! confirmed a new expiry, nor while the token is expired. `claude auth
//! status` and `claude doctor` are not run at all.

use ottto_core::ClaudeConfigDirSlot;
use std::path::Path;
use std::time::{Duration, SystemTime};
use time::{Duration as TimeDuration, OffsetDateTime};

/// No short Claude run starts this close to the access token's expiry: the
/// CLI's 5-minute refresh window, plus 10 minutes for start-up and the run.
pub(crate) const QUIET_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Another Claude Code process holding its refresh lock this recently is
/// refreshing now.
pub(crate) const REFRESH_LOCK_FRESHNESS: Duration = Duration::from_secs(60);
/// Claude Code's advisory refresh lock inside the config directory.
pub(crate) const REFRESH_LOCK_FILE: &str = ".oauth_refresh.lock";

/// Secret-free view of a stored credential.
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
    CredentialReadFailed,
    AccessExpiryUnknown,
    QuietWindow,
    RefreshInProgress,
}

impl ClaudeSpawnRefusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CredentialReadFailed => "credential_read_failed",
            Self::AccessExpiryUnknown => "access_expiry_unknown",
            Self::QuietWindow => "quiet_window",
            Self::RefreshInProgress => "refresh_in_progress",
        }
    }

    /// Claude Code (or the background refresher) must refresh this login
    /// first; a later attempt can succeed without user action.
    pub(crate) fn waits_for_claude_refresh(self) -> bool {
        matches!(self, Self::QuietWindow | Self::RefreshInProgress)
    }
}

/// The rule. Pure: every input is passed in, so it is tested with a fake
/// clock.
pub(crate) fn evaluate_short_run(
    credential: ClaudeGateCredential,
    refresh_lock_modified: Option<SystemTime>,
    now: OffsetDateTime,
) -> Result<(), ClaudeSpawnRefusal> {
    match credential {
        ClaudeGateCredential::ReadFailed => return Err(ClaudeSpawnRefusal::CredentialReadFailed),
        // No refresh token: no refresh is possible, so none can be lost.
        ClaudeGateCredential::Absent
        | ClaudeGateCredential::Present {
            has_refresh_token: false,
            ..
        } => return Ok(()),
        ClaudeGateCredential::Present {
            access_expires_at: None,
            ..
        } => return Err(ClaudeSpawnRefusal::AccessExpiryUnknown),
        ClaudeGateCredential::Present {
            access_expires_at: Some(expires_at),
            ..
        } => {
            if expires_at - now < TimeDuration::try_from(QUIET_WINDOW).expect("window") {
                return Err(ClaudeSpawnRefusal::QuietWindow);
            }
        }
    }
    if let Some(modified) = refresh_lock_modified {
        // A lock stamped in the future (clock jump) counts as fresh.
        if now - OffsetDateTime::from(modified)
            < TimeDuration::try_from(REFRESH_LOCK_FRESHNESS).expect("freshness")
        {
            return Err(ClaudeSpawnRefusal::RefreshInProgress);
        }
    }
    Ok(())
}

/// The single gate every short Claude run asks immediately before it starts:
/// a fresh read of that login's stored credential (keychain, then the
/// credentials file) and of Claude Code's refresh lock.
pub(crate) fn check_short_claude_run(slot: &ClaudeConfigDirSlot) -> Result<(), ClaudeSpawnRefusal> {
    let credential = crate::agent_status::read_claude_spawn_gate_credential(slot);
    let lock_modified = slot
        .credentials_path(&crate::agent_status::home_dir())
        .parent()
        .and_then(refresh_lock_modified);
    let decision = evaluate_short_run(credential, lock_modified, OffsetDateTime::now_utc());
    if let Err(refusal) = decision {
        eprintln!(
            "claude_short_run decision=refused reason={} target={}",
            refusal.code(),
            if slot.config_dir().is_some() {
                "slot"
            } else {
                "default"
            }
        );
    }
    decision
}

/// Modification time of Claude Code's refresh lock. Read-only: the lock
/// belongs to Claude Code and is never created or removed here.
pub(crate) fn refresh_lock_modified(config_dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(config_dir.join(REFRESH_LOCK_FILE))
        .and_then(|metadata| metadata.modified())
        .ok()
}

/// A fresh, empty, owner-only working directory for a Claude run that must not
/// pick up any project settings. Removed on drop.
pub(crate) struct EmptyWorkingDir {
    path: std::path::PathBuf,
}

impl EmptyWorkingDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EmptyWorkingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn empty_working_dir() -> std::io::Result<EmptyWorkingDir> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "ottto-claude-empty-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(EmptyWorkingDir { path })
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

        /// Every logged spawn except `--version` probes, which a detached
        /// status refresh from another test may run under this fixture's
        /// search path (they never touch a login).
        pub(crate) fn spawns(&self) -> Vec<String> {
            std::fs::read_to_string(&self.spawn_log)
                .unwrap_or_default()
                .lines()
                .filter(|line| *line != "|--version")
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
    use std::path::PathBuf;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000 + seconds).expect("timestamp")
    }

    fn present(expires_in: TimeDuration) -> ClaudeGateCredential {
        ClaudeGateCredential::Present {
            has_refresh_token: true,
            access_expires_at: Some(at(0) + expires_in),
        }
    }

    #[test]
    fn short_runs_wait_from_15_minutes_before_expiry_until_a_new_expiry() {
        for offset in [
            TimeDuration::minutes(15) - TimeDuration::seconds(1),
            TimeDuration::minutes(5),
            TimeDuration::seconds(1),
            -TimeDuration::seconds(1),
            -TimeDuration::hours(8),
        ] {
            assert_eq!(
                evaluate_short_run(present(offset), None, at(0)),
                Err(ClaudeSpawnRefusal::QuietWindow),
                "{offset}"
            );
        }
        assert_eq!(
            evaluate_short_run(present(TimeDuration::minutes(15)), None, at(0)),
            Ok(())
        );
        // After the refresher confirmed a new expiry, runs resume.
        assert_eq!(
            evaluate_short_run(present(TimeDuration::hours(8)), None, at(0)),
            Ok(())
        );
    }

    #[test]
    fn short_runs_fail_closed_and_respect_a_running_refresh() {
        assert_eq!(
            evaluate_short_run(ClaudeGateCredential::ReadFailed, None, at(0)),
            Err(ClaudeSpawnRefusal::CredentialReadFailed)
        );
        assert_eq!(
            evaluate_short_run(
                ClaudeGateCredential::Present {
                    has_refresh_token: true,
                    access_expires_at: None,
                },
                None,
                at(0)
            ),
            Err(ClaudeSpawnRefusal::AccessExpiryUnknown)
        );
        assert_eq!(
            evaluate_short_run(ClaudeGateCredential::Absent, None, at(0)),
            Ok(())
        );
        assert_eq!(
            evaluate_short_run(
                present(TimeDuration::hours(2)),
                Some(SystemTime::from(at(-10))),
                at(0)
            ),
            Err(ClaudeSpawnRefusal::RefreshInProgress)
        );
        assert_eq!(
            evaluate_short_run(
                present(TimeDuration::hours(2)),
                Some(SystemTime::from(at(-61))),
                at(0)
            ),
            Ok(())
        );
    }

    /// `claude auth status` and `claude doctor` are never spawned again.
    #[test]
    fn no_auth_status_or_doctor_spawn_in_daemon_code() {
        const FORBIDDEN: &[&str] = &["\"auth\", \"status\"", "\"doctor\"]"];
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .to_path_buf();
        let mut files = Vec::new();
        for krate in ["ottto-service", "ottto-core", "ottto-cli"] {
            collect_rust_files(&crates.join(krate).join("src"), &mut files);
        }
        let mut violations = Vec::new();
        for file in &files {
            let body = std::fs::read_to_string(file).expect("read source");
            let production = body.split("#[cfg(test)]\nmod tests").next().unwrap_or("");
            for (number, line) in production.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("const FORBIDDEN") {
                    continue;
                }
                for pattern in FORBIDDEN {
                    if code.contains(pattern) {
                        violations.push(format!("{}:{}: {pattern}", file.display(), number + 1));
                    }
                }
            }
        }
        assert!(violations.is_empty(), "{violations:#?}");
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
}
