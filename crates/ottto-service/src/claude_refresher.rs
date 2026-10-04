//! "Keep my Claude accounts signed in": one waiting background refresh per
//! Claude login (each registered slot and the default login).
//!
//! Claude Code refreshes an OAuth login only inside its own 5-minute window
//! before the access token expires (or after it). A refresh that is cut short
//! before the rotated token is saved signs the login out
//! (anthropics/claude-code#95822). So the refresher:
//!
//! - starts when the access token is within 5 minutes of expiry, or already
//!   expired (for example on the first pass after the Mac wakes);
//! - runs exactly one `claude -p /usage --no-session-persistence
//!   --strict-mcp-config` per login, in an empty working directory, in its own
//!   process group (a daemon restart does not stop it), with the Mac kept
//!   awake while it runs;
//! - is never killed: after 120 seconds it is reported as still running and
//!   left to finish;
//! - leaves concurrency to Claude Code's own `.oauth_refresh.lock`;
//! - afterwards proves success only by a new, later `expiresAt`. If the
//!   login was blanked, or the expiry did not advance twice, that login is
//!   not refreshed again (it asks to sign in again) until a new credential
//!   appears. A first failure that leaves the login intact (refresh token
//!   present, not blanked; typically a refresh right after a wake, before the
//!   network is back) gets exactly one retry, at least 5 minutes later;
//! - runs only for logins whose `/usage` actually refreshes: `user:profile`
//!   scope, not usage-billed, no other credential taking precedence
//!   (`agent_status::claude_refresher_skip_reason`).
//!
//! `-p /usage` is a local command (`supportsNonInteractive`) that reads plan
//! usage with the account's token, so it uses no model quota; Claude Code
//! refreshes the token first because it is inside its refresh window.
//! `--no-session-persistence` saves no session; `--strict-mcp-config` starts
//! no MCP server. All three are verified in Claude Code 2.1.288's source.

use crate::agent_status::{ClaudeLiveLogin, ClaudeLocalLoginState};
use ottto_core::{default_support_dir, write_owner_only_file_atomic, ClaudeConfigDirSlot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

/// Claude Code's own refresh window: it refreshes when `now + 5 min >=
/// expiresAt`. Starting earlier would not refresh.
pub(crate) const REFRESH_TRIGGER: Duration = Duration::from_secs(5 * 60);
/// After this the refresher is reported as still running and left alone.
pub(crate) const REFRESH_REPORT_AFTER: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// The single retry after an intact failure waits at least this long.
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
pub(crate) const REFRESH_ARGV: [&str; 4] = [
    "-p",
    "/usage",
    "--no-session-persistence",
    "--strict-mcp-config",
];
const STATE_FILE: &str = "claude-login-refresh-state.json";

static RUNNING: OnceLock<Mutex<BTreeMap<String, ()>>> = OnceLock::new();

fn running() -> &'static Mutex<BTreeMap<String, ()>> {
    RUNNING.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// What the refresher does for one login on this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshDecision {
    /// No refresh needed now (not near expiry, or not a refreshable login).
    NotNeeded,
    /// A refresh was started on this pass.
    Started,
    /// A refresh for this login is still running.
    Running,
    /// "Keep my Claude accounts signed in" is off, or usage reads are off.
    Disabled,
    /// The first refresh of this exact credential failed but left it
    /// intact; its one retry starts on a later pass.
    RetryWaiting,
    /// The refresh of this exact credential signed it out, or failed twice:
    /// wait for the user to sign in again.
    FailedWaitingForSignIn,
}

/// The outcome of one finished refresher run, judged from the stored
/// credential alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    Refreshed,
    ExpiryUnchanged,
    SignedOut,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RefreshState {
    #[serde(default)]
    failed: BTreeMap<String, FailedRefresh>,
}

/// A failed refresh of one exact credential (identified by its access
/// deadline). Holds no token, account or path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FailedRefresh {
    access_expires_at: String,
    failed_at: String,
    outcome: String,
    /// The first failure left the login intact: one retry is allowed.
    #[serde(default)]
    retry_allowed: bool,
}

/// Pure decision: should this login be refreshed now?
pub(crate) fn decide_refresh(
    live: &ClaudeLiveLogin,
    enabled: bool,
    already_running: bool,
    failed: Option<&FailedRefresh>,
    now: OffsetDateTime,
) -> RefreshDecision {
    if !matches!(
        live.state,
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending
    ) {
        return RefreshDecision::NotNeeded;
    }
    let Some(expires_at) = live
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.access_expires_at.as_deref())
    else {
        return RefreshDecision::NotNeeded;
    };
    if let Some(failed) = failed.filter(|failed| failed.access_expires_at == expires_at) {
        if !failed.retry_allowed {
            return RefreshDecision::FailedWaitingForSignIn;
        }
        let retry_at = OffsetDateTime::parse(&failed.failed_at, &Rfc3339)
            .map(|at| at + TimeDuration::try_from(RETRY_AFTER).expect("retry"));
        if !already_running && retry_at.map_or(true, |retry_at| now < retry_at) {
            return RefreshDecision::RetryWaiting;
        }
    }
    let Ok(expiry) = OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return RefreshDecision::NotNeeded;
    };
    if expiry - now > TimeDuration::try_from(REFRESH_TRIGGER).expect("trigger") {
        return RefreshDecision::NotNeeded;
    }
    if already_running {
        return RefreshDecision::Running;
    }
    if !enabled {
        return RefreshDecision::Disabled;
    }
    RefreshDecision::Started
}

/// Pure verification: compare the credential read after the run with the
/// one the run started from.
pub(crate) fn judge_refresh(
    before_expires_at: &str,
    after: &ClaudeLiveLogin,
    now: OffsetDateTime,
) -> RefreshOutcome {
    if matches!(
        after.state,
        ClaudeLocalLoginState::SignedOutByCli | ClaudeLocalLoginState::NeedsLogin
    ) {
        return RefreshOutcome::SignedOut;
    }
    let parse = |at: Option<&str>| at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok());
    let before = parse(Some(before_expires_at));
    let after_expiry = parse(
        after
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.access_expires_at.as_deref()),
    );
    match (before, after_expiry) {
        (Some(before), Some(after)) if after > before && after > now => RefreshOutcome::Refreshed,
        _ => RefreshOutcome::ExpiryUnchanged,
    }
}

/// Decide for one login and, when due, start its refresher. `slot_id` is the
/// daemon's opaque slot id (`default` for the default login).
pub(crate) fn maybe_refresh(
    slot_id: &str,
    slot: &ClaudeConfigDirSlot,
    live: &ClaudeLiveLogin,
    enabled: bool,
) -> RefreshDecision {
    maybe_refresh_with(
        slot_id,
        slot,
        live,
        enabled,
        &default_support_dir(),
        &ProductionLauncher,
        &|| {
            crate::agent_status::claude_refresher_skip_reason(slot, live, OffsetDateTime::now_utc())
        },
    )
}

/// Starts the refresher process. Tests substitute a fake CLI through the
/// command search path; the launcher seam keeps the decision testable.
pub(crate) trait RefreshLauncher {
    fn launch(&self, slot: &ClaudeConfigDirSlot, cwd: &Path) -> std::io::Result<Child>;
}

struct ProductionLauncher;

impl RefreshLauncher for ProductionLauncher {
    fn launch(&self, slot: &ClaudeConfigDirSlot, cwd: &Path) -> std::io::Result<Child> {
        let mut command = crate::agent_status::resolved_claude_slot_command(slot, &REFRESH_ARGV)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "Claude Code CLI not found")
            })?;
        command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Own process group: a daemon restart (launchd stops the daemon's
        // group) does not stop a refresh in the middle of saving its token.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn()
    }
}

fn maybe_refresh_with(
    slot_id: &str,
    slot: &ClaudeConfigDirSlot,
    live: &ClaudeLiveLogin,
    enabled: bool,
    support_dir: &Path,
    launcher: &dyn RefreshLauncher,
    skip_reason: &dyn Fn() -> Option<&'static str>,
) -> RefreshDecision {
    let now = OffsetDateTime::now_utc();
    let current_expiry = live
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.access_expires_at.clone());
    let network_enabled = !crate::agent_status::claude_oauth_usage_network_disabled();
    // Read the failure history, check and reserve the slot in one critical
    // section (`running`, then the state lock; the waiter records its
    // outcome and releases the slot under the same `running` lock), so two
    // overlapping passes can never both start a refresher, and no pass
    // decides from a failure history older than the last finished attempt.
    {
        let mut reserved = running()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failed = {
            let _guard = state_lock()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut state = load_state(support_dir);
            // A new credential (a different access deadline) clears an old
            // failure.
            if let Some(failed) = state.failed.get(slot_id) {
                if current_expiry.as_deref() != Some(failed.access_expires_at.as_str()) {
                    state.failed.remove(slot_id);
                    let _ = write_state(support_dir, &state);
                }
            }
            state.failed.get(slot_id).cloned()
        };
        let decision = decide_refresh(
            live,
            enabled && network_enabled,
            reserved.contains_key(slot_id),
            failed.as_ref(),
            now,
        );
        if decision != RefreshDecision::Started || current_expiry.is_none() {
            return if decision == RefreshDecision::Started {
                RefreshDecision::NotNeeded
            } else {
                decision
            };
        }
        if let Some(reason) = skip_reason() {
            eprintln!("claude_refresher result=skipped reason={reason} target={slot_id}");
            return RefreshDecision::NotNeeded;
        }
        reserved.insert(slot_id.to_string(), ());
    }
    let release = || {
        running()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(slot_id);
    };
    let before_expires_at = current_expiry.expect("checked above");
    let Ok(cwd) = crate::claude_spawn_gate::empty_working_dir() else {
        release();
        eprintln!("claude_refresher result=not_started reason=working_dir target={slot_id}");
        return RefreshDecision::NotNeeded;
    };
    let before_mdat = credential_modified_marker(slot);
    let mut child = match launcher.launch(slot, cwd.path()) {
        Ok(child) => child,
        Err(_) => {
            release();
            eprintln!("claude_refresher result=not_started reason=spawn target={slot_id}");
            return RefreshDecision::NotNeeded;
        }
    };
    let mut keep_awake = keep_awake_while(&child);
    eprintln!("claude_refresher result=started target={slot_id}");
    let caller_slot_id = slot_id;
    let slot_id = slot_id.to_string();
    let slot = slot.clone();
    let support_dir = support_dir.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("ottto-claude-refresher".to_string())
        .spawn(move || {
            // Never killed: wait for the CLI to finish on its own.
            let started = Instant::now();
            let mut reported = false;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => {
                        if !reported && started.elapsed() >= REFRESH_REPORT_AFTER {
                            reported = true;
                            eprintln!(
                                "claude_refresher result=still_running target={slot_id} seconds={}",
                                started.elapsed().as_secs()
                            );
                        }
                        std::thread::sleep(POLL_INTERVAL);
                    }
                }
            }
            drop(cwd);
            // `caffeinate -w` exits with the refresher; reap it.
            if let Some(caffeinate) = keep_awake.as_mut() {
                let _ = caffeinate.wait();
            }
            let after = crate::agent_status::read_claude_live_login_for_slot(&slot);
            let outcome = judge_refresh(&before_expires_at, &after, OffsetDateTime::now_utc());
            let intact = after.metadata.as_ref().is_some_and(|metadata| {
                metadata.has_refresh_token && !metadata.cleared_by_cli
            });
            let mdat_changed = credential_modified_marker(&slot) != before_mdat;
            eprintln!(
                "claude_refresher result={} target={slot_id} keychain_modified={mdat_changed} seconds={}",
                outcome_code(outcome),
                started.elapsed().as_secs()
            );
            {
                // Record and release together, under the lock passes decide
                // in.
                let mut reserved = running()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if outcome != RefreshOutcome::Refreshed {
                    record_failure(&support_dir, &slot_id, &before_expires_at, outcome, intact);
                }
                reserved.remove(&slot_id);
            }
            // Collect again right away. (Not in unit tests: a detached status
            // pass must never outlive a test's throwaway environment.)
            #[cfg(not(test))]
            crate::snapshot_sync::spawn_claude_agent_status_refresh("claude_refresher");
        });
    if spawned.is_err() {
        // No waiter thread: the child keeps running unobserved; a later pass
        // reads the stored expiry and may refresh again if it did not move.
        running()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(caller_slot_id);
    }
    RefreshDecision::Started
}

fn outcome_code(outcome: RefreshOutcome) -> &'static str {
    match outcome {
        RefreshOutcome::Refreshed => "refreshed",
        RefreshOutcome::ExpiryUnchanged => "expiry_unchanged",
        RefreshOutcome::SignedOut => "signed_out",
    }
}

/// Wait (bounded) until no refresher runs for `slot_id`.
#[cfg(test)]
pub(crate) fn wait_until_idle(slot_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while running()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(slot_id)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Move a recorded failure `by` into the past (tests only).
#[cfg(test)]
pub(crate) fn backdate_failure_for_test(slot_id: &str, by: Duration) {
    let support_dir = default_support_dir();
    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut state = load_state(&support_dir);
    if let Some(failed) = state.failed.get_mut(slot_id) {
        let at = OffsetDateTime::parse(&failed.failed_at, &Rfc3339).expect("failed_at")
            - TimeDuration::try_from(by).expect("duration");
        failed.failed_at = at.format(&Rfc3339).expect("format");
        write_state(&support_dir, &state).expect("state");
    }
}

/// Forget a removed slot's refresh history.
pub(crate) fn prune_slot(slot_id: &str) {
    let support_dir = default_support_dir();
    let mut state = load_state(&support_dir);
    if state.failed.remove(slot_id).is_some() {
        let _ = write_state(&support_dir, &state);
    }
}

/// Record a failed refresh. The first failure of a credential that left it
/// intact allows one retry; a second failure, or a sign-out, does not.
fn record_failure(
    support_dir: &Path,
    slot_id: &str,
    expires_at: &str,
    outcome: RefreshOutcome,
    intact: bool,
) {
    let _guard = state_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut state = load_state(support_dir);
    let first_failure = state
        .failed
        .get(slot_id)
        .map_or(true, |failed| failed.access_expires_at != expires_at);
    let retry_allowed = first_failure && intact && outcome == RefreshOutcome::ExpiryUnchanged;
    state.failed.insert(
        slot_id.to_string(),
        FailedRefresh {
            access_expires_at: expires_at.to_string(),
            failed_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            outcome: outcome_code(outcome).to_string(),
            retry_allowed,
        },
    );
    let _ = write_state(support_dir, &state);
}

fn state_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn load_state(support_dir: &Path) -> RefreshState {
    std::fs::read(support_dir.join(STATE_FILE))
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

fn write_state(support_dir: &Path, state: &RefreshState) -> std::io::Result<()> {
    std::fs::create_dir_all(support_dir)?;
    let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&support_dir.join(STATE_FILE), &body)
}

/// Keep the Mac awake while the refresher runs (`caffeinate -i -w <pid>` exits
/// on its own when the refresher does; the waiter reaps it). Best effort.
fn keep_awake_while(child: &Child) -> Option<Child> {
    if cfg!(test) {
        return None;
    }
    let caffeinate = Path::new("/usr/bin/caffeinate");
    if !caffeinate.is_file() {
        return None;
    }
    std::process::Command::new(caffeinate)
        .args(["-i", "-w", &child.id().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

/// The stored credential's modification marker, for the log only: the
/// keychain item's `mdat` attribute (read without `-w`, so no secret), or the
/// credentials file's mtime.
fn credential_modified_marker(slot: &ClaudeConfigDirSlot) -> Option<String> {
    crate::agent_status::claude_credential_modified_marker(slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_status::ClaudeOAuthCredentialMetadata;
    use std::os::unix::fs::PermissionsExt;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000 + seconds).expect("time")
    }

    fn rfc(time: OffsetDateTime) -> String {
        time.format(&Rfc3339).expect("format")
    }

    fn live(state: ClaudeLocalLoginState, expires_at: OffsetDateTime) -> ClaudeLiveLogin {
        ClaudeLiveLogin {
            state,
            metadata: Some(ClaudeOAuthCredentialMetadata {
                access_expires_at: Some(rfc(expires_at)),
                refresh_token_expires_at: Some(rfc(expires_at + TimeDuration::days(20))),
                has_refresh_token: true,
                cleared_by_cli: false,
                has_profile_scope: false,
            }),
        }
    }

    #[test]
    fn refresh_starts_only_inside_claude_codes_own_window() {
        let valid = ClaudeLocalLoginState::AccessValid;
        let pending = ClaudeLocalLoginState::RefreshPending;
        for (state, expires_in, expected) in [
            (valid, TimeDuration::minutes(30), RefreshDecision::NotNeeded),
            (
                valid,
                TimeDuration::minutes(5) + TimeDuration::seconds(1),
                RefreshDecision::NotNeeded,
            ),
            (valid, TimeDuration::minutes(5), RefreshDecision::Started),
            (valid, TimeDuration::minutes(3), RefreshDecision::Started),
            (pending, TimeDuration::seconds(30), RefreshDecision::Started),
            // First pass after a wake: already expired.
            (pending, -TimeDuration::hours(3), RefreshDecision::Started),
        ] {
            assert_eq!(
                decide_refresh(&live(state, at(0) + expires_in), true, false, None, at(0)),
                expected,
                "{expires_in}"
            );
        }
        let due = live(pending, at(-60));
        assert_eq!(
            decide_refresh(&due, true, true, None, at(0)),
            RefreshDecision::Running
        );
        assert_eq!(
            decide_refresh(&due, false, false, None, at(0)),
            RefreshDecision::Disabled
        );
        let failed = |expiry: OffsetDateTime, failed_at: OffsetDateTime, retry_allowed: bool| {
            FailedRefresh {
                access_expires_at: rfc(expiry),
                failed_at: rfc(failed_at),
                outcome: "expiry_unchanged".to_string(),
                retry_allowed,
            }
        };
        assert_eq!(
            decide_refresh(
                &due,
                true,
                false,
                Some(&failed(at(-60), at(-30), false)),
                at(0)
            ),
            RefreshDecision::FailedWaitingForSignIn
        );
        // One retry after an intact failure: not before 5 minutes, then once.
        let intact = failed(at(-60), at(-30), true);
        assert_eq!(
            decide_refresh(&due, true, false, Some(&intact), at(0)),
            RefreshDecision::RetryWaiting
        );
        assert_eq!(
            decide_refresh(&due, true, false, Some(&intact), at(5 * 60 - 31)),
            RefreshDecision::RetryWaiting
        );
        assert_eq!(
            decide_refresh(&due, true, false, Some(&intact), at(5 * 60 - 30)),
            RefreshDecision::Started
        );
        assert_eq!(
            decide_refresh(&due, true, true, Some(&intact), at(5 * 60)),
            RefreshDecision::Running
        );
        // A different (new) credential is not held back by an old failure.
        assert_eq!(
            decide_refresh(
                &due,
                true,
                false,
                Some(&failed(at(-7_200), at(-30), false)),
                at(0)
            ),
            RefreshDecision::Started
        );
        for state in [
            ClaudeLocalLoginState::NeedsLogin,
            ClaudeLocalLoginState::SignedOutByCli,
            ClaudeLocalLoginState::NotSignedIn,
            ClaudeLocalLoginState::Unreadable,
        ] {
            assert_eq!(
                decide_refresh(&live(state, at(-60)), true, false, None, at(0)),
                RefreshDecision::NotNeeded
            );
        }
    }

    /// Two overlapping passes can never both start a refresher for a slot:
    /// the check and the reservation happen together.
    #[test]
    #[serial_test::serial]
    fn concurrent_passes_start_one_refresher_per_slot() {
        struct SlowLauncher {
            launches: std::sync::atomic::AtomicUsize,
        }
        impl RefreshLauncher for SlowLauncher {
            fn launch(&self, _slot: &ClaudeConfigDirSlot, _cwd: &Path) -> std::io::Result<Child> {
                self.launches
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                std::process::Command::new("/bin/sleep").arg("0.3").spawn()
            }
        }
        let support = std::env::temp_dir().join(format!(
            "ottto-claude-refresher-race-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(support.join("empty-bin")).expect("support");
        // No `security` on the search path: no keychain is ever queried.
        let previous_search = std::env::var_os("OTTTO_COMMAND_SEARCH_PATH");
        std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", support.join("empty-bin"));
        let launcher = std::sync::Arc::new(SlowLauncher {
            launches: std::sync::atomic::AtomicUsize::new(0),
        });
        let due = live(
            ClaudeLocalLoginState::RefreshPending,
            OffsetDateTime::now_utc() - TimeDuration::minutes(1),
        );
        let slot = ClaudeConfigDirSlot::registered("/tmp/ottto-refresher-race-slot".to_string())
            .expect("slot");
        let decisions = (0..4)
            .map(|_| {
                let launcher = launcher.clone();
                let due = due.clone();
                let slot = slot.clone();
                let support = support.clone();
                std::thread::spawn(move || {
                    maybe_refresh_with(
                        "race-slot",
                        &slot,
                        &due,
                        true,
                        &support,
                        launcher.as_ref(),
                        &|| None,
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("join"))
            .collect::<Vec<_>>();
        assert_eq!(
            decisions
                .iter()
                .filter(|decision| **decision == RefreshDecision::Started)
                .count(),
            1,
            "{decisions:?}"
        );
        assert_eq!(
            launcher.launches.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        wait_until_idle("race-slot");
        match previous_search {
            Some(value) => std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", value),
            None => std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH"),
        }
        let _ = std::fs::remove_dir_all(support);
    }

    #[test]
    #[serial_test::serial]
    fn only_a_first_intact_failure_gets_one_retry() {
        let support = std::env::temp_dir().join(format!(
            "ottto-claude-refresher-retry-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let expiry = rfc(at(0));
        let retry = |slot_id: &str| load_state(&support).failed[slot_id].retry_allowed;
        record_failure(
            &support,
            "a",
            &expiry,
            RefreshOutcome::ExpiryUnchanged,
            true,
        );
        assert!(retry("a"), "first failure, login intact");
        record_failure(
            &support,
            "a",
            &expiry,
            RefreshOutcome::ExpiryUnchanged,
            true,
        );
        assert!(!retry("a"), "the retry failed too");
        record_failure(&support, "b", &expiry, RefreshOutcome::SignedOut, false);
        assert!(!retry("b"), "signed out");
        record_failure(
            &support,
            "c",
            &expiry,
            RefreshOutcome::ExpiryUnchanged,
            false,
        );
        assert!(!retry("c"), "refresh token gone or blanked");
        let _ = std::fs::remove_dir_all(support);
    }

    /// A login whose `/usage` would not refresh (no `user:profile`,
    /// usage-billed, another credential first) never gets a refresher.
    #[test]
    #[serial_test::serial]
    fn an_ineligible_login_never_starts_a_refresher() {
        struct CountingLauncher(std::sync::atomic::AtomicUsize);
        impl RefreshLauncher for CountingLauncher {
            fn launch(&self, _slot: &ClaudeConfigDirSlot, _cwd: &Path) -> std::io::Result<Child> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::process::Command::new("/usr/bin/true").spawn()
            }
        }
        let support = std::env::temp_dir().join(format!(
            "ottto-claude-refresher-skip-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let launcher = CountingLauncher(std::sync::atomic::AtomicUsize::new(0));
        let due = live(
            ClaudeLocalLoginState::RefreshPending,
            OffsetDateTime::now_utc() - TimeDuration::minutes(1),
        );
        let slot = ClaudeConfigDirSlot::registered("/tmp/ottto-refresher-skip-slot".to_string())
            .expect("slot");
        for reason in [
            "no_profile_scope",
            "usage_billing",
            "other_auth",
            "usage_cached",
        ] {
            assert_eq!(
                maybe_refresh_with("skip-slot", &slot, &due, true, &support, &launcher, &|| {
                    Some(reason)
                }),
                RefreshDecision::NotNeeded,
                "{reason}"
            );
        }
        assert_eq!(launcher.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!running().lock().unwrap().contains_key("skip-slot"));
        let _ = std::fs::remove_dir_all(support);
    }

    #[test]
    fn success_is_only_a_later_future_expiry() {
        let before = rfc(at(60));
        assert_eq!(
            judge_refresh(
                &before,
                &live(ClaudeLocalLoginState::AccessValid, at(8 * 3600)),
                at(0)
            ),
            RefreshOutcome::Refreshed
        );
        assert_eq!(
            judge_refresh(
                &before,
                &live(ClaudeLocalLoginState::AccessValid, at(60)),
                at(0)
            ),
            RefreshOutcome::ExpiryUnchanged
        );
        assert_eq!(
            judge_refresh(
                &before,
                &live(ClaudeLocalLoginState::SignedOutByCli, at(0)),
                at(0)
            ),
            RefreshOutcome::SignedOut
        );
    }

    /// End to end with a fake `claude` and a file credential: a refresher run
    /// that advances `expiresAt` succeeds; one that does not is recorded and
    /// the login is not refreshed again until a new credential appears.
    #[test]
    #[serial_test::serial]
    fn refresher_verifies_the_stored_expiry_and_stops_after_a_failure() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-refresher-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let bin = root.join("bin");
        let home = root.join("home");
        let support = root.join("support");
        let slot_dir = root.join("slot");
        for dir in [&bin, &home, &support, &slot_dir] {
            std::fs::create_dir_all(dir).expect("dir");
        }
        let credential = |expires: OffsetDateTime| {
            serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": "fixture-access",
                    "refreshToken": "fixture-refresh",
                    "expiresAt": expires.unix_timestamp() * 1_000,
                    "refreshTokenExpiresAt": (expires + TimeDuration::days(20)).unix_timestamp() * 1_000,
                    "scopes": ["user:inference"]
                }
            })
            .to_string()
        };
        let now = OffsetDateTime::now_utc();
        let fresh = credential(now + TimeDuration::hours(8));
        let fresh_path = root.join("fresh.json");
        std::fs::write(&fresh_path, &fresh).expect("fresh");
        let log = root.join("spawns.log");
        // The fake CLI "refreshes" by writing a later expiry when asked to.
        let claude = bin.join("claude");
        std::fs::write(
            &claude,
            format!(
                "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR|$PWD|$*\" >> '{log}'\nif [ -f '{root}/refresh-works' ]; then /bin/cp '{fresh}' \"$CLAUDE_CONFIG_DIR/.credentials.json\"; fi\nexit 0\n",
                log = log.display(),
                root = root.display(),
                fresh = fresh_path.display()
            ),
        )
        .expect("claude");
        let security = bin.join("security");
        std::fs::write(&security, "#!/bin/sh\nexit 44\n").expect("security");
        for path in [&claude, &security] {
            let mut permissions = std::fs::metadata(path).expect("meta").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("chmod");
        }
        let guards = [
            ("HOME", home.as_os_str().to_os_string()),
            (
                "OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS",
                home.as_os_str().to_os_string(),
            ),
            (
                "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
                support.as_os_str().to_os_string(),
            ),
            ("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string()),
        ]
        .map(|(key, value)| {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            (key, previous)
        });
        let slot =
            ClaudeConfigDirSlot::registered(slot_dir.to_string_lossy().to_string()).expect("slot");
        let wait = |slot_id: &str| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while running().lock().unwrap().contains_key(slot_id) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
        };

        // Expiring in 2 minutes; the refresh works.
        std::fs::write(root.join("refresh-works"), "").expect("flag");
        std::fs::write(
            slot_dir.join(".credentials.json"),
            credential(now + TimeDuration::minutes(2)),
        )
        .expect("credential");
        let due = crate::agent_status::read_claude_live_login_for_slot(&slot);
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &due,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::Started
        );
        wait("slot-a");
        let after = crate::agent_status::read_claude_live_login_for_slot(&slot);
        assert_eq!(after.state, ClaudeLocalLoginState::AccessValid);
        assert!(load_state(&support).failed.is_empty());
        let spawned = std::fs::read_to_string(&log).expect("log");
        assert_eq!(spawned.lines().count(), 1, "exactly one refresher");
        let line = spawned.lines().next().unwrap();
        assert!(line.starts_with(&format!("{}|", slot_dir.display())));
        assert!(line.ends_with("|-p /usage --no-session-persistence --strict-mcp-config"));
        assert!(
            line.contains("ottto-claude-empty-"),
            "empty working dir: {line}"
        );

        // Expired; the refresh does not advance the expiry.
        std::fs::remove_file(root.join("refresh-works")).expect("flag");
        let expired = now - TimeDuration::minutes(30);
        std::fs::write(slot_dir.join(".credentials.json"), credential(expired)).expect("cred");
        let due = crate::agent_status::read_claude_live_login_for_slot(&slot);
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &due,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::Started
        );
        wait("slot-a");
        let first = load_state(&support).failed["slot-a"].clone();
        assert_eq!(first.outcome, "expiry_unchanged");
        assert!(first.retry_allowed, "the login is intact: one retry");
        let again = crate::agent_status::read_claude_live_login_for_slot(&slot);
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &again,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::RetryWaiting,
            "the retry waits for a later pass"
        );
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
        // Five minutes later the one retry runs; it fails too.
        let mut state = load_state(&support);
        state.failed.get_mut("slot-a").unwrap().failed_at =
            rfc(OffsetDateTime::now_utc() - TimeDuration::minutes(6));
        write_state(&support, &state).expect("state");
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &again,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::Started
        );
        wait("slot-a");
        assert!(!load_state(&support).failed["slot-a"].retry_allowed);
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &again,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::FailedWaitingForSignIn,
            "no loop: sign in again after the one retry"
        );
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 3);

        // A new credential (the user signed in again) clears the failure.
        std::fs::write(
            slot_dir.join(".credentials.json"),
            credential(now + TimeDuration::hours(8)),
        )
        .expect("cred");
        let signed_in = crate::agent_status::read_claude_live_login_for_slot(&slot);
        assert_eq!(
            maybe_refresh_with(
                "slot-a",
                &slot,
                &signed_in,
                true,
                &support,
                &ProductionLauncher,
                &|| None
            ),
            RefreshDecision::NotNeeded
        );
        assert!(load_state(&support).failed.is_empty());

        for (key, previous) in guards {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
