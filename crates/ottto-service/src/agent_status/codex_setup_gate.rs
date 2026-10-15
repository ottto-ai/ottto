//! Spacing of the provider reads a Codex setup makes while it waits for the
//! person to sign in.
//!
//! The companion checks a waiting setup every few seconds, whether or not it
//! is visible, until the setup leaves the waiting state. Each check that
//! reaches the provider starts one `codex app-server`, so a sign-in that never
//! finishes, or a home whose read keeps failing, used to start one run after
//! another for as long as the setup waited. Per home, this gate admits:
//! - no read while the home has no `auth.json`: managed homes keep their
//!   credential in that file, so there is nothing to read until the sign-in
//!   writes it;
//! - the first read of a setup operation, and the first read after the home's
//!   sign-in changed, at once;
//! - after a failed read, the next automatic read only after
//!   [`FIRST_RETRY_SECONDS`], doubling per failure up to
//!   [`MAX_RETRY_SECONDS`];
//! - no automatic read once the reads have failed for
//!   [`AUTOMATIC_PROBE_WINDOW_SECONDS`] under the same sign-in. The checks
//!   go on locally: a new sign-in writes `auth.json` and is read at once;
//! - a person's explicit check at most once per [`EXPLICIT_MIN_GAP_SECONDS`].
//!
//! One read at a time per home: a check that arrives while another runs waits
//! for it, then sees its outcome. The state lives in memory, so a daemon
//! restart reads a waiting home once more.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use ottto_core::CodexHomeTrust;

use super::codex_saved_quota::{login_mark, LoginMark};

/// Wait after the first failed read of a waiting setup.
const FIRST_RETRY_SECONDS: u64 = 10;
/// Longest wait between automatic reads of a waiting setup.
const MAX_RETRY_SECONDS: u64 = 300;
/// How long automatic reads keep trying under one sign-in. A browser sign-in
/// a person attends ends within minutes; past this the setup is idle, and only
/// a new sign-in or the person's check reads the provider again.
const AUTOMATIC_PROBE_WINDOW_SECONDS: u64 = 30 * 60;
/// Shortest gap before a person's explicit check reads again after a failure.
const EXPLICIT_MIN_GAP_SECONDS: u64 = 5;

/// Failed setup reads of one home, since the last success.
#[derive(Debug, Clone, PartialEq)]
struct Failures {
    operation_id: String,
    count: u32,
    first_failed_at: Instant,
    last_attempt_at: Instant,
    /// The home's login right after the last failed read. That read may
    /// itself rewrite `auth.json`; only a change after it is a new sign-in.
    login: LoginMark,
}

/// Why a waiting setup's check did not read the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SetupReadDeferred {
    /// The home has no credential file yet.
    NotSignedIn,
    /// A recent read failed; the next one is due in this many seconds.
    RetryIn(u64),
    /// Automatic reads stopped; a new sign-in or an explicit check reads.
    Stopped,
}

impl SetupReadDeferred {
    pub(super) fn message(self) -> String {
        match self {
            Self::NotSignedIn => "Codex sign-in has not finished in this home yet.".to_string(),
            Self::RetryIn(seconds) => format!(
                "The last Codex check failed; the next check runs in {seconds} s or as soon as the sign-in changes."
            ),
            Self::Stopped => "Codex checks paused after 30 minutes without a sign-in; sign in again or check the connection.".to_string(),
        }
    }
}

fn retry_after(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    FIRST_RETRY_SECONDS
        .saturating_mul(1 << doublings)
        .min(MAX_RETRY_SECONDS)
}

/// Whether a waiting setup's check reads the provider now.
fn admit(
    failures: Option<&Failures>,
    operation_id: &str,
    current_login: &LoginMark,
    explicit: bool,
    now: Instant,
) -> Result<(), SetupReadDeferred> {
    if !current_login.has_credential_file() {
        return Err(SetupReadDeferred::NotSignedIn);
    }
    let Some(failures) = failures else {
        return Ok(());
    };
    if failures.operation_id != operation_id || &failures.login != current_login {
        return Ok(());
    }
    let since_last = now.saturating_duration_since(failures.last_attempt_at);
    if explicit {
        let gap = Duration::from_secs(EXPLICIT_MIN_GAP_SECONDS);
        return match gap.checked_sub(since_last) {
            Some(wait) if !wait.is_zero() => Err(SetupReadDeferred::RetryIn(ceil_secs(wait))),
            _ => Ok(()),
        };
    }
    if now.saturating_duration_since(failures.first_failed_at)
        >= Duration::from_secs(AUTOMATIC_PROBE_WINDOW_SECONDS)
    {
        return Err(SetupReadDeferred::Stopped);
    }
    match Duration::from_secs(retry_after(failures.count)).checked_sub(since_last) {
        Some(wait) if !wait.is_zero() => Err(SetupReadDeferred::RetryIn(ceil_secs(wait))),
        _ => Ok(()),
    }
}

fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// The failures after a read admitted at `started_at` ended at `now`.
fn after_read(
    failures: Option<Failures>,
    operation_id: &str,
    login_after: LoginMark,
    succeeded: bool,
    started_at: Instant,
    now: Instant,
) -> Option<Failures> {
    if succeeded {
        return None;
    }
    match failures {
        // Same setup, same sign-in: one more failure in the same run.
        Some(previous)
            if previous.operation_id == operation_id && previous.login == login_after =>
        {
            Some(Failures {
                count: previous.count.saturating_add(1),
                last_attempt_at: now,
                ..previous
            })
        }
        _ => Some(Failures {
            operation_id: operation_id.to_string(),
            count: 1,
            first_failed_at: started_at,
            last_attempt_at: now,
            login: login_after,
        }),
    }
}

/// One home's failures, locked for the length of a read.
type HomeState = Arc<Mutex<Option<Failures>>>;

fn home_state(home: &Path) -> HomeState {
    static HOMES: OnceLock<Mutex<BTreeMap<String, HomeState>>> = OnceLock::new();
    HOMES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(home.to_string_lossy().into_owned())
        .or_default()
        .clone()
}

/// Run `read` (one setup read of `home`, reaching the provider) if the gate
/// admits it now, and note its outcome: `read` returns its value and whether
/// the setup read succeeded.
pub(super) fn read_waiting_setup_home<T>(
    home: &Path,
    operation_id: &str,
    explicit: bool,
    read: impl FnOnce() -> (T, bool),
) -> Result<T, SetupReadDeferred> {
    let state = home_state(home);
    let mut failures = state.lock().unwrap_or_else(PoisonError::into_inner);
    let started_at = Instant::now();
    admit(
        failures.as_ref(),
        operation_id,
        &login_mark(home, CodexHomeTrust::Managed),
        explicit,
        started_at,
    )?;
    let (value, succeeded) = read();
    let login_after = login_mark(home, CodexHomeTrust::Managed);
    *failures = after_read(
        failures.take(),
        operation_id,
        login_after,
        succeeded,
        started_at,
        Instant::now(),
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION: &str = "codex_setup_0123456789abcdef0123456789abcdef";

    fn signed_in(witness: u64) -> LoginMark {
        LoginMark::for_test(None, Some(witness))
    }

    fn failed(count: u32, first: Instant, last: Instant, login: LoginMark) -> Failures {
        Failures {
            operation_id: OPERATION.to_string(),
            count,
            first_failed_at: first,
            last_attempt_at: last,
            login,
        }
    }

    #[test]
    fn a_home_without_a_credential_file_is_never_read() {
        let now = Instant::now();
        let none = LoginMark::default();
        assert_eq!(
            admit(None, OPERATION, &none, false, now),
            Err(SetupReadDeferred::NotSignedIn)
        );
        assert_eq!(
            admit(None, OPERATION, &none, true, now),
            Err(SetupReadDeferred::NotSignedIn)
        );
    }

    #[test]
    fn the_first_read_of_a_setup_runs_at_once() {
        let now = Instant::now();
        let login = signed_in(1);
        assert_eq!(admit(None, OPERATION, &login, false, now), Ok(()));
        // Failures of an earlier setup of the same home do not delay a new one.
        let earlier = Failures {
            operation_id: "codex_setup_ffffffffffffffffffffffffffffffff".to_string(),
            ..failed(6, now, now, login.clone())
        };
        assert_eq!(admit(Some(&earlier), OPERATION, &login, false, now), Ok(()));
    }

    #[test]
    fn automatic_reads_back_off_after_failures_up_to_five_minutes() {
        let start = Instant::now();
        let login = signed_in(1);
        let at = |seconds| start + Duration::from_secs(seconds);
        let one = failed(1, start, start, login.clone());
        assert_eq!(
            admit(Some(&one), OPERATION, &login, false, at(3)),
            Err(SetupReadDeferred::RetryIn(7))
        );
        assert_eq!(admit(Some(&one), OPERATION, &login, false, at(10)), Ok(()));

        let waits: Vec<u64> = (1..=8).map(retry_after).collect();
        assert_eq!(waits, vec![10, 20, 40, 80, 160, 300, 300, 300]);
        let six = failed(6, start, at(100), login.clone());
        assert_eq!(
            admit(Some(&six), OPERATION, &login, false, at(399)),
            Err(SetupReadDeferred::RetryIn(1))
        );
        assert_eq!(admit(Some(&six), OPERATION, &login, false, at(400)), Ok(()));
    }

    #[test]
    fn automatic_reads_stop_after_the_window_until_the_sign_in_changes() {
        let start = Instant::now();
        let login = signed_in(1);
        let late = start + Duration::from_secs(AUTOMATIC_PROBE_WINDOW_SECONDS);
        let many = failed(11, start, late - Duration::from_secs(400), login.clone());
        assert_eq!(
            admit(Some(&many), OPERATION, &login, false, late),
            Err(SetupReadDeferred::Stopped)
        );
        // A new sign-in (the credential file was rewritten) reads at once.
        assert_eq!(
            admit(Some(&many), OPERATION, &signed_in(2), false, late),
            Ok(())
        );
        // So does a person's check.
        assert_eq!(admit(Some(&many), OPERATION, &login, true, late), Ok(()));
    }

    #[test]
    fn an_explicit_check_reads_at_most_once_per_few_seconds() {
        let start = Instant::now();
        let login = signed_in(1);
        let one = failed(4, start, start, login.clone());
        assert_eq!(
            admit(
                Some(&one),
                OPERATION,
                &login,
                true,
                start + Duration::from_secs(2)
            ),
            Err(SetupReadDeferred::RetryIn(3))
        );
        assert_eq!(
            admit(
                Some(&one),
                OPERATION,
                &login,
                true,
                start + Duration::from_secs(EXPLICIT_MIN_GAP_SECONDS)
            ),
            Ok(())
        );
    }

    #[test]
    fn outcomes_count_failures_per_setup_and_sign_in_and_reset_on_success() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let login = signed_in(1);
        let first = after_read(None, OPERATION, login.clone(), false, start, at(4))
            .expect("a failure is noted");
        assert_eq!(first, failed(1, start, at(4), login.clone()));
        let second = after_read(
            Some(first.clone()),
            OPERATION,
            login.clone(),
            false,
            at(14),
            at(18),
        )
        .expect("a second failure is noted");
        assert_eq!(second, failed(2, start, at(18), login.clone()));
        // A failure under another sign-in starts a new run.
        let other = after_read(
            Some(second.clone()),
            OPERATION,
            signed_in(2),
            false,
            at(20),
            at(24),
        )
        .expect("a failure under a new sign-in is noted");
        assert_eq!(other, failed(1, at(20), at(24), signed_in(2)));
        assert_eq!(
            after_read(Some(second), OPERATION, login, true, at(30), at(34)),
            None
        );
    }
}
