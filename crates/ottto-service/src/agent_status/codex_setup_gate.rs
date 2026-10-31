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
//! - one read at once after `auth.json` was rewritten since the last read
//!   noted it, without restarting the run of failures (see below);
//! - after a failed read, the next automatic read only after
//!   [`SHORT_RETRY_SECONDS`] for the first [`SHORT_RETRIES`] failures under
//!   one sign-in, then after [`FIRST_RETRY_SECONDS`], doubling per failure up
//!   to [`MAX_RETRY_SECONDS`];
//! - once the reads have failed for [`LONG_FAILURE_SECONDS`] under one
//!   sign-in, one automatic read per [`SLOW_RETRY_SECONDS`];
//! - a person's explicit check at most once per [`EXPLICIT_MIN_GAP_SECONDS`].
//!
//! A sign-in is the account and workspace the credential names, compared as
//! the saved-quota schedule does ([`LoginMark::same_login`]): every read
//! refreshes the token and so rewrites `auth.json`, and that rewrite, or one
//! by another reader of the home, is not a new sign-in. Only a credential
//! that names no account falls back to the file's metadata. Whether a read
//! continues a run of failures is decided from the sign-in seen before it.
//!
//! A reconnect keeps the home and its `auth.json`, and the person signs in
//! again to the same account and workspace. While the old access token has
//! not expired, that new credential names the same sign-in, so it continues
//! the run. The gate stores the file's metadata as it was right after each
//! read, so a read's own rewrite is never seen as a change; a rewrite made
//! between reads (that sign-in, or another reader refreshing the token) is
//! read once at once and then spaced like the run it continues.
//!
//! One read at a time per home: a check that arrives while a read runs waits
//! for it. After a failed read it is spaced like any other check; after a
//! successful one the state is cleared, so it reads again (the setup has
//! usually moved on by then, as before this gate). The state lives in memory
//! of one daemon process: a daemon restart reads a waiting home once more,
//! and two daemons on one support directory each keep their own spacing.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use ottto_core::CodexHomeTrust;

use super::codex_saved_quota::{login_mark, LoginMark};

/// Wait after each of the first [`SHORT_RETRIES`] failed reads under one
/// sign-in: a short provider error right after a person signs in should not
/// keep them waiting.
const SHORT_RETRY_SECONDS: u64 = 5;
/// Failed reads under one sign-in that are retried after
/// [`SHORT_RETRY_SECONDS`].
const SHORT_RETRIES: u32 = 3;
/// Wait after the first failed read past the short retries; it doubles per
/// further failure.
const FIRST_RETRY_SECONDS: u64 = 10;
/// Longest wait between automatic reads while the failures are recent.
const MAX_RETRY_SECONDS: u64 = 5 * 60;
/// How long reads under one sign-in fail before automatic reads slow to
/// [`SLOW_RETRY_SECONDS`]. A browser sign-in a person attends ends within
/// minutes; past this nobody is waiting on the setup.
const LONG_FAILURE_SECONDS: u64 = 30 * 60;
/// Wait between automatic reads once the failures are older than
/// [`LONG_FAILURE_SECONDS`], the saved-quota schedule's interval for a home
/// not in use. A cleared cause (network back, Codex CLI updated) is still
/// noticed without a new sign-in or a person's check.
const SLOW_RETRY_SECONDS: u64 = 15 * 60;
/// Shortest gap before a person's explicit check reads again after a failure.
const EXPLICIT_MIN_GAP_SECONDS: u64 = 5;

/// A run of failed setup reads of one home: one setup operation under one
/// sign-in, since the last success.
#[derive(Debug, Clone, PartialEq)]
struct Failures {
    operation_id: String,
    count: u32,
    first_failed_at: Instant,
    last_attempt_at: Instant,
    /// The home's login right after the last failed read, which may itself
    /// have rewritten `auth.json`.
    login: LoginMark,
}

impl Failures {
    /// Whether a read of `operation_id` under `current_login` (the login seen
    /// before it) continues this run.
    ///
    /// The claimed sign-in exists only while the access token has not
    /// expired by the wall clock. When the stored token expires between
    /// reads, or the clock steps across its expiry, the claim appears or
    /// disappears and a new run starts, with its short retries. That happens
    /// once per expiry: the next read refreshes the token.
    fn continued_by(&self, operation_id: &str, current_login: &LoginMark) -> bool {
        self.operation_id == operation_id && self.login.same_login(current_login)
    }
}

/// Why a waiting setup's check did not read the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SetupReadDeferred {
    /// The home has no credential file yet.
    NotSignedIn,
    /// A recent read failed; the next automatic one is due in this many
    /// seconds.
    RetryIn(u64),
}

impl SetupReadDeferred {
    /// Diagnostic text. The setup check answers with the stored setup state,
    /// which still says it waits for sign-in, so the companion does not show
    /// this.
    pub(super) fn message(self) -> String {
        match self {
            Self::NotSignedIn => "Codex sign-in has not finished in this home yet.".to_string(),
            Self::RetryIn(seconds) => format!(
                "The last Codex check failed; the next check runs in {seconds} s or as soon as the sign-in changes."
            ),
        }
    }
}

/// The wait after `failures` failed reads in one run, while the run is
/// younger than [`LONG_FAILURE_SECONDS`].
fn retry_after(failures: u32) -> u64 {
    if failures <= SHORT_RETRIES {
        return SHORT_RETRY_SECONDS;
    }
    let doublings = (failures - SHORT_RETRIES - 1).min(16);
    FIRST_RETRY_SECONDS
        .saturating_mul(1 << doublings)
        .min(MAX_RETRY_SECONDS)
}

/// Whether a waiting setup's check reads the provider now. `run` is the run
/// of failures this read would continue ([`Failures::continued_by`]); `None`
/// for a new setup operation or a new sign-in. A credential file rewritten
/// since the run's last read is read at once; the run goes on.
fn admit(
    run: Option<&Failures>,
    current_login: &LoginMark,
    explicit: bool,
    now: Instant,
) -> Result<(), SetupReadDeferred> {
    if !current_login.has_credential_file() {
        return Err(SetupReadDeferred::NotSignedIn);
    }
    let Some(run) = run else {
        return Ok(());
    };
    // `run.login` is the file as the last read left it, so this is a rewrite
    // made between reads, such as a sign-in to the same account.
    if !run.login.same_credential_file(current_login) {
        return Ok(());
    }
    let wait = if explicit {
        EXPLICIT_MIN_GAP_SECONDS
    } else if now.saturating_duration_since(run.first_failed_at)
        >= Duration::from_secs(LONG_FAILURE_SECONDS)
    {
        SLOW_RETRY_SECONDS
    } else {
        retry_after(run.count)
    };
    let since_last = now.saturating_duration_since(run.last_attempt_at);
    match Duration::from_secs(wait).checked_sub(since_last) {
        Some(remaining) if !remaining.is_zero() => {
            Err(SetupReadDeferred::RetryIn(ceil_secs(remaining)))
        }
        _ => Ok(()),
    }
}

fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// The failures after a read admitted at `started_at` ended at `now`. `run`
/// is the run the read continued, if any.
fn after_read(
    run: Option<Failures>,
    operation_id: &str,
    login_after: LoginMark,
    succeeded: bool,
    started_at: Instant,
    now: Instant,
) -> Option<Failures> {
    if succeeded {
        return None;
    }
    Some(match run {
        Some(run) => Failures {
            count: run.count.saturating_add(1),
            last_attempt_at: now,
            login: login_after,
            ..run
        },
        None => Failures {
            operation_id: operation_id.to_string(),
            count: 1,
            first_failed_at: started_at,
            last_attempt_at: now,
            login: login_after,
        },
    })
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

#[cfg(not(test))]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn now() -> Instant {
    TEST_NOW
        .with(|test_now| test_now.get())
        .unwrap_or_else(Instant::now)
}

/// The gate's clock on this thread, frozen for a test: it moves only when the
/// test sets it. Dropping it gives the thread the real clock back.
#[cfg(test)]
pub(crate) struct SetupGateTestClock {
    start: Instant,
}

#[cfg(test)]
impl SetupGateTestClock {
    pub(crate) fn frozen_at(start: Instant) -> Self {
        TEST_NOW.with(|test_now| test_now.set(Some(start)));
        Self { start }
    }

    /// Set the clock to `seconds` after the start.
    pub(crate) fn set(&self, seconds: u64) {
        let at = self.start + Duration::from_secs(seconds);
        TEST_NOW.with(|test_now| test_now.set(Some(at)));
    }
}

#[cfg(test)]
impl Drop for SetupGateTestClock {
    fn drop(&mut self) {
        TEST_NOW.with(|test_now| test_now.set(None));
    }
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
    let started_at = now();
    let login_before = login_mark(home, CodexHomeTrust::Managed);
    let run = failures
        .as_ref()
        .filter(|run| run.continued_by(operation_id, &login_before))
        .cloned();
    admit(run.as_ref(), &login_before, explicit, started_at)?;
    let (value, succeeded) = read();
    let login_after = login_mark(home, CodexHomeTrust::Managed);
    *failures = after_read(run, operation_id, login_after, succeeded, started_at, now());
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
            admit(None, &none, false, now),
            Err(SetupReadDeferred::NotSignedIn)
        );
        assert_eq!(
            admit(None, &none, true, now),
            Err(SetupReadDeferred::NotSignedIn)
        );
    }

    #[test]
    fn the_first_read_of_a_setup_or_sign_in_runs_at_once() {
        let now = Instant::now();
        let login = signed_in(1);
        assert_eq!(admit(None, &login, false, now), Ok(()));
        // Failures of an earlier setup of the same home do not delay a new one.
        let earlier = Failures {
            operation_id: "codex_setup_ffffffffffffffffffffffffffffffff".to_string(),
            ..failed(6, now, now, login.clone())
        };
        assert!(!earlier.continued_by(OPERATION, &login));
        // Nor do failures under another sign-in.
        let other = failed(6, now, now, signed_in(2));
        assert!(!other.continued_by(OPERATION, &login));
        assert!(other.continued_by(OPERATION, &signed_in(2)));
    }

    #[test]
    fn a_rewritten_credential_of_the_same_account_continues_the_run() {
        // Every read refreshes the token and rewrites `auth.json`.
        let before = LoginMark::for_test(Some("account-a"), Some(1));
        let rewritten = LoginMark::for_test(Some("account-a"), Some(2));
        let other_account = LoginMark::for_test(Some("account-b"), Some(2));
        let run = failed(4, Instant::now(), Instant::now(), before);
        assert!(run.continued_by(OPERATION, &rewritten));
        assert!(!run.continued_by(OPERATION, &other_account));
    }

    #[test]
    fn a_credential_rewritten_between_reads_is_read_once_at_once() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        // The last read left the file like this, its own refresh included.
        let after_last_read = LoginMark::for_test(Some("account-a"), Some(1));
        let run = failed(6, start, at(100), after_last_read.clone());
        assert_eq!(
            admit(Some(&run), &after_last_read, false, at(101)),
            Err(SetupReadDeferred::RetryIn(39))
        );
        // The person signed in again to the same account: same run, read now.
        let signed_in_again = LoginMark::for_test(Some("account-a"), Some(2));
        assert!(run.continued_by(OPERATION, &signed_in_again));
        assert_eq!(admit(Some(&run), &signed_in_again, false, at(101)), Ok(()));
        // That read failed too: the run keeps counting and spacing.
        let next = after_read(
            Some(run),
            OPERATION,
            LoginMark::for_test(Some("account-a"), Some(3)),
            false,
            at(101),
            at(102),
        )
        .expect("the failure is noted");
        assert_eq!(
            next,
            failed(
                7,
                start,
                at(102),
                LoginMark::for_test(Some("account-a"), Some(3))
            )
        );
        assert_eq!(
            admit(
                Some(&next),
                &LoginMark::for_test(Some("account-a"), Some(3)),
                false,
                at(103)
            ),
            Err(SetupReadDeferred::RetryIn(79))
        );
    }

    #[test]
    fn long_failing_reads_slow_down_but_never_stop() {
        let start = Instant::now();
        let login = signed_in(1);
        let late = start + Duration::from_secs(LONG_FAILURE_SECONDS);
        let last = late - Duration::from_secs(400);
        let many = failed(13, start, last, login.clone());
        assert_eq!(
            admit(Some(&many), &login, false, late),
            Err(SetupReadDeferred::RetryIn(SLOW_RETRY_SECONDS - 400))
        );
        assert_eq!(
            admit(
                Some(&many),
                &login,
                false,
                last + Duration::from_secs(SLOW_RETRY_SECONDS)
            ),
            Ok(())
        );
        // A person's check reads at once.
        assert_eq!(admit(Some(&many), &login, true, late), Ok(()));
    }

    #[test]
    fn an_explicit_check_reads_at_most_once_per_few_seconds() {
        let start = Instant::now();
        let login = signed_in(1);
        let one = failed(6, start, start, login.clone());
        assert_eq!(
            admit(Some(&one), &login, true, start + Duration::from_secs(2)),
            Err(SetupReadDeferred::RetryIn(3))
        );
        assert_eq!(
            admit(
                Some(&one),
                &login,
                true,
                start + Duration::from_secs(EXPLICIT_MIN_GAP_SECONDS)
            ),
            Ok(())
        );
    }

    #[test]
    fn outcomes_count_failures_per_run_and_reset_on_success() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let login = signed_in(1);
        let first = after_read(None, OPERATION, login.clone(), false, start, at(4))
            .expect("a failure is noted");
        assert_eq!(first, failed(1, start, at(4), login.clone()));
        // The read continued the run; its own rewrite of `auth.json` is kept
        // for the next comparison but does not start a new run.
        let second = after_read(
            Some(first.clone()),
            OPERATION,
            signed_in(2),
            false,
            at(14),
            at(18),
        )
        .expect("a second failure is noted");
        assert_eq!(second, failed(2, start, at(18), signed_in(2)));
        // A read that continued no run starts one.
        let other = after_read(None, OPERATION, signed_in(3), false, at(20), at(24))
            .expect("a failure under a new sign-in is noted");
        assert_eq!(other, failed(1, at(20), at(24), signed_in(3)));
        assert_eq!(
            after_read(Some(second), OPERATION, login, true, at(30), at(34)),
            None
        );
    }

    #[test]
    fn one_read_at_a_time_per_home_and_a_success_clears_the_spacing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after the epoch")
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "ottto-codex-setup-gate-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&home).expect("test home");
        std::fs::write(home.join("auth.json"), "{}").expect("test credential");
        let start = Instant::now();
        let reads = Arc::new(AtomicUsize::new(0));

        // A slow failing read holds the home; a second check made meanwhile
        // waits for it and then sees the failure instead of reading again.
        let (inside_tx, inside_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let first = {
            let home = home.clone();
            let reads = Arc::clone(&reads);
            std::thread::spawn(move || {
                let _clock = SetupGateTestClock::frozen_at(start);
                read_waiting_setup_home(&home, OPERATION, false, || {
                    reads.fetch_add(1, Ordering::SeqCst);
                    inside_tx.send(()).expect("signal the read");
                    release_rx.recv().expect("release the read");
                    ((), false)
                })
            })
        };
        inside_rx.recv().expect("the first read runs");
        let second = {
            let home = home.clone();
            let reads = Arc::clone(&reads);
            std::thread::spawn(move || {
                let _clock = SetupGateTestClock::frozen_at(start);
                read_waiting_setup_home(&home, OPERATION, false, || {
                    reads.fetch_add(1, Ordering::SeqCst);
                    ((), false)
                })
            })
        };
        release_tx.send(()).expect("release");
        assert_eq!(first.join().expect("first check"), Ok(()));
        assert_eq!(
            second.join().expect("second check"),
            Err(SetupReadDeferred::RetryIn(SHORT_RETRY_SECONDS))
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // A success clears the run: the next check reads at once.
        let clock = SetupGateTestClock::frozen_at(start);
        clock.set(SHORT_RETRY_SECONDS);
        assert_eq!(
            read_waiting_setup_home(&home, OPERATION, false, || ((), true)),
            Ok(())
        );
        assert_eq!(
            read_waiting_setup_home(&home, OPERATION, false, || {
                reads.fetch_add(1, Ordering::SeqCst);
                ((), false)
            }),
            Ok(())
        );
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        drop(clock);
        let _ = std::fs::remove_dir_all(home);
    }
}
