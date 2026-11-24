//! A Homebrew `ottto-service serve` hands the service over to `Ottto.app`.
//!
//! Ottto has two install variants: the app (DMG, installer or the
//! `ottto-app` cask), which runs the service from its bundle, and the headless
//! Homebrew formula for Macs without the app. Both use launchd label
//! `net.ottto.service`, and `brew services start|restart|run` rewrites that
//! job to the formula's binary without asking. One variant runs per Mac, and
//! the app wins.
//!
//! A launchd-started Homebrew `serve` that finds a valid installed app whose
//! own process runs for this user hands over: before it takes the state lock
//! or opens any state, it writes its pid to `homebrew-handover` in Ottto's
//! support folder and waits. The app sees the marker, takes the job back with
//! `--migrate-owner` (launchd's bootout ends this process), and starts its own
//! service. If the app quits, or has not taken over when the window ends, this
//! copy removes the marker and serves as usual, so the Mac is never left
//! without a collector. The wait itself never exits; if the copy then meets
//! the app's service holding the state lock, the usual held-lock backoff
//! and exit apply, and launchd's restart hands over again.
//!
//! With the app installed but not running, or after the app wrote
//! `homebrew-keeps-serving` (its own takeover failed and it restored this
//! job), the Homebrew copy serves at once and logs why.

use ottto_protocol::InstallOwner;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the app variant lives: the system and the per-user Applications
/// folders, the same places the daemon trusts a Companion from. An app run
/// from Downloads, a disk image or the Trash is not an install.
pub const SYSTEM_APP_PATH: &str = "/Applications/Ottto.app";

/// Written by the app in Ottto's support folder when its takeover of the
/// service failed and it restored the Homebrew job: while it exists, the
/// Homebrew copy serves even though the app runs. Only its existence is read.
pub const KEEP_SERVING_MARKER: &str = "homebrew-keeps-serving";

/// Written by a Homebrew copy that is handing over; holds its pid. The app
/// takes over a running Homebrew job only when this names that job's pid.
pub const HANDOVER_MARKER: &str = "homebrew-handover";

/// How long a handing-over copy waits for the app. Longer than the app's
/// slowest path to a takeover: a status poll while hidden (60 s), its
/// recovery throttle (15 s) and the bootstrap (60 s).
pub const HANDOVER_WINDOW: Duration = Duration::from_secs(180);
const HANDOVER_POLL: Duration = Duration::from_secs(1);

/// What a starting `serve` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeDecision {
    Serve,
    /// A launchd-started Homebrew copy and a valid installed app whose
    /// process runs for this user: wait for the app to take the job over.
    HandOver {
        app: PathBuf,
    },
    /// A valid app is installed but does not run for this user (quit,
    /// another macOS user's, or it asked this copy to keep serving): serve
    /// and log it once.
    ServeBesideApp {
        app: PathBuf,
    },
}

/// What the decision reads, so every branch is testable without the host.
pub struct ServeContext<'a> {
    /// This process's executable.
    pub daemon_exe: Option<&'a Path>,
    /// launchd started this process (parent pid 1). A copy someone runs by
    /// hand keeps today's behaviour.
    pub started_by_launchd: bool,
    /// Candidate app bundles, in order.
    pub apps: Vec<PathBuf>,
    /// The app restored this job after its own takeover failed.
    pub keep_serving: bool,
}

/// Pure decision. `app_is_valid` and `app_runs` are asked only for a
/// launchd-started Homebrew copy; `app_runs` only for valid candidates.
pub fn decide(
    context: &ServeContext<'_>,
    app_is_valid: impl Fn(&Path) -> bool,
    mut app_runs: impl FnMut(&Path) -> bool,
) -> ServeDecision {
    let Some(exe) = context.daemon_exe else {
        return ServeDecision::Serve;
    };
    // `/opt/homebrew/opt/ottto/bin` is a link into the Cellar.
    let exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    if !context.started_by_launchd
        || ottto_core::install_owner_for_path(&exe) != InstallOwner::Homebrew
    {
        return ServeDecision::Serve;
    }
    let valid: Vec<&PathBuf> = context
        .apps
        .iter()
        .filter(|app| app_is_valid(app))
        .collect();
    let Some(first) = valid.first() else {
        return ServeDecision::Serve;
    };
    if !context.keep_serving {
        if let Some(running) = valid.iter().find(|app| app_runs(app)) {
            return ServeDecision::HandOver {
                app: (*running).clone(),
            };
        }
    }
    ServeDecision::ServeBesideApp {
        app: (*first).clone(),
    }
}

/// The decision for this process, checking the real app bundles, this
/// user's processes and the app's keep-serving marker.
pub fn decide_for_this_process() -> ServeDecision {
    let exe = std::env::current_exe().ok();
    let mut apps = vec![PathBuf::from(SYSTEM_APP_PATH)];
    if let Some(home) = std::env::var_os("HOME") {
        apps.push(PathBuf::from(home).join("Applications").join("Ottto.app"));
    }
    #[cfg(unix)]
    let started_by_launchd = unsafe { libc::getppid() } == 1;
    #[cfg(not(unix))]
    let started_by_launchd = false;
    let support = ottto_core::default_support_dir();
    let context = ServeContext {
        daemon_exe: exe.as_deref(),
        started_by_launchd,
        apps,
        keep_serving: support.join(KEEP_SERVING_MARKER).exists(),
    };
    let decision = decide(&context, installed_app_is_valid, app_process_runs);
    // A launchd-started Homebrew copy is the only writer of the handover
    // marker, and launchd runs one per label. A copy that will serve removes
    // any marker an earlier copy left (killed mid-wait, or asleep through the
    // window), so a reused pid can never look like a handover.
    if is_launchd_homebrew_copy(&context) && !matches!(decision, ServeDecision::HandOver { .. }) {
        let _ = std::fs::remove_file(support.join(HANDOVER_MARKER));
    }
    decision
}

fn is_launchd_homebrew_copy(context: &ServeContext<'_>) -> bool {
    context.started_by_launchd
        && context.daemon_exe.is_some_and(|exe| {
            let exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
            ottto_core::install_owner_for_path(&exe) == InstallOwner::Homebrew
        })
}

/// How a handover wait ended without the app taking over (a takeover ends
/// this process instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverEnd {
    /// The app's process went away.
    AppQuit,
    /// The window ended with the app still running but no takeover.
    TimedOut,
    /// The marker could not be written, so the app could never see the
    /// handover: serve at once instead of waiting for nothing.
    MarkerNotWritten,
}

/// Waits while the app runs, up to `window`, polling every `poll`. Pure
/// apart from the injected clock, so every path is testable.
pub fn wait_for_takeover(
    window: Duration,
    poll: Duration,
    mut app_runs: impl FnMut() -> bool,
    mut sleep: impl FnMut(Duration),
) -> HandoverEnd {
    let mut waited = Duration::ZERO;
    while waited < window {
        if !app_runs() {
            return HandoverEnd::AppQuit;
        }
        sleep(poll);
        waited += poll;
    }
    HandoverEnd::TimedOut
}

/// Hands the service over to `app` and returns only if the app did not take
/// it: writes the marker, waits, then removes the marker when it is still
/// this process's. The caller then serves.
pub fn hand_over(app: &Path) -> HandoverEnd {
    let marker = ottto_core::default_support_dir().join(HANDOVER_MARKER);
    let pid = std::process::id().to_string();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(&marker, &pid).is_err() {
        return HandoverEnd::MarkerNotWritten;
    }
    let executable = app.join("Contents").join("MacOS").join("Ottto");
    let end = wait_for_takeover(
        HANDOVER_WINDOW,
        HANDOVER_POLL,
        || app_process_runs_at(&executable),
        std::thread::sleep,
    );
    if std::fs::read_to_string(&marker).is_ok_and(|held| held.trim() == pid) {
        let _ = std::fs::remove_file(&marker);
    }
    end
}

/// Whether this user runs the app at `app`.
fn app_process_runs(app: &Path) -> bool {
    app_process_runs_at(&app.join("Contents").join("MacOS").join("Ottto"))
}

/// A failed process listing counts as not running, so the Homebrew copy
/// serves.
#[cfg(target_os = "macos")]
fn app_process_runs_at(executable: &Path) -> bool {
    crate::local_state_sweep::same_user_process_runs(executable).unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn app_process_runs_at(_executable: &Path) -> bool {
    false
}

/// The release gate's check of the shipped decision against a packaged app:
/// decide as a launchd-started Homebrew copy whose user runs that app. The app
/// check is the real one (bundled service, version, this build's code
/// requirement), so a stable release whose app would not take the headless
/// copy's handover fails the gate.
pub fn release_check(app: &Path) -> serde_json::Value {
    let decision = decide(
        &ServeContext {
            daemon_exe: Some(Path::new(
                "/opt/homebrew/Cellar/ottto/release-check/bin/ottto-service",
            )),
            started_by_launchd: true,
            apps: vec![app.to_path_buf()],
            keep_serving: false,
        },
        installed_app_is_valid,
        |_| true,
    );
    serde_json::json!({
        "decision": match decision {
            ServeDecision::Serve | ServeDecision::ServeBesideApp { .. } => "serve",
            ServeDecision::HandOver { .. } => "step_aside",
        },
        "app": app.display().to_string(),
    })
}

/// The line a Homebrew copy writes when it serves beside an installed app.
pub fn serve_beside_app_message(app: &Path) -> String {
    format!(
        "ottto-service: {} is installed but not running for this user, or it asked this copy to keep \
         serving; this Homebrew copy serves. One Ottto runs per Mac: in Ottto.app choose Move service \
         to the app, or uninstall the app to keep this headless install.",
        app.display()
    )
}

/// The line a Homebrew copy writes when it starts handing over.
pub fn hand_over_message(app: &Path) -> String {
    format!(
        "ottto-service: {} is running for this user, and the app runs this Mac's Ottto service. \
         This Homebrew copy is handing over and waits up to {} s for the app to take the service back; \
         if the app quits or does not take over, this copy serves. Remove it with `brew uninstall ottto`. \
         To run Ottto headless instead, uninstall the app first, then run `brew services restart ottto`.",
        app.display(),
        HANDOVER_WINDOW.as_secs()
    )
}

/// The line a Homebrew copy writes when a handover ended without a takeover.
pub fn hand_over_ended_message(end: HandoverEnd) -> &'static str {
    match end {
        HandoverEnd::AppQuit => {
            "ottto-service: Ottto.app quit before taking the service over; this Homebrew copy serves."
        }
        HandoverEnd::TimedOut => {
            "ottto-service: Ottto.app did not take the service over in time; this Homebrew copy serves."
        }
        HandoverEnd::MarkerNotWritten => {
            "ottto-service: could not write the handover marker in Ottto's support folder; this Homebrew copy serves."
        }
    }
}

/// The app counts when its bundled service is an executable file, its
/// version is at least this copy's, and the bundle satisfies the code
/// requirement this daemon demands of a token-less Companion (the Developer
/// ID team for a release-signed daemon). A half-written bundle during a
/// Sparkle update, a foreign or unsigned copy, an older app, or a build with
/// Companion trust disabled fails, and the Homebrew copy serves.
#[cfg(target_os = "macos")]
fn installed_app_is_valid(app: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let helper = app.join("Contents").join("Helpers").join("ottto-service");
    if !std::fs::metadata(&helper)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    {
        return false;
    }
    // An app older than this copy may predate taking a Homebrew job over (the
    // formula can reach a Mac before Sparkle updates the app).
    let Some(app_version) = crate::app_bundle_version::companion_bundle_version(app) else {
        return false;
    };
    if !version_at_least(&app_version, &ottto_core::compiled_release_version()) {
        return false;
    }
    let Some(requirement) = crate::control::installed_companion_code_requirement() else {
        return false;
    };
    bundle_satisfies_requirement(app, &requirement)
}

/// `codesign --verify --strict` of the bundle at `app` against `requirement`, within 10 s.
#[cfg(target_os = "macos")]
pub(crate) fn bundle_satisfies_requirement(app: &Path, requirement: &str) -> bool {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    const CODESIGN_TIMEOUT: Duration = Duration::from_secs(10);

    // A leading `=` makes codesign read the argument as requirement text.
    let Ok(mut child) = Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg("--strict")
        .arg("-R")
        .arg(format!("={requirement}"))
        .arg(app)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + CODESIGN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn installed_app_is_valid(_app: &Path) -> bool {
    false
}

/// `version >= minimum` for dotted numeric release versions ("0.1.262").
/// Anything that does not parse is not at least the minimum.
pub fn version_at_least(version: &str, minimum: &str) -> bool {
    fn parts(value: &str) -> Option<Vec<u64>> {
        value
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
            .filter(|parts| !parts.is_empty())
    }
    match (parts(version), parts(minimum)) {
        (Some(version), Some(minimum)) => version >= minimum,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const USER_APP: &str = "/Users/me/Applications/Ottto.app";

    fn context(exe: &str, started_by_launchd: bool, keep_serving: bool) -> ServeContext<'_> {
        ServeContext {
            daemon_exe: Some(Path::new(exe)),
            started_by_launchd,
            apps: vec![PathBuf::from(SYSTEM_APP_PATH), PathBuf::from(USER_APP)],
            keep_serving,
        }
    }

    fn hand_over_to(app: &str) -> ServeDecision {
        ServeDecision::HandOver {
            app: PathBuf::from(app),
        }
    }

    fn beside(app: &str) -> ServeDecision {
        ServeDecision::ServeBesideApp {
            app: PathBuf::from(app),
        }
    }

    /// [behaviour] A launchd-started Homebrew copy hands over to a valid app
    /// that runs for this user, any candidate; it serves beside a quit app,
    /// another user's app, or after the app asked it to keep serving; a
    /// hand-started copy or one with no valid app just serves.
    #[test]
    fn only_a_launchd_homebrew_copy_hands_over_to_a_running_valid_app() {
        for exe in [
            "/opt/homebrew/Cellar/ottto/0.1.262/bin/ottto-service",
            "/opt/homebrew/opt/ottto/bin/ottto-service",
            "/usr/local/Cellar/ottto/0.1.262/bin/ottto-service",
        ] {
            let ctx = context(exe, true, false);
            assert_eq!(
                decide(&ctx, |_| true, |_| true),
                hand_over_to(SYSTEM_APP_PATH),
                "{exe}"
            );
            assert_eq!(
                decide(&ctx, |_| true, |app| app.starts_with("/Users/me")),
                hand_over_to(USER_APP),
                "{exe}: the running copy wins over a quit first candidate"
            );
            assert_eq!(
                decide(&ctx, |_| false, |_| true),
                ServeDecision::Serve,
                "{exe}"
            );
            assert_eq!(
                decide(&ctx, |_| true, |_| false),
                beside(SYSTEM_APP_PATH),
                "{exe}: app quit, or another user's app"
            );
            assert_eq!(
                decide(&context(exe, true, true), |_| true, |_| true),
                beside(SYSTEM_APP_PATH),
                "{exe}: the app restored this copy"
            );
            assert_eq!(
                decide(&context(exe, false, false), |_| true, |_| true),
                ServeDecision::Serve,
                "{exe}: started by hand"
            );
        }
        for exe in [
            "/Applications/Ottto.app/Contents/Helpers/ottto-service",
            "/Users/me/Applications/Ottto.app/Contents/Helpers/ottto-service",
            "/Users/me/.ottto/bin/ottto-service",
            "/Users/me/src/ottto/target/release/ottto-service",
        ] {
            let checked = Cell::new(false);
            assert_eq!(
                decide(
                    &context(exe, true, false),
                    |_| {
                        checked.set(true);
                        true
                    },
                    |_| true
                ),
                ServeDecision::Serve,
                "{exe}"
            );
            assert!(!checked.get(), "{exe} must not check the app");
        }
        let no_exe = ServeContext {
            daemon_exe: None,
            started_by_launchd: true,
            apps: vec![PathBuf::from(SYSTEM_APP_PATH)],
            keep_serving: false,
        };
        assert_eq!(decide(&no_exe, |_| true, |_| true), ServeDecision::Serve);
    }

    /// [behaviour] Only a launchd-started Homebrew copy owns the handover
    /// marker (and removes a leftover one when it serves).
    #[test]
    fn only_a_launchd_homebrew_copy_owns_the_handover_marker() {
        let brew = "/opt/homebrew/Cellar/ottto/0.1.262/bin/ottto-service";
        assert!(is_launchd_homebrew_copy(&context(brew, true, false)));
        assert!(!is_launchd_homebrew_copy(&context(brew, false, false)));
        assert!(!is_launchd_homebrew_copy(&context(
            "/Applications/Ottto.app/Contents/Helpers/ottto-service",
            true,
            false
        )));
    }

    /// [behaviour] The handover wait ends at once when the app quits, and
    /// after the window when the app runs but never takes over; it never
    /// waits past the window.
    #[test]
    fn handover_wait_ends_when_the_app_quits_or_the_window_closes() {
        let slept = Cell::new(Duration::ZERO);
        let polls = Cell::new(0_u32);
        let end = wait_for_takeover(
            Duration::from_secs(5),
            Duration::from_secs(1),
            || {
                polls.set(polls.get() + 1);
                polls.get() < 3
            },
            |step| slept.set(slept.get() + step),
        );
        assert_eq!(end, HandoverEnd::AppQuit);
        assert_eq!(slept.get(), Duration::from_secs(2));

        slept.set(Duration::ZERO);
        let end = wait_for_takeover(
            Duration::from_secs(5),
            Duration::from_secs(1),
            || true,
            |step| slept.set(slept.get() + step),
        );
        assert_eq!(end, HandoverEnd::TimedOut);
        assert_eq!(slept.get(), Duration::from_secs(5));
        assert!(HANDOVER_WINDOW > Duration::from_secs(60 + 15 + 60));
    }

    /// [behaviour] The app must be at least the Homebrew copy's version;
    /// unparsable versions never count.
    #[test]
    fn the_app_must_be_at_least_this_version() {
        assert!(version_at_least("0.1.262", "0.1.262"));
        assert!(version_at_least("0.1.263", "0.1.262"));
        assert!(version_at_least("0.2.0", "0.1.262"));
        assert!(!version_at_least("0.1.261", "0.1.262"));
        assert!(!version_at_least("0.1.262-dev", "0.1.262"));
        assert!(!version_at_least("0.1.262", "unknown"));
        assert!(!version_at_least("", "0.1.262"));
    }

    /// [behaviour] The release check serves for an app that is not there.
    #[test]
    fn release_check_serves_for_a_missing_app() {
        let report = release_check(Path::new("/nonexistent/Ottto.app"));
        assert_eq!(report["decision"], "serve");
        assert_eq!(report["app"], "/nonexistent/Ottto.app");
    }

    /// [behaviour] The log lines name the app, the bounded wait, the
    /// fallback and both fixes.
    #[test]
    fn messages_name_the_wait_the_fallback_and_both_fixes() {
        let app = Path::new(SYSTEM_APP_PATH);
        let hand_over = hand_over_message(app);
        for part in [
            "/Applications/Ottto.app",
            "180 s",
            "this copy serves",
            "brew uninstall ottto",
            "uninstall the app first",
        ] {
            assert!(hand_over.contains(part), "{part}: {hand_over}");
        }
        let beside = serve_beside_app_message(app);
        for part in [
            "not running for this user",
            "Move service to the app",
            "uninstall the app",
        ] {
            assert!(beside.contains(part), "{part}: {beside}");
        }
        assert!(hand_over_ended_message(HandoverEnd::AppQuit).contains("serves"));
        assert!(hand_over_ended_message(HandoverEnd::TimedOut).contains("serves"));
        assert!(hand_over_ended_message(HandoverEnd::MarkerNotWritten).contains("serves"));
    }

    /// [behaviour] Off macOS there is no app, so a Homebrew copy serves.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_no_app_counts() {
        assert!(!installed_app_is_valid(Path::new(SYSTEM_APP_PATH)));
    }

    /// [behaviour] A bundle without an executable bundled service never
    /// counts, before any signature check.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_app_without_an_executable_bundled_service_does_not_count() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "ottto-step-aside-{}-{}",
            std::process::id(),
            line!()
        ));
        let app = root.join("Ottto.app");
        let helpers = app.join("Contents").join("Helpers");
        std::fs::create_dir_all(&helpers).unwrap();
        assert!(!installed_app_is_valid(&app));
        let helper = helpers.join("ottto-service");
        std::fs::write(&helper, b"").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!installed_app_is_valid(&app));
        assert!(!installed_app_is_valid(&root.join("missing.app")));
        let _ = std::fs::remove_dir_all(&root);
    }
}
