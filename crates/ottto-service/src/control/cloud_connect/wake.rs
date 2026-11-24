//! Waking the Mac app's signer loop: when a request is queued and no app said hello recently, the
//! app bundle this service runs from is checked against the release app requirement and opened in
//! the background with an unauthenticated URL hint. Signer requests travel over verified XPC.

/// An unauthenticated hint to start the app's signer loop. The app polls over verified XPC.
#[cfg(target_os = "macos")]
const SIGN_URL: &str = "ottto://cloud/sign";

/// Opens the app this service belongs to, off the caller's thread. Does nothing when the bundle
/// fails `app_requirement`.
#[cfg(target_os = "macos")]
pub(super) fn wake_app(app_requirement: &str) {
    let app_requirement = app_requirement.to_string();
    let spawned = std::thread::Builder::new()
        .name("ottto-signer-wake".to_string())
        .spawn(move || {
            let Some(app) = std::env::current_exe()
                .ok()
                .and_then(|executable| app_bundle_of(&executable))
            else {
                eprintln!("ottto-service: signer wake skipped: this service is not inside an app");
                return;
            };
            if !crate::homebrew_step_aside::bundle_satisfies_requirement(&app, &app_requirement) {
                eprintln!(
                    "ottto-service: signer wake skipped: the app beside this service fails its code requirement"
                );
                return;
            }
            // `-a <path>`, never `-b`: a bundle id could name another copy of the app.
            let opened = std::process::Command::new("/usr/bin/open")
                .arg("-g")
                .arg("-a")
                .arg(&app)
                .arg(SIGN_URL)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if !opened.is_ok_and(|status| status.success()) {
                eprintln!("ottto-service: signer wake could not open the app");
            }
        });
    if spawned.is_err() {
        eprintln!("ottto-service: signer wake could not start");
    }
}

#[cfg(not(target_os = "macos"))]
pub(super) fn wake_app(_app_requirement: &str) {}

/// `<App>.app` for a service at `<App>.app/Contents/Helpers/<service>`.
#[cfg(any(target_os = "macos", test))]
pub(super) fn app_bundle_of(executable: &std::path::Path) -> Option<std::path::PathBuf> {
    let contents = executable.parent()?.parent()?;
    let app = contents.parent()?;
    (executable.parent()?.file_name()? == "Helpers"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then(|| app.to_path_buf())
}
