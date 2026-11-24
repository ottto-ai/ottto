//! peer for local control.

use crate::control::LocalClientKind;
use crate::control::LocalControlRequest;
#[cfg(target_os = "macos")]
use crate::control::Ordering;
#[cfg(target_os = "macos")]
use crate::control::Path;
#[cfg(target_os = "macos")]
use crate::control::PathBuf;
#[cfg(target_os = "macos")]
use crate::control::OTTTO_COMPANION_DEFAULT_TEAM_ID;

#[cfg(target_os = "macos")]
const OTTTO_COMPANION_BUNDLE_IDENTIFIER: &str = "net.ottto.Companion";

#[derive(Debug, Clone, Default)]
pub struct LocalClientPeer {
    pub pid: Option<u32>,
    /// Effective uid of the connecting peer, when the transport can supply it
    /// (`getpeereid` for the unix socket, `xpc_connection_get_euid` for XPC).
    /// Used as a connection-level gate: a peer running as a different uid than
    /// the daemon is never trusted, which keeps the Mach service at least as
    /// restrictive as the 0600 unix socket and closes the cross-uid attack
    /// surface around the (recyclable) PID-based companion check.
    pub euid: Option<u32>,
    #[cfg(test)]
    pub(super) trusted_for_tests: bool,
}

impl LocalClientPeer {
    // NOTE: there is intentionally no `from_pid(pid)` constructor. A peer must
    // always carry its effective uid so the euid gate can run; a euid-less peer
    // would be fail-closed for companion trust anyway. Both transports build
    // peers via `from_pid_and_euid` (unix_socket: getpeereid, xpc: shim euid).
    pub fn from_pid_and_euid(pid: Option<u32>, euid: Option<u32>) -> Self {
        Self {
            pid,
            euid,
            #[cfg(test)]
            trusted_for_tests: false,
        }
    }

    #[cfg(test)]
    pub(super) fn trusted_for_tests() -> Self {
        Self {
            pid: None,
            euid: None,
            trusted_for_tests: true,
        }
    }

    /// True when the peer's effective uid is known and equals the daemon's
    /// effective uid. Returns `false` if the transport could not supply the
    /// peer euid (fail-closed): a peer we cannot attribute to our own uid must
    /// not be trusted for the token-less companion authorization.
    pub(super) fn euid_matches_daemon(&self) -> bool {
        match self.euid {
            Some(peer_euid) => peer_euid == daemon_effective_uid(),
            None => false,
        }
    }
}

/// The effective uid of the running daemon process.
#[cfg(unix)]
pub(super) fn daemon_effective_uid() -> u32 {
    // SAFETY: geteuid() is always-successful and has no preconditions.
    // `libc::uid_t` is `u32` on every supported unix target.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub(super) fn daemon_effective_uid() -> u32 {
    u32::MAX
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RequestAuthorization {
    Token(String),
    TrustedCompanionApp,
    /// The daemon's own source verification, never built from a request. It
    /// takes the trusted path only at the checks that verification reaches
    /// and is refused at every other caller check.
    DaemonInternal,
    Untrusted,
}

pub(super) fn request_authorization(
    request: &LocalControlRequest,
    peer: Option<&LocalClientPeer>,
) -> RequestAuthorization {
    if let Some(token) = &request.token {
        return RequestAuthorization::Token(token.clone());
    }
    if request.client_kind == Some(LocalClientKind::CompanionApp) && companion_peer_is_trusted(peer)
    {
        return RequestAuthorization::TrustedCompanionApp;
    }
    RequestAuthorization::Untrusted
}

pub(super) fn companion_peer_is_trusted(peer: Option<&LocalClientPeer>) -> bool {
    let Some(peer) = peer else {
        return false;
    };

    #[cfg(test)]
    if peer.trusted_for_tests {
        return true;
    }

    // Connection-level peer gate (defense against PID-reuse TOCTOU and the
    // missing XPC credential check): the token-less companion authorization is
    // only ever granted to a peer that runs as the daemon's own effective uid.
    // This is evaluated with supported, non-spoofable kernel-provided
    // credentials (`getpeereid` / `xpc_connection_get_euid`) before the
    // recyclable-PID-based code-signing check runs.
    if !peer.euid_matches_daemon() {
        return false;
    }

    let Some(pid) = peer.pid else {
        return false;
    };

    crate::local_resource_diagnostics::trust_check(|| trusted_companion_pid(pid))
}

#[cfg(target_os = "macos")]
fn trusted_companion_pid(pid: u32) -> bool {
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    // SECURITY / KNOWN-LIMITATION (PID-reuse TOCTOU):
    //
    // `kSecGuestAttributePid` is the Apple-documented-insecure way to identify a
    // guest: a PID is recyclable, so between the kernel handing us the peer PID
    // and this `copy_guest_with_attribues` call the original process could exit
    // and its PID be reused by an attacker's process. The robust fix is to
    // identify the guest by its `audit_token_t` instead of its PID.
    //
    // The dependency surface to do that is already available:
    //   * `security_framework::os::macos::code_signing::GuestAttributes` exposes
    //     `set_audit_token(token: CFDataRef)` (security-framework 3.7), which
    //     maps to `kSecGuestAttributeAudit` — the non-recyclable identifier.
    //   * The peer audit token is obtainable per transport:
    //       - unix socket: `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` (documented
    //         in <sys/un.h>) yields the 32-byte `audit_token_t`.
    //       - XPC: `xpc_connection_get_audit_token(peer, &token)` — present in
    //         libxpc but NOT declared in the public SDK headers.
    //
    // It is NOT wired up here yet for two reasons that, given this finding's
    // low/medium severity and the impossibility of validating against the real
    // signed Companion in this environment, make shipping it now riskier than
    // the bug:
    //   1. `set_audit_token` takes a `core_foundation::data::CFDataRef`, which
    //      would require adding `core-foundation` as a *direct* dependency of
    //      ottto-service (it is currently only transitive) and constructing the
    //      CFData/audit-token FFI correctly.
    //   2. The XPC capture relies on a private (undeclared) libxpc symbol.
    // A wrong move here would break legitimate Companion auth, a worse
    // regression than this hard-to-exploit, same-uid bug.
    //
    // The shipped mitigations are (a) the connection-level euid gate in
    // `companion_peer_is_trusted`, which requires the peer to run as the
    // daemon's own uid before this PID check is even reached — closing the
    // cross-uid attack surface — and (b) the Developer ID code requirement
    // below, which is now enforced by default (see
    // `OTTTO_COMPANION_DEFAULT_TEAM_ID`). With (b) in place, winning the PID
    // race is no longer enough: whatever process ends up holding the recycled
    // PID must ALSO live at a trusted Companion path and carry a valid
    // signature from the Ottto Developer ID team — i.e. it must be the real
    // Companion. That leaves the residual risk at "a same-uid attacker
    // substitutes one legitimately signed Ottto build for another", against a
    // principal who can already read the 0600 control token.
    //
    // FOLLOW-UP (unchanged, still open): implement the audit-token upgrade
    // above and validate it on-device against the signed Companion before a
    // release. It remains deliberately unshipped — the two blockers above are
    // unchanged, and the payoff shrank now that the signature check runs
    // unconditionally.
    let mut attrs = GuestAttributes::new();
    attrs.set_pid(pid as libc::pid_t);
    let Ok(code) = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE) else {
        return false;
    };

    let Ok(path) = code.path(Flags::NONE).and_then(|url| {
        url.to_path()
            .ok_or_else(|| security_framework::base::Error::from_code(-1))
    }) else {
        return false;
    };

    if !trusted_companion_paths()
        .iter()
        .any(|trusted_path| same_path(trusted_path, &path))
    {
        return false;
    }

    // Fail closed: a build with no baked-in team id and no explicit override
    // grants no token-less Companion trust at all. Path-only trust — the old
    // behaviour whenever neither env var was set, which was every production
    // install — is no longer reachable.
    let requirement_text = match companion_code_requirement() {
        CompanionCodeRequirement::Enforced(requirement_text) => requirement_text,
        CompanionCodeRequirement::Disabled => return false,
    };
    let Ok(requirement) = requirement_text.parse::<SecRequirement>() else {
        log_companion_code_requirement_denial(&path, "code requirement is not valid csreq syntax");
        return false;
    };
    if code.check_validity(Flags::NONE, &requirement).is_ok() {
        return true;
    }
    log_companion_code_requirement_denial(&path, "signature does not satisfy the code requirement");
    false
}

/// Log, at most once per daemon run, that something at a trusted Companion path
/// failed the code requirement.
///
/// The Companion never sends a control token — token-less trust is its only
/// auth path — so a signature failure makes the app stop working entirely. Log
/// it or the only symptom is an opaque `local_client_not_trusted`. The most
/// likely cause by far is an internal ad-hoc-signed dev build, so the message
/// names the dev override. Once-per-process because the Companion polls: a
/// broken setup would otherwise fill the daemon error log.
#[cfg(target_os = "macos")]
fn log_companion_code_requirement_denial(path: &Path, reason: &str) {
    // Imported here rather than at module scope: everything in this file that
    // uses it is macOS-only.
    use std::sync::atomic::AtomicBool;

    static LOGGED: AtomicBool = AtomicBool::new(false);
    if LOGGED.swap(true, Ordering::Relaxed) {
        return;
    }
    let expectation = if daemon_is_release_signed() {
        "this daemon is a signed release build, so the Companion must carry the \
         same Developer ID; running a locally built Companion against it needs \
         OTTTO_COMPANION_CODE_REQUIREMENT (scripts/macos_dev_install.sh \
         --trust-dev-companion writes it)"
    } else {
        "this daemon is an internal build, so the Companion must at least be \
         signed (ad-hoc is enough) with that bundle identifier"
    };
    eprintln!(
        "ottto-service: refused token-less Companion trust for {}: {reason}. {expectation}.",
        path.display()
    );
}

#[cfg(not(target_os = "macos"))]
fn trusted_companion_pid(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn trusted_companion_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(path) = std::env::var("OTTTO_COMPANION_TRUSTED_PATH") {
        push_companion_path_variants(&mut paths, PathBuf::from(path));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(contents_dir) = current_exe
            .parent()
            .and_then(|helpers_dir| helpers_dir.parent())
        {
            paths.push(contents_dir.join("MacOS").join("Ottto"));
            if let Some(app_bundle) = contents_dir.parent() {
                paths.push(app_bundle.to_path_buf());
            }
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        push_companion_path_variants(
            &mut paths,
            PathBuf::from(home).join("Applications").join("Ottto.app"),
        );
    }

    push_companion_path_variants(&mut paths, PathBuf::from("/Applications").join("Ottto.app"));

    paths
}

#[cfg(target_os = "macos")]
fn push_companion_path_variants(paths: &mut Vec<PathBuf>, path: PathBuf) {
    paths.push(path.clone());
    if path.extension().and_then(|extension| extension.to_str()) == Some("app") {
        paths.push(path.join("Contents").join("MacOS").join("Ottto"));
    }
}

#[cfg(target_os = "macos")]
fn same_path(expected: &Path, actual: &Path) -> bool {
    let expected = expected
        .canonicalize()
        .unwrap_or_else(|_| expected.to_path_buf());
    let actual = actual
        .canonicalize()
        .unwrap_or_else(|_| actual.to_path_buf());
    expected == actual
}

/// Outcome of resolving the code requirement a token-less Companion peer must
/// satisfy. There is deliberately no "trust without checking the signature"
/// variant: the only two outcomes are "check this requirement" and "grant no
/// token-less trust".
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CompanionCodeRequirement {
    /// The peer's code signature must satisfy this requirement string.
    Enforced(String),
    /// Token-less Companion trust is unavailable in this build/configuration.
    Disabled,
}

/// The code requirement enforced against a token-less Companion peer.
///
/// See [`resolve_companion_code_requirement`] for the precedence. The two env
/// vars can only be set by something already running as the daemon's uid (the
/// LaunchAgent plist and the daemon's own environment are user-owned), which is
/// the same principal that can already read the 0600 control token — so they
/// weaken nothing that was not already reachable, and they exist so QA can
/// point a release daemon at a locally built Companion.
#[cfg(target_os = "macos")]
pub(super) fn companion_code_requirement() -> CompanionCodeRequirement {
    resolve_companion_code_requirement(
        std::env::var("OTTTO_COMPANION_CODE_REQUIREMENT")
            .ok()
            .as_deref(),
        std::env::var("OTTTO_COMPANION_TEAM_ID").ok().as_deref(),
        OTTTO_COMPANION_DEFAULT_TEAM_ID,
        daemon_is_release_signed(),
    )
}

/// The code requirement an installed `Ottto.app` must satisfy before a
/// Homebrew `serve` steps aside for it (`crate::homebrew_step_aside`): the
/// same requirement this daemon demands of a token-less Companion peer, so the
/// Homebrew copy only yields to an app whose daemon it would itself trust.
/// `None` when token-less Companion trust is disabled (a fork's build).
#[cfg(target_os = "macos")]
pub(crate) fn installed_companion_code_requirement() -> Option<String> {
    match companion_code_requirement() {
        CompanionCodeRequirement::Enforced(requirement) => Some(requirement),
        CompanionCodeRequirement::Disabled => None,
    }
}

/// Pure resolution of [`companion_code_requirement`], split out so every branch
/// is testable without mutating process env, re-signing this binary, or
/// rebuilding with a different baked-in team id.
///
/// Precedence:
///   1. `OTTTO_COMPANION_CODE_REQUIREMENT` — a full requirement string. Lets QA
///      run a release daemon against a locally built Companion.
///   2. `OTTTO_COMPANION_TEAM_ID` — a team id to build the standard requirement
///      from.
///   3. An empty baked-in team id — a fork opting out. Fails closed: no
///      token-less trust at all.
///   4. `daemon_is_release_signed`: this daemon is itself signed by the baked-in
///      team, so it is a customer artifact and the Companion beside it must be
///      one too. Developer ID enforced.
///   5. Otherwise this is an internal build (`macos_package.sh` ad-hoc seals
///      dev/preview/RC artifacts). An ad-hoc signature carries no team, so
///      demanding one would break every internal tester on an install where
///      *both* halves are ad-hoc. Fall back to the bundle identifier alone.
///
/// Be honest about rule 5: on Apple Silicon every running process already
/// carries at least an ad-hoc signature, and whoever can place a bundle at a
/// trusted path also writes its `Info.plist`, so the identifier is not a
/// boundary against a deliberate attacker. Internal builds keep the posture
/// they have today — same-uid only — and the real boundary lands where
/// customers are. Tightening rule 5 further would mean pinning a cdhash the
/// daemon cannot know for an app it does not ship with.
///
/// Rule 4 vs 5 is what keeps this from being a flag people must remember: the
/// daemon and the Companion beside it are built and signed by the same pipeline
/// run, so the daemon's own signature already says which kind of install this
/// is. Nothing in the installers, the LaunchAgent, or the app's own re-bootstrap
/// has to carry the decision — which matters, because
/// `LocalServiceRegistrar.runBundledServiceBootstrap` in the Companion rewrites
/// the LaunchAgent on refresh and would drop any env override written there.
///
/// Blank (empty or whitespace-only) env values are treated as unset and fall
/// through, so an accidentally-empty var cannot silently change the outcome.
#[cfg(target_os = "macos")]
pub(super) fn resolve_companion_code_requirement(
    requirement_override: Option<&str>,
    team_id_override: Option<&str>,
    default_team_id: &str,
    daemon_is_release_signed: bool,
) -> CompanionCodeRequirement {
    fn present(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| !value.is_empty())
    }

    if let Some(requirement) = present(requirement_override) {
        return CompanionCodeRequirement::Enforced(requirement.to_string());
    }
    if let Some(team_id) = present(team_id_override) {
        return CompanionCodeRequirement::Enforced(companion_team_code_requirement(team_id));
    }
    let Some(default_team_id) = present(Some(default_team_id)) else {
        return CompanionCodeRequirement::Disabled;
    };
    if daemon_is_release_signed {
        return CompanionCodeRequirement::Enforced(companion_team_code_requirement(
            default_team_id,
        ));
    }
    CompanionCodeRequirement::Enforced(companion_identity_code_requirement())
}

/// Requirement fragment pinning a signature to a Developer ID certificate
/// issued by Apple to `team_id`.
///
/// SECURITY: all three clauses matter, and `subject.OU` alone is the trap. A
/// code requirement only checks the fields it names, so
/// `certificate leaf[subject.OU] = "TEAM"` on its own is satisfied by ANY
/// certificate carrying that OU — including a self-signed one a same-uid
/// attacker mints, since the team id is public. `anchor apple generic` is what
/// forces the chain back to Apple, and the leaf marker OID
/// `1.2.840.113635.100.6.1.13` is what makes it Developer ID rather than a
/// development or Mac App Store certificate from the same team.
///
/// This is exactly the shape of Apple's own generated designated requirement;
/// `codesign -d -r- /Applications/Ottto.app` prints it.
#[cfg(target_os = "macos")]
fn developer_id_requirement_fragment(team_id: &str) -> String {
    format!(
        "anchor apple generic \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] \
         and certificate leaf[subject.OU] = \"{team_id}\""
    )
}

/// The Developer ID requirement string for `team_id`: the Companion bundle
/// identifier, signed by a Developer ID certificate Apple issued to that team.
#[cfg(target_os = "macos")]
pub(super) fn companion_team_code_requirement(team_id: &str) -> String {
    format!(
        "identifier \"{OTTTO_COMPANION_BUNDLE_IDENTIFIER}\" and {}",
        developer_id_requirement_fragment(team_id)
    )
}

/// The identifier-only requirement used by internal builds, where no Apple team
/// is available to assert. Satisfied by an ad-hoc-signed Companion; not
/// satisfied by an unsigned or differently-identified binary.
#[cfg(target_os = "macos")]
pub(super) fn companion_identity_code_requirement() -> String {
    format!("identifier \"{OTTTO_COMPANION_BUNDLE_IDENTIFIER}\"")
}

/// The signing identifier of `ottto-service`: the packager signs it without `--identifier`, so
/// codesign takes its file name. The Mac app pins it, with the team, to trust the signer channel.
#[cfg(target_os = "macos")]
const OTTTO_SERVICE_SIGNING_IDENTIFIER: &str = "ottto-service";

/// The release `ottto-service`: its identifier, signed by a Developer ID certificate Apple issued
/// to `team_id`. The Mac app requires it of the signer channel, and this service requires it of
/// itself before it opens that channel.
#[cfg(target_os = "macos")]
pub(super) fn service_team_code_requirement(team_id: &str) -> String {
    format!(
        "identifier \"{OTTTO_SERVICE_SIGNING_IDENTIFIER}\" and {}",
        developer_id_requirement_fragment(team_id)
    )
}

/// Whether this running process satisfies `requirement`.
#[cfg(target_os = "macos")]
pub(super) fn this_process_satisfies(requirement: &str) -> bool {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    let Ok(requirement) = requirement.parse::<SecRequirement>() else {
        return false;
    };
    SecCode::for_self(Flags::NONE)
        .is_ok_and(|code| code.check_validity(Flags::NONE, &requirement).is_ok())
}

/// The requirement this daemon's own code must satisfy for the install to count
/// as a customer artifact: a Developer ID certificate Apple issued to the
/// baked-in team. No `identifier` clause — the daemon ships under several
/// (`ottto-service` standalone, and bundled inside the app).
#[cfg(target_os = "macos")]
pub(super) fn daemon_release_code_requirement(team_id: &str) -> String {
    developer_id_requirement_fragment(team_id)
}

/// Whether this running `ottto-service` is itself signed by the baked-in team.
///
/// The stable release gate signs every customer artifact with Developer ID;
/// `macos_package.sh` ad-hoc seals dev, preview, and RC builds. So this is a
/// reliable "am I a customer artifact?" test, and it is a property of the build
/// rather than of anything a peer supplies.
///
/// An attacker who could make this return `false` by tampering with the daemon
/// binary already has write access to the daemon and does not need to bother.
///
/// Evaluated once: it runs on every token-less request and a process cannot
/// re-sign itself while running.
#[cfg(target_os = "macos")]
pub(super) fn daemon_is_release_signed() -> bool {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
    use std::sync::OnceLock;

    static RELEASE_SIGNED: OnceLock<bool> = OnceLock::new();
    *RELEASE_SIGNED.get_or_init(|| {
        let team_id = OTTTO_COMPANION_DEFAULT_TEAM_ID.trim();
        if team_id.is_empty() {
            return false;
        }
        let Ok(requirement) = daemon_release_code_requirement(team_id).parse::<SecRequirement>()
        else {
            return false;
        };
        let Ok(code) = SecCode::for_self(Flags::NONE) else {
            return false;
        };
        code.check_validity(Flags::NONE, &requirement).is_ok()
    })
}
