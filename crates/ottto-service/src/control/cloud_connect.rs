//! Cloud connect on this Mac, service side: the signer channel the Ottto app signs through (start
//! conditions and entry points), its in-memory sign queue and wake, the cloud-key server calls,
//! and the CloudFormation template digest check.
//!
//! The channel opens only in a release-signed `ottto-service` the app installed, with no
//! Companion trust override set. Nothing here is persisted.

mod agent;
pub(super) use agent::dispatch as dispatch_agent;

mod queue;
mod server;
mod signer;
mod template;
mod wake;
mod wire;

#[cfg(test)]
mod tests;

pub use queue::SignKind;
pub use queue::SignOutcome;
pub use queue::SignQueue;
pub use queue::SignQueueError;
pub use queue::MAX_LIVE_SIGN_REQUESTS;
pub use template::verified_template_url;
pub use template::TemplateError;
pub use template::TemplatePinId;

use crate::LocalDaemon;
use ottto_protocol::InstallOwner;
use std::sync::OnceLock;

static SIGN_QUEUE: OnceLock<SignQueue> = OnceLock::new();
static CONNECTIONS: OnceLock<signer::Connections> = OnceLock::new();
/// Set once the signer listener is up: the requirement its peers (the release app) must meet.
static SIGNER_PEER_REQUIREMENT: OnceLock<String> = OnceLock::new();

/// Why this service opens no signer channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerOff {
    /// A Homebrew, hosted-installer or dev service.
    NotAppInstalled,
    /// An `OTTTO_COMPANION_*` trust override is set.
    CompanionOverride,
    /// This build names no Developer ID team.
    NoReleaseTeam,
    /// This process is not the release-signed `ottto-service`.
    NotReleaseService,
}

impl SignerOff {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotAppInstalled => "this service was not installed by the Ottto app",
            Self::CompanionOverride => "a Companion trust override is set",
            Self::NoReleaseTeam => "this build names no Developer ID team",
            Self::NotReleaseService => "this service is not the release-signed ottto-service",
        }
    }
}

struct SignerStartFacts {
    owner: InstallOwner,
    companion_override: bool,
    release_team: bool,
    release_service: bool,
}

fn resolve_signer_start(facts: &SignerStartFacts) -> Result<(), SignerOff> {
    if facts.owner != InstallOwner::AppBundle {
        return Err(SignerOff::NotAppInstalled);
    }
    if facts.companion_override {
        return Err(SignerOff::CompanionOverride);
    }
    if !facts.release_team {
        return Err(SignerOff::NoReleaseTeam);
    }
    if !facts.release_service {
        return Err(SignerOff::NotReleaseService);
    }
    Ok(())
}

fn companion_override_set() -> bool {
    std::env::vars_os().any(|(name, value)| {
        name.to_string_lossy().starts_with("OTTTO_COMPANION_") && !value.is_empty()
    })
}

fn this_service_owner() -> InstallOwner {
    std::env::current_exe()
        .map(|executable| crate::control::install_owner_for_path(&executable))
        .unwrap_or(InstallOwner::Unknown)
}

/// The code requirement every signer peer must meet (the release Ottto app), or why this service
/// opens no signer channel. There is no dev or ad-hoc mode.
#[cfg(target_os = "macos")]
pub fn signer_peer_requirement() -> Result<String, SignerOff> {
    let team_id = super::OTTTO_COMPANION_DEFAULT_TEAM_ID.trim();
    let release_team = !team_id.is_empty();
    resolve_signer_start(&SignerStartFacts {
        owner: this_service_owner(),
        companion_override: companion_override_set(),
        release_team,
        release_service: release_team
            && super::peer::this_process_satisfies(&super::peer::service_team_code_requirement(
                team_id,
            )),
    })?;
    Ok(super::peer::companion_signer_code_requirement(team_id))
}

/// Off macOS there is no Mac app and no release signature.
#[cfg(not(target_os = "macos"))]
pub fn signer_peer_requirement() -> Result<String, SignerOff> {
    resolve_signer_start(&SignerStartFacts {
        owner: this_service_owner(),
        companion_override: companion_override_set(),
        release_team: false,
        release_service: false,
    })
    .map(|()| String::new())
}

/// Marks the signer channel as serving peers that meet `peer_requirement`.
pub fn signer_listening(peer_requirement: String) {
    let _ = SIGNER_PEER_REQUIREMENT.set(peer_requirement);
}

/// Whether this service serves the signer channel.
pub fn signer_available() -> bool {
    SIGNER_PEER_REQUIREMENT.get().is_some()
}

pub fn sign_queue() -> &'static SignQueue {
    SIGN_QUEUE.get_or_init(SignQueue::default)
}

fn connections() -> &'static signer::Connections {
    CONNECTIONS.get_or_init(signer::Connections::default)
}

/// Queues `payload` for the app to sign until `expires_at` (Unix seconds), with a throttled wake
/// hint when no signer said hello recently. Returns the request id to wait on.
pub fn queue_sign_request(
    kind: SignKind,
    payload: Vec<u8>,
    expires_at: i64,
) -> Result<String, SignQueueError> {
    let requirement = SIGNER_PEER_REQUIREMENT
        .get()
        .ok_or(SignQueueError::SignerUnavailable)?;
    let queued = sign_queue().enqueue(kind, payload, expires_at)?;
    if queued.wake_app {
        wake::wake_app(requirement);
    }
    Ok(queued.request_id)
}

/// One request from the signer listener's connection `connection`, as JSON in and out.
pub fn handle_signer_request_json(
    daemon: &LocalDaemon,
    connection: u64,
    request_json: &str,
) -> String {
    signer::handle(
        sign_queue(),
        connections(),
        &server::SetupRunServer { daemon },
        connection,
        request_json,
    )
}

/// The signer connection `connection` ended: drop what it prepared and return what it took.
pub fn signer_connection_closed(connection: u64) {
    connections().close(connection);
    sign_queue().release(connection);
}
