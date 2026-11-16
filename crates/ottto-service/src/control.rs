use crate::agent_configs::codex_toml;
use crate::{
    agent_configs::{claude_env, detection::detect_agent_installation, fence::AgentConfigError},
    agent_status::{
        pi_identity_hints_for_route, read_pi_agent_auth, read_pi_smoke_routes,
        BillingIdentityHints, PiModelRoute,
    },
    current_rfc3339_timestamp, diagnostics_local_only_upload_report,
    keychain::TelemetryKeyStore,
    snapshot_client::relay_token_request_payload,
    BackendErrorDetails, BackendErrorKind, LocalApiError, LocalDaemon, PendingAuthClaim,
    SetupRunReadStart, StagedAccountSwitch,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ottto_core::token_store::{
    OTTTO_HISTORY_BROWSER_CLAIM_ACCOUNT as HISTORY_BROWSER_ACCOUNT,
    OTTTO_LOCAL_RELEASE_MARKER_ACCOUNT as HISTORY_MARKER_ACCOUNT,
    OTTTO_LOCAL_RELEASE_PROOF_ACCOUNT as HISTORY_PROOF_ACCOUNT, OTTTO_REVOCATION_RECEIPT_ACCOUNT,
};
use ottto_core::{
    compiled_build_id, compiled_release_channel, compiled_release_version,
    default_prior_device_path, default_support_dir, execute_local_uninstall,
    generate_control_token, install_owner_for_path, local_lifecycle_home_dir, plan_local_uninstall,
    redact_inline, release_channel_from_str, ClaudeConfigSlotSettingsError,
    CodexAccountSlotSettingsError, ControlTokenStore, DeviceCredentialContinuity, FileAccountStore,
    FileClaudeConfigSlotSettingsStore, FileCodexAccountSlotSettingsStore, FileConnectionStore,
    FileDeviceStore, FileMachineStore, FileOwnerSnapshotNamespaceStore,
    FilePendingDeviceCredentialStore, KeychainSecretStore, LocalConnectionBinding,
    LocalCredentialOwner, LocalDeviceBinding, LocalDeviceCredentialBinding, LocalDeviceEnvelope,
    OwnerSnapshotKey, OwnerSnapshotNamespace, PendingClaimCredentialCommit,
    PendingDeviceCredentialPreparation, PendingDeviceCredentialRequestAuthority,
    SnapshotNamespaceAlias, TokenStoreError, UninstallExecutionOptions, OTTTO_CLIENT_NAME,
    OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT,
    OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_SERVICE_BINARY_NAME, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
use ottto_protocol::{
    validate_local_control_protocol_version, AgentContextQuery, AgentCostsQuery,
    AgentInstallationDetection, AgentProviderImpactQuery, AgentRecommendationsQuery,
    AgentSessionsQuery, AgentStatusSnapshot, AuthCompleteResponse, AuthResetResponse,
    AuthStartResponse, ClaudeAccountSetupOperationState, ClaudeConfigSlotCollectionStateV1,
    CliError, CliErrorCode, CodexAccountSetupOperationStateV1, ConfigDrift, ControlResult,
    ControlResultStatus, DiagnosticsBundle, DiagnosticsRetentionDisclosure,
    DiagnosticsUploadApproval, DiagnosticsUploadAuthorization, DiagnosticsUploadReport,
    DiagnosticsUploadStatus, InstallOwner, LocalAccountBinding, LocalAccountOrganization,
    LocalAccountState, LocalAccountUser, LocalClientKind, LocalControlCommand, LocalControlRequest,
    LocalControlResponse, MachineIdentity, ProviderDailyReferenceBackendGrantResponseV1,
    ProviderDailyReferenceControlAction, RedactedValue, RelayRuntimeState, RelayState,
    ReleaseChannel, RepairAction, RepairActionApproval, RepairActionKind, RepairApprovalSurface,
    RepairPlan, RepairPlanStatus, SecretString, ServiceOwnerState, SourceConfigState, SourceKind,
    SourceRouteVerificationResult, SourceVerificationCheck, SourceVerificationMethod,
    SourceVerificationResult, SourceVerificationScope, SourceVerificationStatus, StableMessage,
    TelemetryControlAction, UninstallExecutionResult, UpdateGate, UpdateState, UpdateStatus,
    DIAGNOSTICS_RETENTION_DISCLOSURE, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fs;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, Item};

#[cfg(test)]
use ottto_core::LocalMachineBinding;

// Direct API host (was the apex `ottto.net/backend` proxy, retired in the
// marketing-site cutover). Matches DIRECT_API_BASE_URL below.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const DIRECT_API_BASE_URL: &str = "https://api.ottto.net";
const DEVICE_CREDENTIAL_PREPARATION_CAPABILITY: &str = "device_credential_prepare_confirm_v1";
const DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER: &str =
    "X-Ottto-Device-Credential-Preparation-Secret";
const PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION: u16 = 2;
// v2 is already released. History-bearing ceremonies must reject downgrade.
const OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION: u16 = 3;

fn supported_pending_credential_schema(version: u16) -> bool {
    matches!(
        version,
        PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION | OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
    )
}
// Legacy apex proxy base persisted by daemons installed before the marketing
// cutover. Still trusted/recognized so existing installs keep ingesting until
// they re-onboard onto the direct api.ottto.net base.
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";
const SMOKE_PROMPT: &str = "Reply with exactly: ottto smoke test";
const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_READ_HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const SETUP_SCAN_RESULT_HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const SETUP_VERIFICATION_HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const SETUP_VERIFICATION_MARKER_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SMOKE_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const PI_SMOKE_COMMAND_TIMEOUT: Duration = Duration::from_secs(25);
const PI_VERIFICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(8);
const PI_VERIFICATION_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON: &str =
    "race-safe rooted session access is unavailable on this platform";
const PI_SESSION_CENSUS_FAILED_CODE: &str = "pi_session_census_failed";
// Poll long enough for slow-arriving agent telemetry (codex batches + flushes
// its token records, then the relay forwards them) to reach the backend before
// we give up — claude/pi still return early on success. Kept under
// SETUP_VERIFICATION_HTTP_TIMEOUT (120s).
const VERIFICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(110);
const VERIFICATION_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: u64 = 15;
const VERIFICATION_MARKER_METRIC_NAME: &str = "ottto.verification.smoke";
const VERIFICATION_MARKER_ATTRIBUTE: &str = "ottto.verification";
const VERIFICATION_MARKER_HEADER: &str = "X-Ottto-Verification";
const SMOKE_USAGE_LIMIT_ERROR_CODE: &str = "usage_limited";
const CLAUDE_OAUTH_REAUTH_REQUIRED_CODE: &str =
    crate::CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE;
/// Verification message/error code for a source whose CLI is genuinely not
/// installed on this machine. Reported instead of running a doomed smoke that
/// would surface "not installed or not executable" as a blocking telemetry
/// failure. Maps to a non-blocking `not_found` source state. Shared with the
/// crate-root health projection via [`crate::SOURCE_NOT_INSTALLED_VERIFICATION_CODE`].
const SOURCE_NOT_INSTALLED_CODE: &str = crate::SOURCE_NOT_INSTALLED_VERIFICATION_CODE;
/// Data/config present but the CLI binary can't be found or executed (desktop-
/// app-only installs). Maps to a visible, non-blocking soft warning. Shared
/// with the crate-root health projection via
/// [`crate::AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE`].
const AGENT_CLI_UNAVAILABLE_CODE: &str = crate::AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_CONFIG_BACKUPS_PER_SOURCE: usize = 10;
const OTTTO_CONFIG_BACKUP_RETENTION_ENV: &str = "OTTTO_CONFIG_BACKUP_RETENTION";
#[cfg(target_os = "macos")]
const OTTTO_COMPANION_BUNDLE_IDENTIFIER: &str = "net.ottto.Companion";
/// Apple Developer Team ID that signs the official Ottto Companion app, baked
/// into the binary at compile time.
///
/// SECURITY: this is what makes the Companion code requirement enforced *by
/// default*. It used to be supplied only through `OTTTO_COMPANION_TEAM_ID` /
/// `OTTTO_COMPANION_CODE_REQUIREMENT`, and nothing in the shipped installers
/// or LaunchAgents ever set either one — so every production install fell back
/// to trusting any binary sitting at one of the [`trusted_companion_paths`]
/// (including the user-writable `~/Applications/Ottto.app`). A compile-time
/// default cannot be un-set by an installer regression, and — unlike a
/// LaunchAgent `EnvironmentVariables` entry — it is not stored in a
/// user-writable file.
///
/// The value is not a secret: it is the `subject.OU` of the Developer ID
/// certificate in every signed, notarized Ottto release and is printed by
/// `codesign -dv --verbose=4 /Applications/Ottto.app`.
///
/// It has two jobs: it is the team the Companion must be signed by, and — via
/// [`daemon_is_release_signed`] — the team whose signature on *this daemon*
/// marks the install as a customer artifact rather than an internal build.
///
/// Forks and downstream builds override it at build time:
/// `OTTTO_COMPANION_DEFAULT_TEAM_ID=ABCDE12345 cargo build --release`.
/// Building with an empty value (`OTTTO_COMPANION_DEFAULT_TEAM_ID=`) disables
/// token-less Companion trust entirely rather than falling back to path-only
/// trust — see [`resolve_companion_code_requirement`].
#[cfg(target_os = "macos")]
const OTTTO_COMPANION_DEFAULT_TEAM_ID: &str = match option_env!("OTTTO_COMPANION_DEFAULT_TEAM_ID") {
    Some(team_id) => team_id,
    None => "YRNP9UD7WY",
};

// Serializes every account/device identity mutation with Codex cloud-task I/O
// admission. The same lock covers that admission and the identity write/reset.
static SETUP_RUN_BINDING_LOCK: Mutex<()> = Mutex::new(());
static IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(0);
static NEXT_IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn lock_setup_run_binding() -> MutexGuard<'static, ()> {
    SETUP_RUN_BINDING_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn try_lock_setup_run_binding() -> Option<MutexGuard<'static, ()>> {
    SETUP_RUN_BINDING_LOCK.try_lock().ok()
}

pub(crate) fn identity_mutation_in_progress() -> bool {
    IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire) != 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalIdentityAuthoritySnapshot {
    account: LocalAccountBinding,
    device: Option<LocalDeviceBinding>,
}

struct IdentityMutationReservation {
    id: u64,
    snapshot: LocalIdentityAuthoritySnapshot,
}

impl IdentityMutationReservation {
    fn validate_locked(&self) -> Result<(), LocalApiError> {
        require_identity_mutation_reservation(Some(self))?;
        if load_local_identity_authority_snapshot()? != self.snapshot {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        Ok(())
    }
}

impl Drop for IdentityMutationReservation {
    fn drop(&mut self) {
        let _ = IDENTITY_MUTATION_RESERVATION.compare_exchange(
            self.id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn reserve_identity_mutation() -> Result<IdentityMutationReservation, LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reserve_identity_mutation_locked()
}

/// [`reserve_identity_mutation`] for a caller already holding the identity
/// lifecycle lock.
fn reserve_identity_mutation_locked() -> Result<IdentityMutationReservation, LocalApiError> {
    require_identity_mutation_reservation(None)?;
    let snapshot = load_local_identity_authority_snapshot()?;
    crate::account_nicknames::invalidate_locked();
    let id = NEXT_IDENTITY_MUTATION_RESERVATION.fetch_add(1, Ordering::Relaxed);
    if id == 0
        || IDENTITY_MUTATION_RESERVATION
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let reservation = IdentityMutationReservation { id, snapshot };
    // The reservation closes new Codex cloud-task admission. Drain work
    // already admitted before replacing local identity.
    crate::cloud_sessions::CloudSessionCheckpointStore::default()
        .wait_for_collector_io_idle(crate::cloud_sessions::COLLECTOR_IO_STOP_TIMEOUT)
        .map_err(|_| LocalApiError::CloudSessionCleanupRequired)?;
    Ok(reservation)
}

fn require_identity_mutation_reservation(
    owner: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    let active = IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire);
    if match owner {
        Some(owner) => active == owner.id,
        None => active == 0,
    } {
        Ok(())
    } else {
        Err(LocalApiError::IdentityMutationInProgress)
    }
}

fn load_local_identity_authority_snapshot() -> Result<LocalIdentityAuthoritySnapshot, LocalApiError>
{
    let account = FileAccountStore::default().load().or_state_poisoned()?;
    let device = FileDeviceStore::default().load().or_state_poisoned()?;
    Ok(LocalIdentityAuthoritySnapshot { account, device })
}

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
    trusted_for_tests: bool,
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
    fn trusted_for_tests() -> Self {
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
    fn euid_matches_daemon(&self) -> bool {
        match self.euid {
            Some(peer_euid) => peer_euid == daemon_effective_uid(),
            None => false,
        }
    }
}

/// The effective uid of the running daemon process.
#[cfg(unix)]
fn daemon_effective_uid() -> u32 {
    // SAFETY: geteuid() is always-successful and has no preconditions.
    // `libc::uid_t` is `u32` on every supported unix target.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn daemon_effective_uid() -> u32 {
    u32::MAX
}

pub fn handle_request(daemon: &LocalDaemon, request: LocalControlRequest) -> LocalControlResponse {
    handle_request_with_peer(daemon, request, None)
}

pub fn handle_request_with_peer(
    daemon: &LocalDaemon,
    request: LocalControlRequest,
    peer: Option<LocalClientPeer>,
) -> LocalControlResponse {
    let request_id = request.request_id.clone();
    if let Err(message) =
        validate_local_control_protocol_version(request.protocol_version, &request.command)
    {
        return LocalControlResponse {
            request_id,
            ok: false,
            payload: None,
            error: Some(CliError {
                message,
                retryable: false,
                code: CliErrorCode::InvalidRequest,
                details: BTreeMap::new(),
            }),
        };
    }
    let authorization = request_authorization(&request, peer.as_ref());
    let client_install_owner = request
        .client_install_owner
        .unwrap_or(InstallOwner::Unknown);
    let cli_session_exec = request.client_kind == Some(LocalClientKind::Cli);
    let status_refresh_quota_source =
        status_refresh_quota_source(request.client_kind, request.protocol_version);
    match handle_command(
        daemon,
        authorization,
        request.command,
        client_install_owner,
        status_refresh_quota_source,
        cli_session_exec,
    ) {
        Ok(payload) => LocalControlResponse {
            request_id,
            ok: true,
            payload: Some(payload),
            error: None,
        },
        Err(error) => LocalControlResponse {
            request_id,
            ok: false,
            payload: None,
            error: Some(cli_error(error)),
        },
    }
}

/// The diagnostic class of a control command; counts only, no ids or args.
pub(crate) fn control_command_class(command: &LocalControlCommand) -> &'static str {
    match command {
        LocalControlCommand::Status { .. } => "status",
        LocalControlCommand::ClaudeAccountsStatus => "claude_accounts_status",
        LocalControlCommand::CodexAccountsStatus => "codex_accounts_status",
        LocalControlCommand::AgentStatusRefresh { .. } => "agent_status_refresh",
        _ => "other",
    }
}

pub fn handle_request_json_with_peer(
    daemon: &LocalDaemon,
    request_json: &str,
    peer: Option<LocalClientPeer>,
) -> String {
    let request = serde_json::from_str::<LocalControlRequest>(request_json);
    crate::local_resource_diagnostics::control_class(
        request
            .as_ref()
            .map_or("other", |request| control_command_class(&request.command)),
    );
    let response = match request {
        Ok(request) => handle_request_with_peer(daemon, request, peer),
        Err(error) => LocalControlResponse {
            request_id: "req_xpc_invalid".to_string(),
            ok: false,
            payload: None,
            error: Some(CliError {
                message: format!("invalid local control request: {error}"),
                retryable: false,
                code: CliErrorCode::InvalidRequest,
                details: BTreeMap::new(),
            }),
        },
    };
    serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"request_id":"req_xpc_invalid","ok":false,"payload":null,"error":{"code":"internal","message":"failed to serialize local control response","retryable":false,"details":{}}}"#.to_string()
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestAuthorization {
    Token(String),
    TrustedCompanionApp,
    Untrusted,
}

fn request_authorization(
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

fn companion_peer_is_trusted(peer: Option<&LocalClientPeer>) -> bool {
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
enum CompanionCodeRequirement {
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
fn companion_code_requirement() -> CompanionCodeRequirement {
    resolve_companion_code_requirement(
        std::env::var("OTTTO_COMPANION_CODE_REQUIREMENT")
            .ok()
            .as_deref(),
        std::env::var("OTTTO_COMPANION_TEAM_ID").ok().as_deref(),
        OTTTO_COMPANION_DEFAULT_TEAM_ID,
        daemon_is_release_signed(),
    )
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
fn resolve_companion_code_requirement(
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
fn companion_team_code_requirement(team_id: &str) -> String {
    format!(
        "identifier \"{OTTTO_COMPANION_BUNDLE_IDENTIFIER}\" and {}",
        developer_id_requirement_fragment(team_id)
    )
}

/// The identifier-only requirement used by internal builds, where no Apple team
/// is available to assert. Satisfied by an ad-hoc-signed Companion; not
/// satisfied by an unsigned or differently-identified binary.
#[cfg(target_os = "macos")]
fn companion_identity_code_requirement() -> String {
    format!("identifier \"{OTTTO_COMPANION_BUNDLE_IDENTIFIER}\"")
}

/// The requirement this daemon's own code must satisfy for the install to count
/// as a customer artifact: a Developer ID certificate Apple issued to the
/// baked-in team. No `identifier` clause — the daemon ships under several
/// (`ottto-service` standalone, and bundled inside the app).
#[cfg(target_os = "macos")]
fn daemon_release_code_requirement(team_id: &str) -> String {
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
fn daemon_is_release_signed() -> bool {
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

/// Companion apps up to this protocol version have no `quota_refresh`: their
/// Refresh button sends `status` with `refresh_agent_status`, the same request
/// as their 5-minute scan. Those requests stand in for an explicit refresh of
/// every Codex home, at most once per
/// [`LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS`] per home. Claude is left out:
/// its Refresh never forced a provider read, and its accounts are served the
/// stored reading the daemon's schedule keeps current. Such a request cannot
/// be told from the app's timer, so it reads nothing while Codex background
/// limit refresh is off.
const LEGACY_APP_QUOTA_REFRESH_MAX_PROTOCOL_VERSION: u16 = 15;
const LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS: u64 = 5 * 60;

/// The source whose quota a `status` refresh from this client refreshes
/// explicitly, if any.
fn status_refresh_quota_source(
    client_kind: Option<LocalClientKind>,
    protocol_version: u16,
) -> Option<SourceKind> {
    (client_kind == Some(LocalClientKind::CompanionApp)
        && protocol_version <= LEGACY_APP_QUOTA_REFRESH_MAX_PROTOCOL_VERSION)
        .then_some(SourceKind::Codex)
}

fn require_session_launch_schema(version: u16) -> Result<(), LocalApiError> {
    if version != 1 {
        return Err(LocalApiError::InvalidRequest(
            "unsupported session launch schema".into(),
        ));
    }
    Ok(())
}

fn handle_command(
    daemon: &LocalDaemon,
    authorization: RequestAuthorization,
    command: LocalControlCommand,
    client_install_owner: InstallOwner,
    status_refresh_quota_source: Option<SourceKind>,
    cli_session_exec: bool,
) -> Result<serde_json::Value, LocalApiError> {
    // Invalidate pending handoffs before any explicit account/slot mutation.
    // Existing mutation handlers retain all of their authorization and order.
    if matches!(
        &command,
        LocalControlCommand::AuthComplete { .. }
            | LocalControlCommand::AuthCompletePending { .. }
            | LocalControlCommand::AuthSwitchAccount { .. }
            | LocalControlCommand::AuthReset { .. }
            | LocalControlCommand::ClaudeAccountRemove { .. }
            | LocalControlCommand::ClaudeAccountReconnect { .. }
            | LocalControlCommand::ClaudeAccountReconnectTarget { .. }
            | LocalControlCommand::ClaudeAccountStartBrowserReconnect { .. }
            | LocalControlCommand::CodexAccountRemove { .. }
            | LocalControlCommand::CodexAccountReconnect { .. }
    ) {
        require_authorized_local_client(daemon, &authorization)?;
        daemon
            .session_launch
            .lock()
            .or_state_poisoned()?
            .invalidate();
    }
    match command {
        LocalControlCommand::SessionLaunchPrepare {
            schema_version,
            provider,
            slot_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
            folder,
            ..
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon.session_launch.lock().or_state_poisoned()?.prepare(
                    provider,
                    &slot_id,
                    &expected_account_identifier_hash,
                    expected_organization_identifier_hash
                        .as_deref()
                        .unwrap_or(""),
                    folder,
                    preferred_ottto_cli_path(),
                    &default_support_dir(),
                ),
            )
        }
        LocalControlCommand::SessionLaunchConsume {
            schema_version,
            launch_id,
            secret,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            // Only the token-authenticated CLI owns the exec plan. The trusted
            // Companion can prepare/poll/cancel, but never consume a handoff.
            if !cli_session_exec || !matches!(&authorization, RequestAuthorization::Token(_)) {
                return Err(LocalApiError::Unauthorized);
            }
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .consume(&launch_id, secret.expose_secret()),
            )
        }
        LocalControlCommand::SessionLaunchReport {
            schema_version,
            launch_id,
            attempt_id,
            reason,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            if !cli_session_exec || !matches!(&authorization, RequestAuthorization::Token(_)) {
                return Err(LocalApiError::Unauthorized);
            }
            require_session_launch_schema(schema_version)?;
            to_value(daemon.session_launch.lock().or_state_poisoned()?.report(
                &launch_id,
                attempt_id.expose_secret(),
                reason,
            ))
        }
        LocalControlCommand::SessionLaunchStatus {
            schema_version,
            launch_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .status(&launch_id, false),
            )
        }
        LocalControlCommand::SessionLaunchCancel {
            schema_version,
            launch_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .status(&launch_id, true),
            )
        }
        LocalControlCommand::SessionLaunchRecentFolders {
            schema_version,
            provider,
            slot_id,
            limit,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(daemon.session_launch.lock().or_state_poisoned()?.recent(
                provider,
                slot_id.as_deref(),
                usize::from(limit.unwrap_or(100)),
                &default_support_dir(),
            ))
        }
        LocalControlCommand::AccountNicknames => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::account_nicknames::read())
        }
        LocalControlCommand::AccountNicknameSet {
            source,
            account_identifier_hash,
            organization_identifier_hash,
            nickname,
            base_revision,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::account_nicknames::set(
                ottto_protocol::AccountNicknamePairV1 {
                    source,
                    account_identifier_hash: Some(account_identifier_hash),
                    organization_identifier_hash,
                },
                nickname,
                base_revision,
            ))
        }
        LocalControlCommand::Status {
            refresh_agent_status,
            retry_relay_authorization,
        } => {
            if retry_relay_authorization {
                require_authorized_local_client(daemon, &authorization)?;
                crate::snapshot_sync::reset_relay_authorization_backoff();
                daemon.refresh_shell_profile_health()?;
            }
            if refresh_agent_status {
                if let Some(source) = status_refresh_quota_source.as_ref().filter(|_| {
                    FileCodexAccountSlotSettingsStore::default().background_quota_refresh_allowed()
                }) {
                    require_authorized_local_client(daemon, &authorization)?;
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::OlderAppCompat,
                        || {
                            request_explicit_quota_refresh(
                                Some(source),
                                LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS,
                            )
                        },
                    );
                }
                refresh_agent_status_for(daemon, &authorization, None)?;
            }
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            status.service_owner = service_owner_state(client_install_owner);
            crate::refresh_canonical_local_health(&mut status);
            status.account = crate::effective_account_binding(&status);
            let mut value = to_value(status)?;
            inject_machine_icon(&mut value);
            // Doctor only: ordinary status polls must not walk the store.
            #[cfg(unix)]
            if retry_relay_authorization {
                if let Ok((files, bytes)) =
                    crate::claude_local_otel::support_health::store_size(&default_support_dir())
                {
                    value["local_otel"] = serde_json::json!({"files": files, "bytes": bytes});
                }
            }
            Ok(value)
        }
        LocalControlCommand::Receipts {
            limit,
            since,
            source,
            before,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            if limit == 0 || usize::from(limit) > crate::upload_receipts::UPLOAD_RECEIPT_PAGE_SIZE {
                return Err(LocalApiError::InvalidRequest(format!(
                    "receipts limit must be between 1 and {}",
                    crate::upload_receipts::UPLOAD_RECEIPT_PAGE_SIZE
                )));
            }
            if let Some(value) = since.as_deref() {
                time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        LocalApiError::InvalidRequest(
                            "receipts since must be an RFC3339 timestamp".to_string(),
                        )
                    })?;
            }
            to_value(
                crate::upload_receipts::read_page(
                    &default_support_dir(),
                    limit,
                    since.as_deref(),
                    source,
                    before,
                )
                .map_err(|_| {
                    LocalApiError::LocalOperationFailed(
                        "could not read snapshot upload receipts".to_string(),
                    )
                })?,
            )
        }
        LocalControlCommand::AuthStatus => {
            let mut status = status_for(daemon, &authorization)?;
            status.account = crate::effective_account_binding(&status);
            to_value(status)
        }
        LocalControlCommand::AgentStatusRefresh {
            source,
            quota_refresh,
        } => {
            if quota_refresh {
                require_authorized_local_client(daemon, &authorization)?;
                crate::provider_calls::with_trigger(
                    crate::provider_calls::Trigger::ExplicitRefresh,
                    || request_explicit_quota_refresh(source.as_ref(), 0),
                );
            }
            to_value(refresh_agent_status_for(daemon, &authorization, source)?)
        }
        LocalControlCommand::AgentStatusCached { source } => {
            // Unlike the usual authorization helper, this skips the daemon-state
            // poison check: the cached read uses no daemon state.
            match &authorization {
                RequestAuthorization::Token(token) => daemon.control_token.authorize(token)?,
                RequestAuthorization::TrustedCompanionApp => {}
                RequestAuthorization::Untrusted => {
                    return Err(LocalApiError::LocalClientNotTrusted)
                }
            }
            to_value(crate::agent_status_refresh::cached(source.as_ref()))
        }
        LocalControlCommand::PersonalMeterLocalSnapshot { source } => {
            let status = status_for(daemon, &authorization)?;
            to_value(crate::personal_meter_local_snapshot_from_status(
                &status,
                source.as_ref(),
            ))
        }
        LocalControlCommand::AgentContext { query } => agent_context(daemon, &authorization, query),
        LocalControlCommand::AgentCosts { query } => agent_costs(daemon, &authorization, query),
        LocalControlCommand::AgentSessions { query } => {
            agent_sessions(daemon, &authorization, query)
        }
        LocalControlCommand::AgentRecommendations { query } => {
            agent_recommendations(daemon, &authorization, query)
        }
        LocalControlCommand::AgentProviderImpact { query } => {
            agent_provider_impact(daemon, &authorization, query)
        }
        LocalControlCommand::CloudStatus { source } => cloud_status(daemon, &authorization, source),
        LocalControlCommand::AuthStart => to_value(auth_start(daemon, &authorization)?),
        LocalControlCommand::AuthComplete { claim_code, nonce } => {
            to_value(auth_complete(daemon, &authorization, &claim_code, &nonce)?)
        }
        LocalControlCommand::AuthCompletePending { claim_code } => {
            to_value(auth_complete_pending(daemon, &authorization, &claim_code)?)
        }
        LocalControlCommand::AuthSwitchAccount { claim_code } => {
            to_value(auth_switch_account(daemon, &authorization, &claim_code)?)
        }
        LocalControlCommand::AuthReset {
            local_only,
            forget_installation,
        } => to_value(auth_reset(
            daemon,
            &authorization,
            local_only,
            forget_installation,
            None,
        )?),
        LocalControlCommand::Account => to_value(account_for(daemon, &authorization)?),
        LocalControlCommand::ClaudeAccountsStatus => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(load_claude_config_slot_settings()?)
        }
        LocalControlCommand::ClaudeAccountSetUpkeepConsent {
            schema_version,
            consent,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(set_claude_account_upkeep_consent(schema_version, consent)?)
        }
        LocalControlCommand::ClaudeAccountRemove {
            schema_version,
            slot_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(remove_claude_account(schema_version, &slot_id)?)
        }
        LocalControlCommand::ClaudeAccountRegisterPath {
            schema_version,
            config_dir,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(register_claude_account_path(schema_version, config_dir)?)
        }
        LocalControlCommand::ClaudeAccountPrepare {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(prepare_claude_account_legacy(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
            )?)
        }
        LocalControlCommand::ClaudeAccountPrepareTarget {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(prepare_claude_account_target(
                schema_version,
                operation_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountReconnect {
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(reconnect_claude_account(
                schema_version,
                operation_id,
                &slot_id,
                None,
                expected_account_identifier_hash,
                None,
            )?)
        }
        LocalControlCommand::ClaudeAccountReconnectTarget {
            schema_version,
            operation_id,
            slot_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(reconnect_claude_account_target(
                schema_version,
                operation_id,
                &slot_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountCheck {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(check_claude_account(
                schema_version,
                &operation_id,
                expected_account_identifier_hash.as_deref(),
            )?)
        }
        LocalControlCommand::ClaudeAccountStopWaiting {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(stop_waiting_for_claude_account(
                schema_version,
                &operation_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountStartBrowserLogin {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(start_claude_browser_login(
                schema_version,
                operation_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountStartBrowserReconnect {
            schema_version,
            operation_id,
            slot_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(start_claude_browser_reconnect(
                schema_version,
                operation_id,
                &slot_id,
                target_id,
            )?)
        }
        LocalControlCommand::RetiredClaudeAccountSubmitAuthCode {} => {
            // Authorization runs first so untrusted callers keep the normal
            // rejection; nothing reaches browser-auth state or the provider.
            require_authorized_local_client(daemon, &authorization)?;
            Err(LocalApiError::RetiredCommand(
                crate::claude_browser_auth::RETIRED_CODE_SUBMISSION_MESSAGE,
            ))
        }
        LocalControlCommand::CodexAccountsStatus => {
            require_authorized_local_client(daemon, &authorization)?;
            crate::codex_sign_in::end_stale_run();
            to_value(crate::codex_sign_in::present(
                load_codex_account_settings_for_status_read()?,
            ))
        }
        LocalControlCommand::CodexAccountPrepare {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_codex_account(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_workspace_identifier_hash,
            )?))
        }
        LocalControlCommand::CodexAccountPrepareOpen {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_open_codex_account(
                schema_version,
                operation_id,
            )?))
        }
        LocalControlCommand::CodexAccountPrepareTarget {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_codex_account_target(
                schema_version,
                operation_id,
                target_id,
            )?))
        }
        LocalControlCommand::CodexAccountReconnect {
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(reconnect_codex_account(
                schema_version,
                operation_id,
                &slot_id,
                expected_account_identifier_hash,
                expected_workspace_identifier_hash,
            )?))
        }
        LocalControlCommand::CodexAccountCheck {
            schema_version,
            operation_id,
            explicit,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(check_codex_account(
                schema_version,
                &operation_id,
                explicit,
            )?))
        }
        LocalControlCommand::CodexAccountStartSignIn {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(start_codex_sign_in(
                schema_version,
                &operation_id,
            )?))
        }
        LocalControlCommand::CodexAccountStopWaiting {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(
                stop_waiting_for_codex_account(schema_version, &operation_id)?,
            ))
        }
        LocalControlCommand::CodexAccountRemove {
            schema_version,
            slot_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(remove_codex_account(
                schema_version,
                &slot_id,
            )?))
        }
        LocalControlCommand::CodexAccountSetQuotaRefreshConsent {
            schema_version,
            consent,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(
                set_codex_quota_refresh_consent(schema_version, consent)?,
            ))
        }
        LocalControlCommand::Detect { source } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(detect_agent_installation(&source))
        }
        LocalControlCommand::Repair { source, dry_run } => {
            to_value(repair_source(daemon, &authorization, source, dry_run)?)
        }
        LocalControlCommand::DiagnosticsCollect {
            upload,
            upload_approval,
            api_base_url,
        } => diagnostics_collect(
            daemon,
            &authorization,
            upload,
            upload_approval,
            api_base_url,
        ),
        LocalControlCommand::RelayStart => {
            let relay = RelayState {
                state: RelayRuntimeState::Starting,
                endpoint: None,
                last_connected_at: None,
                last_error: None,
            };
            match &authorization {
                RequestAuthorization::Token(token) => {
                    daemon.set_relay_state(token, relay)?;
                    to_value(daemon.status(token)?.relay)
                }
                RequestAuthorization::TrustedCompanionApp => {
                    daemon.set_relay_state_for_trusted_client(relay)?;
                    to_value(daemon.status_for_trusted_client()?.relay)
                }
                RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
            }
        }
        LocalControlCommand::RelayStop => {
            let relay = RelayState {
                state: RelayRuntimeState::Stopping,
                endpoint: None,
                last_connected_at: None,
                last_error: None,
            };
            match &authorization {
                RequestAuthorization::Token(token) => {
                    daemon.set_relay_state(token, relay)?;
                    to_value(daemon.status(token)?.relay)
                }
                RequestAuthorization::TrustedCompanionApp => {
                    daemon.set_relay_state_for_trusted_client(relay)?;
                    to_value(daemon.status_for_trusted_client()?.relay)
                }
                RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
            }
        }
        LocalControlCommand::Verify { source, repair } => {
            // A person's Verify (the app or `ottto verify`) is a setup check.
            let result =
                crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, || {
                    verify_source(daemon, &authorization, source, repair)
                })?;
            if verification_result_should_refresh_agent_status(&result) {
                if let Err(error) =
                    refresh_agent_status_for(daemon, &authorization, Some(result.source.clone()))
                {
                    eprintln!(
                        "post-verify agent status refresh skipped: {}",
                        cli_error_message(&error)
                    );
                }
            }
            let mut value = to_value(result)?;
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            status.service_owner = service_owner_state(client_install_owner);
            crate::refresh_canonical_local_health(&mut status);
            if let Err(error) = crate::snapshot_sync::upload_local_health_projection_now(daemon) {
                eprintln!(
                    "manual local health projection upload skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            if let serde_json::Value::Object(object) = &mut value {
                object.insert(
                    "canonical_health".to_string(),
                    to_value(status.canonical_health)?,
                );
                object.insert(
                    "runtime_heartbeat".to_string(),
                    to_value(status.runtime_heartbeat)?,
                );
                object.insert(
                    "local_health_events".to_string(),
                    to_value(status.local_health_events)?,
                );
                object.insert(
                    "command_ledger".to_string(),
                    to_value(status.command_ledger)?,
                );
            }
            Ok(value)
        }
        LocalControlCommand::Setup {
            sources,
            claim_code,
            setup_run_id,
            api_base_url,
        } => setup_run(
            daemon,
            &authorization,
            sources,
            claim_code,
            setup_run_id,
            api_base_url,
        ),
        LocalControlCommand::SetupAnswer {
            source,
            answer_type,
            api_base_url,
        } => setup_answer(daemon, &authorization, source, answer_type, api_base_url),
        LocalControlCommand::SetupAction {
            source,
            action_type,
            api_base_url,
        } => setup_action(daemon, &authorization, source, action_type, api_base_url),
        LocalControlCommand::SourceCollection { source, enabled } => {
            source_collection(daemon, &authorization, source, enabled)
        }
        LocalControlCommand::TelemetryControl {
            action,
            source,
            control_token,
            api_base_url,
            key_id,
            organization_id,
            otlp_endpoint,
            ingest_key,
        } => to_value(telemetry_control(
            daemon,
            action,
            source,
            control_token,
            api_base_url,
            key_id,
            organization_id,
            otlp_endpoint,
            ingest_key,
        )?),
        LocalControlCommand::ProviderDailyReferenceControl {
            action,
            control_token,
            api_base_url,
            backend_grant,
            expected_account_fingerprint,
        } => to_value(provider_daily_reference_control(
            action,
            control_token,
            api_base_url,
            backend_grant,
            expected_account_fingerprint,
        )?),
        LocalControlCommand::UpdateCheck => to_value(check_update_state()),
        LocalControlCommand::UninstallPlan | LocalControlCommand::Uninstall => {
            require_authorized_local_client(daemon, &authorization)?;
            let home = local_lifecycle_home()?;
            to_value(plan_local_uninstall(&home))
        }
        LocalControlCommand::UninstallExecute { confirm } => {
            require_authorized_local_client(daemon, &authorization)?;
            if !confirm {
                return Err(LocalApiError::InvalidRequest(
                    "uninstall_execute requires confirm=true".to_string(),
                ));
            }
            let home = local_lifecycle_home()?;
            #[cfg(target_os = "macos")]
            crate::snapshots::invalidate_claude_state_v2_sessions(
                &home.join("Library/Application Support/Ottto"),
            )
            .or_state_poisoned()?;
            crate::claude_local_otel::disable_appends_for_uninstall().or_state_poisoned()?;
            let mut result = execute_local_uninstall(&home, UninstallExecutionOptions::DAEMON);
            sweep_telemetry_keys_for_uninstall(&mut result);
            match &authorization {
                RequestAuthorization::Token(token) => daemon.stop(token)?,
                RequestAuthorization::TrustedCompanionApp => daemon.stop_for_trusted_client()?,
                RequestAuthorization::Untrusted => {
                    return Err(LocalApiError::LocalClientNotTrusted)
                }
            }
            to_value(result)
        }
    }
}

fn status_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<ottto_protocol::DaemonStatus, LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => daemon.status(token),
        RequestAuthorization::TrustedCompanionApp => daemon.status_for_trusted_client(),
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

fn verification_result_should_refresh_agent_status(result: &SourceVerificationResult) -> bool {
    (matches!(result.status, SourceVerificationStatus::NoFreshTelemetry)
        && result.message.code != "telemetry_disabled_by_admin")
        || (matches!(result.status, SourceVerificationStatus::Failed)
            && matches!(
                result.message.code.as_str(),
                "smoke_timeout" | "verification_service_unavailable"
            ))
}

fn account_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<LocalAccountBinding, LocalApiError> {
    // The `account` command answers with the effective account, like `status`.
    status_for(daemon, authorization).map(|status| crate::effective_account_binding(&status))
}

fn load_claude_config_slot_settings(
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
        .map(crate::claude_browser_auth::annotate_status)
}

fn complete_claude_registry_mutation(
    status: ottto_protocol::ClaudeAccountsStatusV1,
) -> ottto_protocol::ClaudeAccountsStatusV1 {
    crate::snapshot_sync::spawn_claude_agent_status_refresh("registry_mutation");
    crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(status),
    )
}

// Account setup must not grant telemetry consent. Only extend an already
// approved source's existing local relay configuration to daemon-owned roots.
static MANAGED_CLAUDE_SETTINGS_LOCK: Mutex<()> = Mutex::new(());

fn lock_managed_claude_settings() -> MutexGuard<'static, ()> {
    MANAGED_CLAUDE_SETTINGS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) enum ManagedClaudeRelaySettings {
    Revoked,
    Missing,
    Body(String),
}

pub(crate) fn read_managed_claude_relay_settings(
) -> Result<ManagedClaudeRelaySettings, LocalApiError> {
    if source_patch_disabled(&SourceKind::ClaudeCode) {
        return Ok(ManagedClaudeRelaySettings::Revoked);
    }
    let device = FileDeviceStore::default().load().map_err(|_| {
        LocalApiError::LocalOperationFailed("read managed Claude source approval".into())
    })?;
    if !device.is_some_and(|device| device.sources.iter().any(|source| source == "claude_code")) {
        return Ok(ManagedClaudeRelaySettings::Revoked);
    }
    let Some(body) = crate::agent_configs::claude_managed_settings::read_settings(&home_path(
        ".claude/settings.json",
    ))
    .map_err(|_| {
        LocalApiError::LocalOperationFailed("read approved Claude relay settings".into())
    })?
    else {
        return Ok(ManagedClaudeRelaySettings::Missing);
    };
    Ok(ManagedClaudeRelaySettings::Body(body))
}

pub(crate) fn approved_managed_claude_relay_endpoint() -> Result<Option<String>, LocalApiError> {
    let body = match read_managed_claude_relay_settings()? {
        ManagedClaudeRelaySettings::Body(body) => body,
        ManagedClaudeRelaySettings::Revoked | ManagedClaudeRelaySettings::Missing => {
            return Ok(None)
        }
    };
    if crate::agent_configs::claude_managed_settings::approved_relay_port(&body).is_none() {
        return Ok(None);
    }
    let settings: serde_json::Value = serde_json::from_str(&body).or_state_poisoned()?;
    Ok(settings["env"]["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]
        .as_str()
        .map(str::to_owned))
}

fn approved_managed_claude_relay_env() -> Result<Option<Vec<(&'static str, String)>>, LocalApiError>
{
    let Some(endpoint) = approved_managed_claude_relay_endpoint()? else {
        return Ok(None);
    };
    let Some(port) = crate::otlp_relay::local_relay_port_from_endpoint(&endpoint) else {
        return Ok(None);
    };
    let Some(machine) = FileMachineStore::default().load().map_err(|_| {
        LocalApiError::LocalOperationFailed("read managed Claude machine binding".into())
    })?
    else {
        return Ok(None);
    };
    Ok(Some(claude_code_relay_env_for_machine_id(
        &machine.machine_id,
        &crate::otlp_relay::local_relay_base_url_for_port(port),
    )))
}

pub(crate) fn provision_managed_claude_relay_settings(
    config_dir: &str,
) -> Result<bool, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    let Some(env) = approved_managed_claude_relay_env()? else {
        return Ok(false);
    };
    let current = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    if !current.managed_slots.iter().any(|slot| {
        slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            && slot.config_dir.as_deref() == Some(config_dir)
    }) && !crate::claude_browser_auth::active_provisional_telemetry_root(config_dir)
    {
        return Ok(false);
    }
    provision_managed_claude_relay_settings_with_env(config_dir, &env)
}

fn provision_managed_claude_relay_settings_with_env(
    config_dir: &str,
    env: &[(&str, String)],
) -> Result<bool, LocalApiError> {
    validate_managed_claude_settings_root(config_dir)?;
    crate::agent_configs::claude_managed_settings::reconcile(Path::new(config_dir), env)
        .map(|outcome| outcome == crate::agent_configs::claude_managed_settings::Outcome::Changed)
        .map_err(|_| {
            LocalApiError::LocalOperationFailed(
                "managed Claude settings could not be safely provisioned".into(),
            )
        })
}

fn validate_managed_claude_settings_root(config_dir: &str) -> Result<(), LocalApiError> {
    // Lexical authority first; the settings writer then opens every component
    // without following links. Do not use the auth-root validator here: it
    // repairs permissions and can follow an intermediate parent link.
    let root = Path::new(config_dir);
    let managed_parent = default_support_dir().join(ottto_core::CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    if root.parent() != Some(managed_parent.as_path())
        || ottto_core::ClaudeConfigDirSlot::registered(config_dir.to_owned()).is_err()
    {
        return Err(LocalApiError::LocalOperationFailed(
            "managed Claude settings root is unavailable or unsafe".into(),
        ));
    }
    Ok(())
}

fn disable_managed_claude_relay_settings() -> Result<bool, LocalApiError> {
    crate::otlp_relay::legacy::revoke_now();
    let _settings_guard = lock_managed_claude_settings();
    use crate::agent_configs::claude_managed_settings::{disable_settings, Outcome};
    let default_root = home_path(".claude");
    let mut changed = disable_settings(&default_root, true).map_err(|_| {
        LocalApiError::LocalOperationFailed("Claude relay opt-out could not be safely saved".into())
    })? == Outcome::Changed;
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    let mut roots: BTreeSet<String> = status
        .managed_slots
        .iter()
        .filter(|slot| slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed)
        .filter_map(|slot| slot.config_dir.clone())
        .collect();
    roots.extend(crate::claude_browser_auth::managed_telemetry_roots());
    let mut failure = None;
    for root in roots {
        let result = validate_managed_claude_settings_root(&root).and_then(|()| {
            disable_settings(Path::new(&root), false).map_err(|_| {
                LocalApiError::LocalOperationFailed(
                    "managed Claude relay settings could not be safely disabled".into(),
                )
            })
        });
        match result {
            Ok(outcome) => changed |= outcome == Outcome::Changed,
            Err(error) => failure = Some(error),
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(changed)
}

#[cfg(test)]
fn repair_registered_managed_claude_relay_settings() -> Result<bool, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    repair_registered_managed_claude_relay_settings_locked()
}

fn repair_registered_managed_claude_relay_settings_locked() -> Result<bool, LocalApiError> {
    let Some(env) = approved_managed_claude_relay_env()? else {
        return Ok(false);
    };
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    let mut changed = false;
    let mut failure = None;
    for slot in status
        .managed_slots
        .iter()
        .filter(|slot| slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed)
    {
        if let Some(root) = slot.config_dir.as_deref() {
            match provision_managed_claude_relay_settings_with_env(root, &env) {
                Ok(updated) => changed |= updated,
                Err(error) => failure = Some(error),
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(changed)
}

fn complete_claude_setup_mutation(
    status: ottto_protocol::ClaudeAccountsStatusV1,
) -> ottto_protocol::ClaudeAccountsStatusV1 {
    if !claude_setup_operation_is_terminal(&status) {
        if let Some(root) = status
            .managed_slots
            .iter()
            .find(|slot| {
                Some(&slot.slot_id) == status.setup_operation.slot_id.as_ref()
                    && slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            })
            .and_then(|slot| slot.config_dir.as_deref())
        {
            if let Err(error) = provision_managed_claude_relay_settings(root) {
                eprintln!("managed Claude settings repair skipped: {error}");
            }
        }
    }
    complete_claude_registry_mutation(status)
}

fn claude_setup_operation_is_terminal(status: &ottto_protocol::ClaudeAccountsStatusV1) -> bool {
    matches!(
        status.setup_operation.state,
        ottto_protocol::ClaudeAccountSetupOperationState::Complete
            | ottto_protocol::ClaudeAccountSetupOperationState::SetupStopped
            | ottto_protocol::ClaudeAccountSetupOperationState::SetupFailed
            | ottto_protocol::ClaudeAccountSetupOperationState::IdentityMismatch
    )
}

fn active_claude_browser_replay(
    store: &FileClaudeConfigSlotSettingsStore,
    operation_id: &str,
    mode: crate::claude_browser_auth::BrowserLoginMode,
) -> Result<Option<ottto_protocol::ClaudeAccountsStatusV1>, LocalApiError> {
    store
        .setup_operation_if_exists(operation_id)
        .map_err(claude_config_slot_settings_error)
        .map(|status| {
            status.and_then(|status| {
                crate::claude_browser_auth::active_replay_is_sealed(&status, operation_id, mode)
                    .then(|| {
                        crate::claude_browser_auth::annotate_status(
                            crate::agent_status::annotate_claude_accounts_status(status),
                        )
                    })
            })
        })
}

fn start_claude_browser_login(
    schema_version: u16,
    operation_id: String,
    target_id: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(claude_config_slot_settings_error)?,
        ),
    );
    let mode = if target_id.is_some() {
        crate::claude_browser_auth::BrowserLoginMode::Target
    } else {
        crate::claude_browser_auth::BrowserLoginMode::Generic
    };
    crate::claude_browser_auth::preflight_browser_binding(
        &operation_id,
        mode,
        None,
        target_id.as_deref(),
    )
    .map_err(LocalApiError::LocalOperationFailed)?;
    if let Some(replay) =
        crate::claude_browser_auth::terminal_replay(current.clone(), &operation_id)
    {
        return Ok(replay);
    }
    if target_id.is_some() {
        if let Some(replay) = active_claude_browser_replay(
            &store,
            &operation_id,
            crate::claude_browser_auth::BrowserLoginMode::Target,
        )? {
            return Ok(replay);
        }
    }
    let status = if let Some(target_id) = target_id {
        prepare_claude_account_target_mode(schema_version, operation_id.clone(), target_id, true)?
    } else {
        crate::claude_browser_auth::prepare_generic(current, &operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?
    };
    crate::claude_browser_auth::start(complete_claude_registry_mutation(status), mode)
        .map_err(LocalApiError::LocalOperationFailed)
}

fn start_claude_browser_reconnect(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(claude_config_slot_settings_error)?,
        ),
    );
    crate::claude_browser_auth::preflight_browser_binding(
        &operation_id,
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
        Some(slot_id),
        Some(&target_id),
    )
    .map_err(LocalApiError::LocalOperationFailed)?;
    if let Some(replay) = crate::claude_browser_auth::terminal_replay(current, &operation_id) {
        return Ok(replay);
    }
    if let Some(replay) = active_claude_browser_replay(
        &store,
        &operation_id,
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
    )? {
        return Ok(replay);
    }
    let status = reconnect_claude_account_target_mode(
        schema_version,
        operation_id,
        slot_id,
        target_id,
        true,
    )?;
    crate::claude_browser_auth::start(
        complete_claude_registry_mutation(status),
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
    )
    .map_err(LocalApiError::LocalOperationFailed)
}

fn set_claude_account_upkeep_consent(
    schema_version: u16,
    consent: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .set_upkeep_consent(schema_version, consent)
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_registry_mutation)
}

fn remove_claude_account(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let status = remove_claude_registration_with_relay_cleanup(schema_version, slot_id)?;
    // Registration removal is authoritative; current-slot filtering excludes
    // orphan collection state if best-effort cleanup cannot complete.
    let _ = crate::agent_status::prune_claude_slot_collection_state(slot_id);
    let _ = crate::claude_upkeep::prune_slot_upkeep_state(slot_id);
    crate::claude_refresher::prune_slot(slot_id);
    let status = complete_claude_registry_mutation(status);
    // The Companion confirms removal from the next status pass, not after the
    // event gap. Other registry mutations keep the ordinary request.
    crate::agent_status_refresh::request_now(&SourceKind::ClaudeCode);
    Ok(status)
}

pub(crate) fn remove_claude_registration_with_relay_cleanup(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let settings_guard = lock_managed_claude_settings();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = store.load().map_err(claude_config_slot_settings_error)?;
    // Preserve the store's request-validation contract before settings effects.
    if schema_version == current.schema_version && slot_id != "default" {
        if let Some(root) = current
            .managed_slots
            .iter()
            .find(|slot| {
                slot.slot_id == slot_id
                    && slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            })
            .and_then(|slot| slot.config_dir.as_deref())
        {
            validate_managed_claude_settings_root(root)?;
            crate::agent_configs::claude_managed_settings::disable_settings(Path::new(root), false)
                .map_err(|_| LocalApiError::LocalOperationFailed("managed Claude relay settings must be safely cleared before removing registration".into()))?;
        }
    }
    let status = store
        .remove(schema_version, slot_id)
        .map_err(claude_config_slot_settings_error)?;
    drop(settings_guard);
    Ok(status)
}

fn register_claude_account_path(
    schema_version: u16,
    config_dir: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .register_path(schema_version, config_dir)
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_registry_mutation)
}

fn prepare_claude_account(
    schema_version: u16,
    operation_id: String,
    target_id: Option<String>,
    expected_account_identifier_hash: Option<String>,
    expected_organization_identifier_hash: Option<String>,
    browser_mode: Option<crate::claude_browser_auth::BrowserLoginMode>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let _registry_guard = browser_mode
        .map(|_| crate::claude_browser_auth::registry_mutation_guard(&operation_id))
        .transpose()
        .map_err(LocalApiError::LocalOperationFailed)?;
    crate::claude_browser_auth::preflight_legacy_binding(&operation_id, target_id.as_deref())
        .map_err(LocalApiError::LocalOperationFailed)?;
    let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?;
    let reusable_root = if target_id.is_some() {
        crate::claude_browser_auth::claim_reusable_root(&operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?
    } else {
        None
    };
    if let Some(mode) = browser_mode {
        if let Err(error) = crate::claude_browser_auth::persist_registry_mutation_fence(
            &operation_id,
            mode,
            None,
            reusable_root.as_deref(),
            target_id.as_deref(),
            expected_account_identifier_hash.as_deref(),
            expected_organization_identifier_hash.as_deref(),
        ) {
            crate::claude_browser_auth::release_reusable_root_claim(&operation_id);
            if acquired {
                crate::claude_browser_auth::release_ceremony(&operation_id);
            }
            return Err(LocalApiError::LocalOperationFailed(error));
        }
    }
    let result = if let Some(config_dir) = reusable_root {
        store.prepare_managed_account_target_in_reusable_root(
            schema_version,
            operation_id.clone(),
            target_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
            config_dir,
        )
    } else {
        store.prepare_managed_account_target(
            schema_version,
            operation_id.clone(),
            target_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
        )
    }
    .map_err(claude_config_slot_settings_error)
    .map(complete_claude_setup_mutation);
    if result.is_err() {
        recover_failed_claude_browser_registry_mutation(
            &store,
            &operation_id,
            browser_mode,
            acquired,
        );
    } else if result
        .as_ref()
        .is_ok_and(claude_setup_operation_is_terminal)
        && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id))
    {
        crate::claude_browser_auth::release_ceremony(&operation_id);
    }
    result
}

fn recover_failed_claude_browser_registry_mutation(
    store: &FileClaudeConfigSlotSettingsStore,
    operation_id: &str,
    browser_mode: Option<crate::claude_browser_auth::BrowserLoginMode>,
    acquired: bool,
) {
    let fence_aborted = browser_mode.is_some()
        && store
            .setup_operation_if_exists(operation_id)
            .is_ok_and(|operation| operation.is_none())
        && crate::claude_browser_auth::abort_registry_mutation_fence(operation_id).is_ok();
    if browser_mode.is_some() && !fence_aborted {
        // The exact reusable-root claim is part of recovery authority. Never
        // release it on a transient core mutation or lookup failure.
        crate::claude_browser_auth::resume_operation_recovery(operation_id);
    } else {
        crate::claude_browser_auth::release_reusable_root_claim(operation_id);
    }
    if acquired && (browser_mode.is_none() || fence_aborted) {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
}

fn prepare_claude_account_legacy(
    schema_version: u16,
    operation_id: String,
    expected_account_identifier_hash: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
        .is_some()
    {
        crate::claude_browser_auth::preflight_legacy_binding(&operation_id, None)
            .map_err(LocalApiError::LocalOperationFailed)?;
        let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?;
        let result = store
            .replay_legacy_managed_account_setup(
                schema_version,
                &operation_id,
                expected_account_identifier_hash.as_deref(),
            )
            .map_err(claude_config_slot_settings_error)
            .map(complete_claude_setup_mutation);
        let terminal = result
            .as_ref()
            .is_ok_and(claude_setup_operation_is_terminal);
        if (acquired && result.is_err())
            || (terminal
                && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id)))
        {
            crate::claude_browser_auth::release_ceremony(&operation_id);
        }
        return result;
    }

    let expected_organization_identifier_hash = expected_account_identifier_hash
        .as_deref()
        .map(|account_hash| {
            let current = crate::agent_status::annotate_claude_accounts_status(
                store.load().map_err(claude_config_slot_settings_error)?,
            );
            let organizations = current
                .anchor_coverage
                .accounts
                .iter()
                .filter(|account| account.account_identifier_hash == account_hash)
                .filter_map(|account| account.organization_identifier_hash.clone())
                .collect::<BTreeSet<_>>();
            if organizations.len() != 1 {
                return Err(LocalApiError::InvalidRequest(
                    "legacy Claude setup requires exactly one strong organization binding for the expected account"
                        .to_string(),
                ));
            }
            Ok(organizations
                .into_iter()
                .next()
                .expect("one organization was required"))
        })
        .transpose()?;

    prepare_claude_account(
        schema_version,
        operation_id,
        None,
        expected_account_identifier_hash,
        expected_organization_identifier_hash,
        None,
    )
}

fn prepare_claude_account_target(
    schema_version: u16,
    operation_id: String,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    prepare_claude_account_target_mode(schema_version, operation_id, target_id, false)
}

fn prepare_claude_account_target_mode(
    schema_version: u16,
    operation_id: String,
    target_id: String,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if let Some(existing) = store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
    {
        if existing.setup_operation.target_id.as_deref() != Some(target_id.as_str()) {
            return Err(LocalApiError::InvalidRequest(
                "setup operation target does not match its original binding".to_string(),
            ));
        }
        return prepare_claude_account(
            schema_version,
            operation_id,
            Some(target_id),
            existing.setup_operation.expected_account_identifier_hash,
            existing
                .setup_operation
                .expected_organization_identifier_hash,
            browser_fence.then_some(crate::claude_browser_auth::BrowserLoginMode::Target),
        );
    }
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let target = current
        .anchor_coverage
        .accounts
        .iter()
        .find(|account| account.target_id.as_deref() == Some(target_id.as_str()))
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Claude account is not a current daemon-selected setup target".to_string(),
            )
        })?;
    if target.durability == ottto_protocol::ClaudeAccountAnchorDurabilityV1::Anchored
        || !target.setup_blockers.is_empty()
    {
        return Err(LocalApiError::InvalidRequest(
            "Claude anchor target is not currently eligible for managed setup".to_string(),
        ));
    }
    let organization_hash = target.organization_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Claude anchor target does not have an unambiguous organization binding".to_string(),
        )
    })?;
    prepare_claude_account(
        schema_version,
        operation_id,
        Some(target_id),
        Some(target.account_identifier_hash.clone()),
        Some(organization_hash),
        browser_fence.then_some(crate::claude_browser_auth::BrowserLoginMode::Target),
    )
}

fn reconnect_claude_account(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: Option<String>,
    expected_account_identifier_hash: String,
    expected_organization_identifier_hash: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    reconnect_claude_account_mode(
        schema_version,
        operation_id,
        slot_id,
        target_id,
        expected_account_identifier_hash,
        expected_organization_identifier_hash,
        false,
    )
}

fn reconnect_claude_account_mode(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: Option<String>,
    expected_account_identifier_hash: String,
    expected_organization_identifier_hash: Option<String>,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let descriptor = current
        .managed_slots
        .iter()
        .chain(current.external_slots.iter())
        .find(|descriptor| descriptor.slot_id == slot_id)
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(format!(
                "unknown registered Claude account slot_id {slot_id}"
            ))
        })?;
    if descriptor.collection.account_identifier_hash.as_deref()
        != Some(expected_account_identifier_hash.as_str())
    {
        return Err(LocalApiError::InvalidRequest(
            "reconnect account binding does not match the slot's last strong identity".to_string(),
        ));
    }
    let organization_hash = descriptor
        .collection
        .organization_identifier_hash
        .clone()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "reconnect requires the slot's last strong organization binding".to_string(),
            )
        })?;
    if expected_organization_identifier_hash
        .as_deref()
        .is_some_and(|expected| expected != organization_hash)
    {
        return Err(LocalApiError::InvalidRequest(
            "reconnect organization binding does not match the slot's last strong identity"
                .to_string(),
        ));
    }
    let _registry_guard = browser_fence
        .then(|| crate::claude_browser_auth::registry_mutation_guard(&operation_id))
        .transpose()
        .map_err(LocalApiError::LocalOperationFailed)?;
    crate::claude_browser_auth::preflight_legacy_binding(&operation_id, target_id.as_deref())
        .map_err(LocalApiError::LocalOperationFailed)?;
    let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?;
    if browser_fence {
        if let Err(error) = crate::claude_browser_auth::persist_registry_mutation_fence(
            &operation_id,
            crate::claude_browser_auth::BrowserLoginMode::Reconnect,
            Some(slot_id),
            descriptor.config_dir.as_deref(),
            target_id.as_deref(),
            Some(&expected_account_identifier_hash),
            Some(&organization_hash),
        ) {
            if acquired {
                crate::claude_browser_auth::release_ceremony(&operation_id);
            }
            return Err(LocalApiError::LocalOperationFailed(error));
        }
    }
    let result = store
        .begin_registered_slot_reconnect_target(
            schema_version,
            operation_id.clone(),
            slot_id,
            target_id,
            expected_account_identifier_hash,
            Some(organization_hash),
        )
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_setup_mutation);
    let terminal = result
        .as_ref()
        .is_ok_and(claude_setup_operation_is_terminal);
    let fence_aborted = result.is_err()
        && browser_fence
        && store
            .setup_operation_if_exists(&operation_id)
            .is_ok_and(|operation| operation.is_none())
        && crate::claude_browser_auth::abort_registry_mutation_fence(&operation_id).is_ok();
    if result.is_err() && browser_fence && !fence_aborted {
        crate::claude_browser_auth::resume_operation_recovery(&operation_id);
    }
    if (acquired && result.is_err() && (!browser_fence || fence_aborted))
        || (terminal
            && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id)))
    {
        crate::claude_browser_auth::release_ceremony(&operation_id);
    }
    result
}

fn reconnect_claude_account_target(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    reconnect_claude_account_target_mode(schema_version, operation_id, slot_id, target_id, false)
}

fn reconnect_claude_account_target_mode(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if let Some(existing) = store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
    {
        if existing.setup_operation.target_id.as_deref() != Some(target_id.as_str()) {
            return Err(LocalApiError::InvalidRequest(
                "reconnect operation target does not match its original binding".to_string(),
            ));
        }
        return reconnect_claude_account_mode(
            schema_version,
            operation_id,
            slot_id,
            Some(target_id),
            existing
                .setup_operation
                .expected_account_identifier_hash
                .ok_or_else(|| {
                    LocalApiError::InvalidRequest("reconnect lost account binding".to_string())
                })?,
            existing
                .setup_operation
                .expected_organization_identifier_hash,
            browser_fence,
        );
    }
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let target = current
        .anchor_coverage
        .accounts
        .iter()
        .find(|account| account.target_id.as_deref() == Some(target_id.as_str()))
        .ok_or_else(|| {
            LocalApiError::InvalidRequest("unknown Claude anchor reconnect target".to_string())
        })?;
    if target.durability != ottto_protocol::ClaudeAccountAnchorDurabilityV1::Anchored {
        return Err(LocalApiError::InvalidRequest(
            "Claude reconnect target is not a registered anchor".to_string(),
        ));
    }
    reconnect_claude_account_mode(
        schema_version,
        operation_id,
        slot_id,
        Some(target_id),
        target.account_identifier_hash.clone(),
        target.organization_identifier_hash.clone(),
        browser_fence,
    )
}

pub(crate) fn check_claude_account(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let result = check_claude_account_with_collector(
        schema_version,
        operation_id,
        expected_account_identifier_hash,
        crate::agent_status::collect_registered_claude_slot_status,
    );
    if result.as_ref().is_ok_and(|status| {
        matches!(
            status.setup_operation.state,
            ClaudeAccountSetupOperationState::Complete
                | ClaudeAccountSetupOperationState::SetupStopped
                | ClaudeAccountSetupOperationState::SetupFailed
                | ClaudeAccountSetupOperationState::IdentityMismatch
        )
    }) {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
    result
}

fn check_claude_account_with_collector<F>(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
    collector: F,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError>
where
    F: FnOnce(&str, String, String) -> ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
{
    check_claude_account_with_hooks(
        schema_version,
        operation_id,
        expected_account_identifier_hash,
        || {},
        collector,
    )
}

fn check_claude_account_with_hooks<B, F>(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
    before_validating: B,
    collector: F,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError>
where
    B: FnOnce(),
    F: FnOnce(&str, String, String) -> ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
{
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = store
        .setup_operation(operation_id)
        .map_err(claude_config_slot_settings_error)?;
    if let (Some(bound), Some(requested)) = (
        current
            .setup_operation
            .expected_account_identifier_hash
            .as_deref(),
        expected_account_identifier_hash,
    ) {
        if bound != requested {
            return Err(LocalApiError::InvalidRequest(
                "setup operation expected account does not match its original binding".to_string(),
            ));
        }
    }
    if current.setup_operation.kind
        == ottto_protocol::ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
    {
        let reconnect_slot_registered =
            current
                .setup_operation
                .slot_id
                .as_deref()
                .is_some_and(|slot_id| {
                    current
                        .managed_slots
                        .iter()
                        .chain(current.external_slots.iter())
                        .any(|slot| slot.slot_id == slot_id)
                });
        if !reconnect_slot_registered {
            return Err(LocalApiError::InvalidRequest(
                "reconnect operation slot is no longer registered".to_string(),
            ));
        }
    }

    // A crash-persisted Preparing intent has no registered credential slot to
    // inspect yet. Its authenticated status remains actionable and replaying
    // prepare resumes the same deterministic path transaction.
    if matches!(
        current.setup_operation.state,
        ClaudeAccountSetupOperationState::Preparing
            | ClaudeAccountSetupOperationState::SetupStopped
    ) {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            current,
        ));
    }
    let Some(_observation_guard) = store
        .try_setup_operation_observation(operation_id)
        .map_err(claude_config_slot_settings_error)?
    else {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            current,
        ));
    };
    let historical_state = current.setup_operation.state.clone();
    let historical_account_hash = current.setup_operation.account_identifier_hash.clone();
    let expected_organization_hash = current
        .setup_operation
        .expected_organization_identifier_hash
        .clone();
    let historical_organization_hash = current.setup_operation.organization_identifier_hash.clone();
    before_validating();
    let validating = store
        .transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Validating,
            historical_account_hash.as_deref(),
            historical_organization_hash.as_deref(),
            Some("Checking the exact registered Claude Code login."),
        )
        .map_err(claude_config_slot_settings_error)?;
    if validating.setup_operation.state != ClaudeAccountSetupOperationState::Validating {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            validating,
        ));
    }

    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    let slot_id = current
        .setup_operation
        .slot_id
        .as_deref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let direct_slot_status = collector(slot_id, captured_at, expires_at);
    crate::agent_status::persist_one_claude_slot_collection_state(slot_id, &direct_slot_status)
        .or_state_poisoned()?;
    let refreshed = store
        .setup_operation(operation_id)
        .map_err(claude_config_slot_settings_error)?;
    let observed_account_hash = direct_slot_status.account_identifier_hash.as_deref();
    let observed_organization_hash = direct_slot_status.organization_identifier_hash.as_deref();
    let bound_account_hash = refreshed
        .setup_operation
        .expected_account_identifier_hash
        .as_deref()
        .or(expected_account_identifier_hash);
    let bound_organization_hash = refreshed
        .setup_operation
        .expected_organization_identifier_hash
        .as_deref();
    // `ConcurrentMutation` is a same-pass race (Claude Code rewrote the
    // account file between two reads), not proof of another account: a real
    // different owner is still caught by the binding comparisons below.
    if direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::IdentityMismatch
        || matches!((bound_account_hash, observed_account_hash), (Some(bound), Some(observed)) if bound != observed)
        || matches!((bound_organization_hash, observed_organization_hash), (Some(bound), Some(observed)) if bound != observed)
    {
        return store
            .transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::IdentityMismatch,
                None,
                None,
                Some("The exact slot did not match the expected Claude account. Complete /login with the intended account, then retry."),
            )
            .map_err(claude_config_slot_settings_error)
            .map(crate::agent_status::annotate_claude_accounts_status);
    }

    let full_read = direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::Fresh
        && direct_slot_status.last_full_quota_read_at.is_some()
        && direct_slot_status.has_account_windows
        && direct_slot_status.has_scoped_limits;
    let result = if full_read {
        let (Some(account_hash), Some(organization_hash)) =
            (observed_account_hash, observed_organization_hash)
        else {
            return Err(LocalApiError::StatePoisoned);
        };
        store
            .transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Reading,
                Some(account_hash),
                Some(organization_hash),
                Some("Identity matched. Reading full Claude quota for this exact account."),
            )
            .map_err(claude_config_slot_settings_error)?;
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Complete,
            Some(account_hash),
            Some(organization_hash),
            Some("Claude account identity and full quota read are complete."),
        )
    } else if let (Some(account_hash), Some(organization_hash)) =
        (observed_account_hash, observed_organization_hash)
    {
        if historical_state == ClaudeAccountSetupOperationState::Complete {
            store.transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Complete,
                Some(account_hash),
                Some(organization_hash),
                Some(
                    "Claude account remains identity-validated; the last full reading is retained.",
                ),
            )
        } else {
            store.transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Reading,
                Some(account_hash),
                Some(organization_hash),
                Some("Identity is validated; the full quota read has not completed yet."),
            )
        }
    } else if historical_state == ClaudeAccountSetupOperationState::Complete {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Complete,
            historical_account_hash.as_deref(),
            historical_organization_hash.as_deref(),
            Some("This setup remains complete, but current exact-slot identity or quota evidence is temporarily unavailable."),
        )
    } else if direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::ConcurrentMutation {
        // No verified account yet (an owner switch arrives as
        // `IdentityMismatch` above): keep waiting without asking for /login.
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
            None,
            None,
            Some("Ottto could not confirm this login yet; it will check it again."),
        )
    } else if matches!(
        direct_slot_status.state,
        ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            | ClaudeConfigSlotCollectionStateV1::IdentityUnknown
            | ClaudeConfigSlotCollectionStateV1::Unverified
    ) {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
            None,
            None,
            Some("Waiting for the customer to complete official Claude Code /login."),
        )
    } else {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::SetupFailed,
            None,
            None,
            Some("Claude account validation could not complete from safe local evidence."),
        )
    };
    result
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
}

fn stop_waiting_for_claude_account(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    if crate::claude_browser_auth::request_cancel(operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?
    {
        return FileClaudeConfigSlotSettingsStore::default()
            .load()
            .map_err(claude_config_slot_settings_error)
            .map(crate::agent_status::annotate_claude_accounts_status)
            .map(crate::claude_browser_auth::annotate_status);
    }
    let result = FileClaudeConfigSlotSettingsStore::default()
        .stop_waiting(schema_version, operation_id)
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
        .map(crate::claude_browser_auth::annotate_status);
    if result.is_ok() {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
    result
}

fn claude_config_slot_settings_error(error: ClaudeConfigSlotSettingsError) -> LocalApiError {
    match error {
        ClaudeConfigSlotSettingsError::Invalid(message) => LocalApiError::InvalidRequest(message),
        ClaudeConfigSlotSettingsError::State(_) => LocalApiError::StatePoisoned,
    }
}

fn load_codex_account_settings() -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .load()
        .map_err(codex_account_slot_settings_error)
        .map(crate::agent_status::annotate_codex_accounts_status)
}

/// How long a status read may reuse the last annotated Codex accounts status.
/// Annotation serves each home's saved quota (it never starts `codex
/// app-server`), but it still runs the local `codex login status` and model
/// listing per home. The companion polls this read every few seconds while an
/// accounts surface is visible, so the reuse bounds those local runs.
const CODEX_ACCOUNTS_STATUS_READ_REUSE: Duration = Duration::from_secs(30);

struct CachedCodexAccountsStatus {
    settings: ottto_protocol::CodexAccountsStatusV1,
    /// [`crate::agent_status::saved_codex_quota_generation`] when annotated.
    saved_quota_generation: u64,
    annotated: ottto_protocol::CodexAccountsStatusV1,
    annotated_at: Instant,
}

/// The polled read. Reuses a recent annotation while the stored settings and
/// the saved quota readings are unchanged; any settings change (connect,
/// remove, prepare) or newly saved reading misses the cache. Holding the lock
/// across annotation also collapses concurrent polls into one annotation.
fn load_codex_account_settings_for_status_read(
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    static CACHE: Mutex<Option<CachedCodexAccountsStatus>> = Mutex::new(None);
    let settings = FileCodexAccountSlotSettingsStore::default()
        .load()
        .map_err(codex_account_slot_settings_error)?;
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let saved_quota_generation = crate::agent_status::saved_codex_quota_generation();
    if let Some(cached) = cache.as_ref() {
        if status_read_reusable(
            &(&cached.settings, cached.saved_quota_generation),
            cached.annotated_at,
            &(&settings, saved_quota_generation),
            Instant::now(),
        ) {
            return Ok(cached.annotated.clone());
        }
    }
    let annotated = crate::agent_status::annotate_codex_accounts_status(settings.clone());
    *cache = Some(CachedCodexAccountsStatus {
        settings,
        saved_quota_generation,
        annotated: annotated.clone(),
        annotated_at: Instant::now(),
    });
    Ok(annotated)
}

fn status_read_reusable<T: PartialEq>(
    cached_settings: &T,
    annotated_at: Instant,
    settings: &T,
    now: Instant,
) -> bool {
    cached_settings == settings
        && now.saturating_duration_since(annotated_at) < CODEX_ACCOUNTS_STATUS_READ_REUSE
}

fn prepare_codex_account(
    schema_version: u16,
    operation_id: String,
    expected_account_identifier_hash: String,
    expected_workspace_identifier_hash: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .prepare_managed_account(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        )
        .map_err(codex_account_slot_settings_error)
}

fn prepare_open_codex_account(
    schema_version: u16,
    operation_id: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .prepare_open_account(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)
}

fn prepare_codex_account_target(
    schema_version: u16,
    operation_id: String,
    target_id: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let current = load_codex_account_settings()?;
    let (account_hash, workspace_hash) =
        codex_account_target_binding(&current, target_id.as_str())?;
    prepare_codex_account(schema_version, operation_id, account_hash, workspace_hash)
}

fn codex_account_target_binding(
    current: &ottto_protocol::CodexAccountsStatusV1,
    target_id: &str,
) -> Result<(String, String), LocalApiError> {
    let target = current
        .target_coverage
        .targets
        .iter()
        .find(|target| target.target_id == target_id)
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex workspace is not a current daemon-selected setup target".to_string(),
            )
        })?;
    if !target.connectable
        || target.durability == ottto_protocol::CodexAccountTargetDurabilityV1::Durable
        || !target.setup_blockers.is_empty()
    {
        return Err(LocalApiError::InvalidRequest(
            "Codex workspace target is not currently eligible for durable setup".to_string(),
        ));
    }
    let account_hash = target.account_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Codex workspace target does not have a confirmed account identity".to_string(),
        )
    })?;
    let workspace_hash = target.workspace_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Codex workspace target does not have a confirmed workspace identity".to_string(),
        )
    })?;
    Ok((account_hash, workspace_hash))
}

fn reconnect_codex_account(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    expected_account_identifier_hash: String,
    expected_workspace_identifier_hash: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .begin_reconnect(
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        )
        .map_err(codex_account_slot_settings_error)
}

fn check_codex_account(
    schema_version: u16,
    operation_id: &str,
    explicit: bool,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let store = FileCodexAccountSlotSettingsStore::default();
    let current_operation = store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?;
    // A daemon-run sign-in reads the account itself when `codex login` ends,
    // so a check while it runs (an older client polling, or a second app)
    // only reports where it is.
    if current_operation.state == CodexAccountSetupOperationStateV1::Complete
        || crate::codex_sign_in::is_running(&current_operation)
    {
        return store
            .load()
            .map_err(codex_account_slot_settings_error)
            .map(crate::agent_status::annotate_codex_accounts_status);
    }
    // `codex login` completes outside this request. A visible client is allowed
    // to poll while the provider-owned browser flow is open, but an incomplete
    // login is progress, not a failed durable connection. Probe before moving
    // the persisted operation to `validating`; only a complete exact identity
    // and fresh quota snapshot crosses that state boundary. Clients poll this
    // every few seconds, so the probe's provider reads are spaced per home.
    let pending_collection = if current_operation.state
        == CodexAccountSetupOperationStateV1::WaitingForUserLogin
    {
        let slot_id = current_operation.slot_id.as_deref().ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex setup operation has no durable connection slot".to_string(),
            )
        })?;
        match crate::agent_status::collect_registered_codex_slot_for_setup(
            slot_id,
            crate::agent_status::CodexSetupRead::WaitingForLogin {
                operation_id,
                explicit,
            },
        ) {
            Ok(result) => Some(Ok(result)),
            Err(crate::agent_status::CodexSlotSetupCollectionError::ProviderLoginPending(_)) => {
                return store
                    .load()
                    .map_err(codex_account_slot_settings_error)
                    .map(crate::agent_status::annotate_codex_accounts_status);
            }
            Err(error) => Some(Err(error)),
        }
    } else {
        None
    };
    store
        .begin_validation(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)?;
    let slot_id = codex_setup_slot_id(&store, operation_id)?;
    if store
        .is_verifying_pinned_workspace(operation_id)
        .map_err(codex_account_slot_settings_error)?
    {
        return verify_pinned_codex_setup(&store, schema_version, operation_id, &slot_id)
            .map(|(status, _)| crate::agent_status::annotate_codex_accounts_status(status));
    }
    let collection = match pending_collection {
        Some(result) => result,
        None => crate::agent_status::collect_registered_codex_slot_for_setup(
            &slot_id,
            crate::agent_status::CodexSetupRead::Validation,
        ),
    };
    finish_codex_setup_validation(&store, schema_version, operation_id, &slot_id, collection)
        .map(|(status, _)| crate::agent_status::annotate_codex_accounts_status(status))
}

/// How the validation of a Codex setup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexSetupValidationEnd {
    /// The exact account and workspace is connected.
    Accepted,
    IdentityMismatch,
    DuplicateAccount,
    /// The workspace restriction did not hold in a fresh provider session.
    WorkspaceNotKept,
    /// The account read failed; the setup failed with its message.
    ReadFailed,
}

/// The managed slot of the setup operation.
pub(crate) fn codex_setup_slot_id(
    store: &FileCodexAccountSlotSettingsStore,
    operation_id: &str,
) -> Result<String, LocalApiError> {
    store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?
        .slot_id
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex setup operation has no durable connection slot".to_string(),
            )
        })
}

/// The fresh restricted read that accepts a pinned workspace, for a setup
/// whose restriction is already durable.
pub(crate) fn verify_pinned_codex_setup(
    store: &FileCodexAccountSlotSettingsStore,
    schema_version: u16,
    operation_id: &str,
    slot_id: &str,
) -> Result<
    (
        ottto_protocol::CodexAccountsStatusV1,
        CodexSetupValidationEnd,
    ),
    LocalApiError,
> {
    let operation = store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?;
    let account_hash = operation
        .account_identifier_hash
        .as_deref()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Pinned Codex verification has no account identity.".to_string(),
            )
        })?;
    let workspace_hash = operation
        .workspace_identifier_hash
        .as_deref()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Pinned Codex verification has no workspace identity.".to_string(),
            )
        })?;
    let sign_in_home = store
        .setup_sign_in_home(slot_id)
        .map_err(codex_account_slot_settings_error)?;
    let slot_home = store
        .slot_home(slot_id)
        .map_err(codex_account_slot_settings_error)?;
    // A login in a staging home moves into the slot only when the read saw
    // the same file from its start to its end: one replaced meanwhile (another
    // sign-in into that home) may belong to someone else.
    let read_from = ottto_core::codex_auth_file_mark(&sign_in_home);
    match crate::agent_status::collect_registered_codex_slot_for_setup(
        slot_id,
        crate::agent_status::CodexSetupRead::Validation,
    ) {
        Ok((pinned, _))
            if pinned.account_identifier_hash == account_hash
                && pinned.workspace_identifier_hash == workspace_hash =>
        {
            let validated_login = ottto_core::codex_auth_file_mark(&sign_in_home);
            if sign_in_home != slot_home
                && (validated_login.is_none() || validated_login != read_from)
            {
                return store
                    .fail_validation(
                        schema_version,
                        operation_id,
                        "The Codex login changed while Ottto checked it. Sign in again.",
                    )
                    .map_err(codex_account_slot_settings_error)
                    .map(|status| (status, CodexSetupValidationEnd::ReadFailed));
            }
            // The verified login is published into the slot's home under that
            // home's read lock, so no limit read rewrites the slot's credential
            // meanwhile; the store publishes only the file with this mark.
            crate::agent_status::with_codex_home_read_lock(&slot_home, || {
                store
                    .complete_pinned_verification(
                        schema_version,
                        operation_id,
                        account_hash,
                        workspace_hash,
                        validated_login,
                    )
                    .inspect(|_| {
                        if sign_in_home != slot_home {
                            crate::agent_status::adopt_saved_codex_reading(
                                &sign_in_home,
                                &slot_home,
                            );
                        }
                    })
            })
            .map_err(codex_account_slot_settings_error)
            .map(|status| (status, CodexSetupValidationEnd::Accepted))
        }
        _ => store
            .fail_validation(
                schema_version,
                operation_id,
                "Codex workspace restriction did not survive a fresh provider restart.",
            )
            .map_err(codex_account_slot_settings_error)
            .map(|status| (status, CodexSetupValidationEnd::WorkspaceNotKept)),
    }
}

/// Validate a setup from one account read of its home: accept the exact
/// identity (pinning its workspace and verifying the pin in a fresh read),
/// or record a mismatch, a duplicate, or the read's failure.
pub(crate) fn finish_codex_setup_validation(
    store: &FileCodexAccountSlotSettingsStore,
    schema_version: u16,
    operation_id: &str,
    slot_id: &str,
    collection: Result<
        (
            crate::agent_status::CodexStrongIdentity,
            ottto_protocol::CodexAccountSlotCollectionStatusV1,
        ),
        crate::agent_status::CodexSlotSetupCollectionError,
    >,
) -> Result<
    (
        ottto_protocol::CodexAccountsStatusV1,
        CodexSetupValidationEnd,
    ),
    LocalApiError,
> {
    let (identity, _) = match collection {
        Ok(result) => result,
        Err(error) => {
            return store
                .fail_validation(schema_version, operation_id, error.message())
                .map_err(codex_account_slot_settings_error)
                .map(|status| (status, CodexSetupValidationEnd::ReadFailed));
        }
    };
    let duplicate = store
        .has_registered_binding(
            &identity.account_identifier_hash,
            &identity.workspace_identifier_hash,
            Some(slot_id),
        )
        .map_err(codex_account_slot_settings_error)?;
    let status = store
        .finish_validation(
            schema_version,
            operation_id,
            identity.account_identifier_hash.clone(),
            identity.workspace_identifier_hash.clone(),
            &identity.raw_workspace_id,
            duplicate,
        )
        .map_err(codex_account_slot_settings_error)?;
    if store
        .is_verifying_pinned_workspace(operation_id)
        .map_err(codex_account_slot_settings_error)?
    {
        return verify_pinned_codex_setup(store, schema_version, operation_id, slot_id);
    }
    let end = match status.setup_operation.state {
        CodexAccountSetupOperationStateV1::DuplicateAccount => {
            CodexSetupValidationEnd::DuplicateAccount
        }
        CodexAccountSetupOperationStateV1::Complete => CodexSetupValidationEnd::Accepted,
        _ => CodexSetupValidationEnd::IdentityMismatch,
    };
    Ok((status, end))
}

/// v26: start the daemon-run sign-in of a setup operation.
fn start_codex_sign_in(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    crate::codex_sign_in::start(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)?;
    load_codex_account_settings()
}

fn stop_waiting_for_codex_account(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    // A running `codex login` ends first, so it cannot write into a home that
    // stopping is about to remove; the sign-in then stops the setup itself.
    if crate::codex_sign_in::cancel(operation_id) {
        return load_codex_account_settings();
    }
    FileCodexAccountSlotSettingsStore::default()
        .stop_waiting(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)
        .map(crate::agent_status::annotate_codex_accounts_status)
}

fn set_codex_quota_refresh_consent(
    schema_version: u16,
    consent: bool,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let status = FileCodexAccountSlotSettingsStore::default()
        .set_quota_refresh_consent(schema_version, consent)
        .map_err(codex_account_slot_settings_error)?;
    // Switched on: the schedule's next round runs now, not at its next wake.
    if consent {
        crate::agent_status::wake_codex_quota_scheduler();
    }
    Ok(crate::agent_status::annotate_codex_accounts_status(status))
}

fn remove_codex_account(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let store = FileCodexAccountSlotSettingsStore::default();
    // A sign-in into the home being removed ends first, so `codex login`
    // never writes into a removed home.
    if let Ok(status) = store.load() {
        let operation = &status.setup_operation;
        if operation.slot_id.as_deref() == Some(slot_id)
            && crate::codex_sign_in::is_running(operation)
            && status
                .managed_slots
                .iter()
                .any(|slot| slot.slot_id == slot_id)
        {
            if let Some(operation_id) = operation.operation_id.as_deref() {
                stop_waiting_for_codex_account(schema_version, operation_id)?;
            }
        }
    }
    // Under the home's read lock: a limits read that may be renewing its login
    // ends (and drains) before the home is removed, so none writes it back.
    let remove = || store.remove(schema_version, slot_id);
    match store.slot_home(slot_id) {
        Ok(home) => crate::agent_status::with_codex_home_read_lock(&home, remove),
        Err(_) => remove(),
    }
    .map_err(codex_account_slot_settings_error)
    .map(crate::agent_status::annotate_codex_accounts_status)
    .inspect(|_| crate::agent_status_refresh::request_now(&SourceKind::Codex))
}

fn codex_account_slot_settings_error(error: CodexAccountSlotSettingsError) -> LocalApiError {
    match error {
        CodexAccountSlotSettingsError::Invalid(message) => LocalApiError::InvalidRequest(message),
        CodexAccountSlotSettingsError::State(_) => LocalApiError::StatePoisoned,
    }
}

fn agent_context(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentContextQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto context",
        |api_base_url, connection| agent_context_url(api_base_url, connection, &query),
    )
}

fn agent_costs(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentCostsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto costs",
        |api_base_url, connection| agent_costs_url(api_base_url, connection, &query),
    )
}

fn agent_sessions(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentSessionsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto sessions",
        |api_base_url, connection| agent_sessions_url(api_base_url, connection, &query),
    )
}

fn agent_recommendations(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentRecommendationsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    observe_agent_read(
        daemon,
        authorization,
        "ottto recommendations",
        |api_base_url, connection| agent_recommendations_url(api_base_url, connection, &query),
    )
}

fn agent_provider_impact(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentProviderImpactQuery,
) -> Result<serde_json::Value, LocalApiError> {
    observe_agent_read(
        daemon,
        authorization,
        "ottto provider-impact",
        |api_base_url, connection| agent_provider_impact_url(api_base_url, connection, &query),
    )
}

/// One observed agent read: the setup-run binding and its observation come
/// from `observe_setup_run_read`, the request from `agent_read_with_refresh`.
fn observe_agent_read(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
    read_url: impl Fn(&str, &LocalConnectionBinding) -> String,
) -> Result<serde_json::Value, LocalApiError> {
    observe_setup_run_read(
        daemon,
        authorization,
        command,
        |api_base_url, connection, setup_run_token| {
            agent_read_with_refresh(api_base_url, connection, setup_run_token, &read_url)
        },
    )
}

const TIMEZONE_OVERRIDE_UNSUPPORTED: &str =
    "--timezone is not supported. Ottto uses the timezone saved in your account settings for calendar windows.";

/// Calendar windows follow the account's saved timezone; Ottto rejects an
/// explicit `timezone=` query, so refuse it locally with that reason instead
/// of forwarding a request that can only fail.
fn reject_timezone_override(timezone: Option<&str>) -> Result<(), LocalApiError> {
    if timezone.is_some_and(|value| !value.trim().is_empty()) {
        return Err(LocalApiError::InvalidRequest(
            TIMEZONE_OVERRIDE_UNSUPPORTED.to_string(),
        ));
    }
    Ok(())
}

/// Run one setup-run agent read and record whether Ottto still accepts this
/// Mac's setup run, so local status stops reporting a rejected run as
/// complete. Only an authoritative terminal answer from the device-secret
/// refresh counts (`terminal_refresh_rejection`): every read path propagates
/// that refresh error unchanged, so it is the read's final error. A read 401,
/// a 401 retried after a successful refresh, an unrecognized refresh detail,
/// and network, timeout or other backend failures say nothing about the run
/// and leave the recorded state unchanged. A successful read clears it.
/// Reads run concurrently with setup and sign-in, so the outcome is recorded
/// against exactly the binding this read used, and dropped by the daemon if
/// that binding has since been replaced. Reads of one binding also run
/// concurrently with each other, so a success clears only the rejection that
/// was already recorded when this read started, never a newer one.
fn observe_setup_run_read<T>(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
    read: impl FnOnce(&str, &LocalConnectionBinding, &str) -> Result<T, LocalApiError>,
) -> Result<T, LocalApiError> {
    let (api_base_url, start) = setup_run_agent_read_binding(daemon, authorization, command)?;
    let result =
        setup_run_token_for_connection(&api_base_url, &start.binding).and_then(|credentials| {
            read(
                &api_base_url,
                &credentials.connection,
                &credentials.setup_run_token,
            )
        });
    match &result {
        Ok(_) => {
            let _ = daemon.record_setup_run_read_accepted(&start);
        }
        Err(error) => {
            if let Some(rejection) = terminal_refresh_rejection(error) {
                let _ = daemon.record_setup_run_read_rejected(&start.binding, rejection);
            }
        }
    }
    result
}

/// `ottto cloud status`: read-only connector status through the setup-run
/// bridge. Connecting or changing a cloud connector happens in the web app.
fn cloud_status(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    validate_cloud_status_source(source.as_deref())?;
    observe_setup_run_read(
        daemon,
        authorization,
        "ottto cloud",
        |api_base_url, connection, setup_run_token| match cloud_status_with_base(
            api_base_url,
            connection,
            setup_run_token,
            source.as_deref(),
        ) {
            Ok(value) => Ok(value),
            Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
                let refreshed =
                    refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
                cloud_status_with_base(
                    api_base_url,
                    &refreshed.connection,
                    &refreshed.setup_run_token,
                    source.as_deref(),
                )
            }
            Err(error) => Err(error),
        },
    )
}

fn validate_cloud_status_source(source: Option<&str>) -> Result<(), LocalApiError> {
    if source.is_some_and(|source| !matches!(source, "bedrock" | "vertex")) {
        return Err(LocalApiError::InvalidRequest(
            "cloud source must be bedrock or vertex".to_string(),
        ));
    }
    Ok(())
}

fn cloud_status_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: Option<&str>,
) -> Result<serde_json::Value, LocalApiError> {
    let header = [("X-Ottto-Setup-Run-Token", setup_run_token)];
    let suffix = source
        .map(|source| format!("?source={}", form_url_encode(source)))
        .unwrap_or_default();
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/cloud/status{suffix}",
            connection.setup_run_id
        ),
    );
    backend_get_agent_read_json(&url, &header)
}

fn setup_run_agent_read_binding(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
) -> Result<(String, SetupRunReadStart), LocalApiError> {
    let status = status_for(daemon, authorization)?;
    if status.account.state != LocalAccountState::Connected {
        return Err(LocalApiError::InvalidRequest(format!(
            "{command} requires this Mac to be connected to Ottto"
        )));
    }
    let start = daemon
        .setup_run_read_start()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let api_base_url = validated_api_base_url(Some(start.binding.api_base_url.as_str()))?;
    Ok((api_base_url, start))
}

fn require_authorized_local_client(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<(), LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => {
            daemon.control_token.authorize(token)?;
            daemon.require_usable_state()
        }
        RequestAuthorization::TrustedCompanionApp => daemon.require_usable_state(),
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

fn diagnostics_collect(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    upload: bool,
    upload_approval: Option<DiagnosticsUploadApproval>,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    let mut bundle = match authorization {
        RequestAuthorization::Token(token) => daemon.diagnostics_stub(token)?,
        RequestAuthorization::TrustedCompanionApp => {
            daemon.diagnostics_stub_for_trusted_client()?
        }
        RequestAuthorization::Untrusted => return Err(LocalApiError::LocalClientNotTrusted),
    };

    if !upload {
        bundle.upload = diagnostics_local_only_upload_report();
        return to_value(bundle);
    }

    let approval = upload_approval.ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "diagnostics upload requires --approve-upload and --accept-retention-disclosure"
                .to_string(),
        )
    })?;
    validate_diagnostics_upload_approval(&approval)?;
    let upload_authorization = diagnostics_upload_authorization(daemon, authorization, &approval)?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        upload_authorization
            .connection_api_base_url()
            .map(String::as_str)
    }))?;

    bundle.upload = upload_diagnostics_bundle(&api_base_url, &bundle, &upload_authorization)?;
    to_value(bundle)
}

fn validate_diagnostics_upload_approval(
    approval: &DiagnosticsUploadApproval,
) -> Result<(), LocalApiError> {
    if !approval.approved {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires --approve-upload".to_string(),
        ));
    }
    if !approval.retention_disclosure_accepted {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires --accept-retention-disclosure".to_string(),
        ));
    }
    normalize_support_claim(approval.support_claim.as_deref())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticsUploadAuth {
    ConnectedAccount {
        setup_run_id: String,
        setup_run_token: String,
        api_base_url: String,
    },
    SupportClaim {
        claim: String,
    },
}

impl DiagnosticsUploadAuth {
    fn authorization_kind(&self) -> DiagnosticsUploadAuthorization {
        match self {
            DiagnosticsUploadAuth::ConnectedAccount { .. } => {
                DiagnosticsUploadAuthorization::ConnectedAccount
            }
            DiagnosticsUploadAuth::SupportClaim { .. } => {
                DiagnosticsUploadAuthorization::SupportClaim
            }
        }
    }

    fn connection_api_base_url(&self) -> Option<&String> {
        match self {
            DiagnosticsUploadAuth::ConnectedAccount { api_base_url, .. } => Some(api_base_url),
            DiagnosticsUploadAuth::SupportClaim { .. } => None,
        }
    }

    fn support_claim_provided(&self) -> bool {
        matches!(self, DiagnosticsUploadAuth::SupportClaim { .. })
    }
}

fn diagnostics_upload_authorization(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    approval: &DiagnosticsUploadApproval,
) -> Result<DiagnosticsUploadAuth, LocalApiError> {
    if let Some(claim) = normalize_support_claim(approval.support_claim.as_deref())? {
        return Ok(DiagnosticsUploadAuth::SupportClaim { claim });
    }

    let status = status_for(daemon, authorization)?;
    if status.account.state != LocalAccountState::Connected {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires an Ottto login or --support-claim".to_string(),
        ));
    }

    let connection = daemon
        .connection_for_authorized_client()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    Ok(DiagnosticsUploadAuth::ConnectedAccount {
        setup_run_id: connection.setup_run_id,
        setup_run_token,
        api_base_url: connection.api_base_url,
    })
}

fn normalize_support_claim(raw: Option<&str>) -> Result<Option<String>, LocalApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics support claim cannot be empty".to_string(),
        ));
    }
    if value.len() > 128 || value.chars().any(char::is_control) {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics support claim is invalid".to_string(),
        ));
    }
    Ok(Some(value.to_string()))
}

#[derive(Debug, Serialize)]
struct DiagnosticsUploadBody<'a> {
    bundle: &'a DiagnosticsBundle,
    approval: DiagnosticsUploadApprovalSummary,
    client: DiagnosticsUploadClient,
}

#[derive(Debug, Serialize)]
struct DiagnosticsUploadApprovalSummary {
    approved: bool,
    retention_disclosure_accepted: bool,
    retention_disclosure: &'static str,
    authorization: DiagnosticsUploadAuthorization,
    support_claim_provided: bool,
}

#[derive(Debug, Serialize)]
struct DiagnosticsUploadClient {
    protocol_version: u16,
    local_platform_version: String,
    machine_id: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticsUploadResponse {
    upload_id: Option<String>,
    uploaded_at: Option<String>,
}

fn upload_diagnostics_bundle(
    api_base_url: &str,
    bundle: &DiagnosticsBundle,
    authorization: &DiagnosticsUploadAuth,
) -> Result<DiagnosticsUploadReport, LocalApiError> {
    let url = diagnostics_upload_url(api_base_url, authorization);
    let body = DiagnosticsUploadBody {
        bundle,
        approval: DiagnosticsUploadApprovalSummary {
            approved: true,
            retention_disclosure_accepted: true,
            retention_disclosure: DIAGNOSTICS_RETENTION_DISCLOSURE,
            authorization: authorization.authorization_kind(),
            support_claim_provided: authorization.support_claim_provided(),
        },
        client: DiagnosticsUploadClient {
            protocol_version: PROTOCOL_VERSION,
            local_platform_version: bundle
                .section_item("versions", "daemon_version")
                .and_then(redacted_string)
                .unwrap_or_else(|| "unknown".to_string()),
            machine_id: bundle.machine_id.clone(),
        },
    };

    let response: DiagnosticsUploadResponse = match authorization {
        DiagnosticsUploadAuth::ConnectedAccount {
            setup_run_token, ..
        } => backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)]),
        DiagnosticsUploadAuth::SupportClaim { claim } => {
            backend_post_json(&url, &body, &[("X-Ottto-Support-Claim", claim)])
        }
    }?;

    Ok(DiagnosticsUploadReport {
        requested: true,
        status: DiagnosticsUploadStatus::Uploaded,
        approval_required: true,
        approved: true,
        retention: DiagnosticsRetentionDisclosure {
            accepted: true,
            text: DIAGNOSTICS_RETENTION_DISCLOSURE.to_string(),
        },
        authorization: authorization.authorization_kind(),
        support_claim_provided: authorization.support_claim_provided(),
        upload_id: response.upload_id,
        uploaded_at: Some(
            response
                .uploaded_at
                .unwrap_or_else(current_rfc3339_timestamp),
        ),
    })
}

fn diagnostics_upload_url(api_base_url: &str, authorization: &DiagnosticsUploadAuth) -> String {
    match authorization {
        DiagnosticsUploadAuth::ConnectedAccount { setup_run_id, .. } => api_url_with_base(
            api_base_url,
            &format!("/api/v1/setup-runs/{setup_run_id}/local-client/diagnostics"),
        ),
        DiagnosticsUploadAuth::SupportClaim { .. } => {
            api_url_with_base(api_base_url, "/api/v1/diagnostics/support-bundles")
        }
    }
}

trait DiagnosticsBundleExt {
    fn section_item(&self, section: &str, key: &str) -> Option<&RedactedValue>;
}

impl DiagnosticsBundleExt for DiagnosticsBundle {
    fn section_item(&self, section: &str, key: &str) -> Option<&RedactedValue> {
        self.sections
            .iter()
            .find(|candidate| candidate.name == section)
            .and_then(|candidate| candidate.items.get(key))
    }
}

fn redacted_string(value: &RedactedValue) -> Option<String> {
    match value {
        RedactedValue::String(value) => Some(value.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendControlTokenClaims {
    organization_id: Option<String>,
    user_id: Option<String>,
    device_id: Option<String>,
    key_id: Option<String>,
    token_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct BackendControlTokenValidationRequest {
    token: String,
    source: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct BackendControlTokenValidationResponse {
    organization_id: Option<String>,
    user_id: Option<String>,
    device_id: Option<String>,
    key_id: Option<String>,
    token_id: Option<String>,
}

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
fn telemetry_control(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
) -> Result<ControlResult, LocalApiError> {
    telemetry_control_with_detector(
        daemon,
        action,
        source,
        control_token,
        api_base_url,
        key_id,
        organization_id,
        otlp_endpoint,
        ingest_key,
        &detect_agent_installation,
    )
}

#[expect(clippy::too_many_arguments, reason = "12 args; no options struct yet")]
fn telemetry_control_with_detector(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    // SECURITY: the request-supplied `api_base_url` cannot freely choose where the
    // control token is validated. Token validation is the only gate protecting
    // this telemetry-config mutation against an untrusted local peer, so
    // `control_token_validation_base_url` only honors this value when it is a
    // trusted production backend (never a request-supplied loopback URL), closing
    // the bypass where a co-resident attacker points validation at their own
    // server. See that resolver for the full rationale.
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
    detector: &dyn Fn(&SourceKind) -> AgentInstallationDetection,
) -> Result<ControlResult, LocalApiError> {
    let mut key_id = key_id;
    if source == SourceKind::Codex && matches!(action, TelemetryControlAction::EnableTelemetry) {
        return Err(LocalApiError::InvalidRequest(
            "Ottto Codex live telemetry is disabled; local session import remains available"
                .to_string(),
        ));
    }
    if !matches!(source, SourceKind::Codex | SourceKind::ClaudeCode) {
        return Err(LocalApiError::InvalidRequest(
            "telemetry control supports codex and claude_code only".to_string(),
        ));
    }

    let token_validation_base_url = control_token_validation_base_url(api_base_url.as_deref())?;
    validate_control_token_fresh(&control_token, &action, &source)?;

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            require_non_empty_field(key_id.as_deref(), "key_id")?;
            require_non_empty_field(organization_id.as_deref(), "organization_id")?;
            require_non_empty_field(otlp_endpoint.as_deref(), "otlp_endpoint")?;
            let Some(secret) = ingest_key.as_ref() else {
                return Err(LocalApiError::InvalidRequest(
                    "enable_telemetry requires ingest_key".to_string(),
                ));
            };
            require_non_empty_field(Some(secret.expose_secret()), "ingest_key")?;
        }
        TelemetryControlAction::DisableTelemetry => {
            // Older installs, manually repaired installs, or installs that lost the
            // key index can still have local agent config patched to the Ottto
            // relay even though there is no indexed ingest key id to revoke.
            // Disabling live telemetry must still remove that local config; key
            // deletion is best-effort and only possible when the caller knows the
            // key id.
            if key_id
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(LocalApiError::InvalidRequest(
                    "key_id must not be empty when provided".to_string(),
                ));
            }
        }
        TelemetryControlAction::Status => {}
    }

    let claims = validate_control_token_with_backend(
        &token_validation_base_url,
        &control_token,
        &action,
        &source,
    )?;
    let _binding_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    require_local_control_account(&claims, &FileAccountStore::default(), "telemetry control")?;
    if matches!(
        action,
        TelemetryControlAction::Status | TelemetryControlAction::DisableTelemetry
    ) {
        let device = FileDeviceStore::default()
            .load()
            .map_err(|_| LocalApiError::LocalClientNotTrusted)?
            .ok_or(LocalApiError::LocalClientNotTrusted)?;
        if device.device_id.trim().is_empty()
            || claims.device_id.as_deref() != Some(device.device_id.as_str())
            || key_id != claims.key_id
        {
            return Err(LocalApiError::LocalClientNotTrusted);
        }
    }
    if let (Some(expected), Some(observed)) = (
        claims.organization_id.as_deref(),
        organization_id
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) {
        if expected != observed {
            return Err(LocalApiError::InvalidRequest(
                "control token organization does not match request".to_string(),
            ));
        }
    }

    let installation = match action {
        TelemetryControlAction::EnableTelemetry | TelemetryControlAction::Status => {
            Some(detector(&source))
        }
        TelemetryControlAction::DisableTelemetry => None,
    };
    if matches!(action, TelemetryControlAction::EnableTelemetry)
        && installation
            .as_ref()
            .is_some_and(|detected| !detected.installed)
    {
        return Ok(ControlResult {
            requires_restart: false,
            key_id,
            action,
            source: source.clone(),
            status: ControlResultStatus::NeedsAttention,
            message: StableMessage {
                code: "agent_not_installed".to_string(),
                text: format!(
                    "Install {} first - we'll wait.",
                    source_display_name(&source)
                ),
            },
            config_preview: None,
            installation,
        });
    }

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            let key_id = key_id
                .as_deref()
                .expect("enable key_id validated before backend call");
            let secret = ingest_key
                .as_ref()
                .expect("enable ingest_key validated before backend call");
            TelemetryKeyStore::production()
                .save(&source, key_id, secret.expose_secret())
                .map_err(|error| {
                    LocalApiError::LocalOperationFailed(format!(
                        "telemetry key storage failed: {error}"
                    ))
                })?;
            if let Err(error) = apply_telemetry_config(daemon, &source) {
                let _ = TelemetryKeyStore::production().delete(&source, key_id);
                return Err(error);
            }
            let otlp_endpoint = otlp_endpoint
                .as_deref()
                .expect("enable otlp_endpoint validated before backend call");
            if let Err(error) = emit_api_key_verification_marker(
                otlp_endpoint,
                secret.expose_secret(),
                &source,
                key_id,
                organization_id.as_deref(),
            ) {
                let _ = remove_telemetry_config(daemon, &source);
                return Err(error);
            }
        }
        TelemetryControlAction::DisableTelemetry => {
            remove_telemetry_config(daemon, &source)?;
            if let Some(key_id) = key_id.as_deref() {
                TelemetryKeyStore::production()
                    .delete(&source, key_id)
                    .map_err(|error| {
                        LocalApiError::LocalOperationFailed(format!(
                            "telemetry key removal failed: {error}"
                        ))
                    })?;
            }
        }
        TelemetryControlAction::Status => {}
    }

    if matches!(action, TelemetryControlAction::Status) && key_id.is_none() {
        key_id = TelemetryKeyStore::production()
            .latest_key_id(&source)
            .map_err(|error| {
                LocalApiError::LocalOperationFailed(format!("telemetry key lookup failed: {error}"))
            })?;
    }

    let requires_restart = matches!(action, TelemetryControlAction::EnableTelemetry)
        || (source == SourceKind::Codex
            && matches!(action, TelemetryControlAction::DisableTelemetry));
    Ok(ControlResult {
        requires_restart,
        key_id,
        action,
        source,
        status: ControlResultStatus::Accepted,
        message: StableMessage {
            code: "telemetry_control_accepted".to_string(),
            text: format!("Telemetry control request accepted by {OTTTO_SERVICE_BINARY_NAME}."),
        },
        config_preview: None,
        installation,
    })
}

fn apply_telemetry_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(source) {
        return Ok(ConfigPatchResult::default());
    }
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            // Explicit, backend-authorized enable also clears the default
            // JSON opt-out written by disable. Per-root user opt-outs and
            // external exporters survive. Settings go first, so kept settings
            // never get the shell env either.
            let settings =
                patch_claude_code_settings_with_relay_base(&machine, &relay_base_url, true)?;
            if let Some(kept) = settings.kept {
                return Err(LocalApiError::LocalOperationFailed(
                    claude_settings_kept_reason(kept).1.to_string(),
                ));
            }
            let mut patch = patch_claude_code_env_with_relay_base(&machine, &relay_base_url)?;
            patch.changed |= settings.changed;
            Ok(patch)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "telemetry control does not patch Pi local config".to_string(),
        )),
    }
}

fn remove_telemetry_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let _ = daemon.status_for_trusted_client()?;
            let changed = disable_managed_claude_relay_settings()?;
            let mut patch = remove_claude_code_env()?;
            patch.changed |= changed;
            Ok(patch)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "telemetry control does not patch Pi local config".to_string(),
        )),
    }
}

fn repair_source(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    dry_run: bool,
) -> Result<RepairPlan, LocalApiError> {
    let plan = propose_repair_plan(daemon, authorization, source.clone(), dry_run)?;
    if dry_run {
        return Ok(plan);
    }
    crate::snapshot_sync::reset_relay_authorization_backoff();
    if let Some(plan) = scan_index_rebuild_override_repair(daemon, authorization, &source, &plan) {
        daemon.arm_tracking_confirmation(&source, &plan)?;
        return Ok(plan);
    }

    // Pi has no local telemetry config to patch; its failure mode is an
    // expired/consumed provider OAuth credential that only a provider re-sign-in
    // can fix (Ottto can't re-mint the rotating token). Offer that actionable
    // recovery instead of a dead "blocked, no actions" response. Build the plan
    // before the WriteConfig-only retain below would strip everything.
    if matches!(source, SourceKind::Pi) {
        let plan = build_pi_reauth_repair_plan(plan);
        daemon.arm_tracking_confirmation(&source, &plan)?;
        return Ok(plan);
    }

    let mut plan = plan;
    plan.actions
        .retain(|action| action.action == RepairActionKind::WriteConfig);

    if !source_requires_config_patch(&source) {
        plan.status = RepairPlanStatus::Blocked;
        plan.authority.message = StableMessage {
            code: "config_repair_not_supported".to_string(),
            text: format!(
                "{} does not support local config repair.",
                source_display_name(&source)
            ),
        };
        plan.actions.clear();
        return Ok(plan);
    }

    if source_patch_disabled(&source) {
        plan.status = RepairPlanStatus::Blocked;
        plan.authority.message = patch_disabled_message(&source);
        plan.actions.clear();
        return Ok(plan);
    }

    let before = source_config_state_for_daemon(daemon, &source)?;
    let patch = if before.drift.is_empty() {
        ConfigPatchResult::default()
    } else {
        execute_write_config_repair(daemon, authorization, &source)?
    };
    let after = source_config_state_for_daemon(daemon, &source)?;
    if after.drift.is_empty() {
        daemon.record_config_repair_result(&source, after.clone())?;
    }

    plan.status = if after.drift.is_empty() {
        RepairPlanStatus::Succeeded
    } else {
        RepairPlanStatus::Failed
    };
    if let Some(action) = plan.actions.first_mut() {
        action.detail = if after.drift.is_empty() {
            if patch.changed {
                format!(
                    "{} telemetry config was repaired through ottto-service.",
                    source_display_name(&source)
                )
            } else {
                format!(
                    "{} local source config already matched its collection policy.",
                    source_display_name(&source)
                )
            }
        } else if let Some(kept) = patch.kept {
            claude_settings_kept_reason(kept).1.to_string()
        } else {
            format!(
                "{} telemetry config still has drift after repair.",
                source_display_name(&source)
            )
        };
    }
    daemon.arm_tracking_confirmation(&source, &plan)?;
    Ok(plan)
}

/// User Repair override of the 24-hour scan-index rebuild-loop guard.
///
/// Origin: only the companion's Repair button counts. It sends a token-less
/// `repair` (`dry_run: false`) as `client_kind: companion_app`, which
/// `request_authorization` grants as `TrustedCompanionApp` only for a
/// same-uid, Developer ID-signed Companion peer; the CLI (`ottto fix`) and
/// agents present the control token. Verify, including `repair: true`, never
/// reaches `repair_source`, and automatic retries are loads, not commands.
/// A source the guard is not pausing takes the ordinary Repair path.
fn scan_index_rebuild_override_repair(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: &SourceKind,
    plan: &RepairPlan,
) -> Option<RepairPlan> {
    if *authorization != RequestAuthorization::TrustedCompanionApp {
        return None;
    }
    let snapshot_source = crate::snapshot_sync::snapshot_source_of_kind(source);
    let outcome = crate::snapshots::arm_scan_index_rebuild_manual_override(
        snapshot_source,
        SystemTime::now(),
    );
    let retry = crate::snapshots::scan_index_rebuild_auto_retry_at(snapshot_source)
        .map(|at| format!(" Ottto retries by itself at {at}."))
        .unwrap_or_default();
    let mut plan = plan.clone();
    plan.actions.clear();
    match outcome {
        crate::snapshots::ScanIndexRebuildOverride::NotPaused => return None,
        crate::snapshots::ScanIndexRebuildOverride::Armed => {
            plan.status = RepairPlanStatus::Running;
            plan.authority.message = StableMessage {
                code: "scan_index_rebuild_override_armed".to_string(),
                text: format!(
                    "{} local record will be rebuilt on the next sync; older sessions are re-checked slowly.",
                    source_display_name(source)
                ),
            };
            // Run that sync now instead of waiting for the next cycle.
            #[cfg(not(test))]
            if let Err(error) =
                crate::snapshot_sync::spawn_one_shot_local_snapshot_sync(daemon.clone())
            {
                eprintln!(
                    "local snapshot sync after user Repair override unavailable: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            #[cfg(test)]
            let _ = daemon;
        }
        crate::snapshots::ScanIndexRebuildOverride::IdentityUnrecoverable => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: crate::snapshots::SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE
                    .to_string(),
                text: format!(
                    "{} local record is too damaged for Repair to rebuild safely.{retry}",
                    source_display_name(source)
                ),
            };
        }
        crate::snapshots::ScanIndexRebuildOverride::Refused(code) => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: code.to_string(),
                text: format!("Repair could not safely recover the local record. The source stays paused and its files are kept.{retry}"),
            };
        }
        crate::snapshots::ScanIndexRebuildOverride::Cooldown => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: crate::snapshots::SCAN_INDEX_REBUILD_OVERRIDE_COOLDOWN_CODE.to_string(),
                text: format!(
                    "Repair was already used for this source in the last 24 hours.{retry}"
                ),
            };
        }
    }
    Some(plan)
}

/// Build an actionable Pi recovery plan: a manual provider re-sign-in (which the
/// daemon cannot perform — it can't re-mint a provider's rotating OAuth token)
/// plus next-session confirmation, instead of the dead `config_repair_not_supported`
/// "blocked, no actions" response. Reuses the authority already computed by
/// `propose_repair_plan` so terminal/browser approval semantics are preserved.
fn build_pi_reauth_repair_plan(mut plan: RepairPlan) -> RepairPlan {
    plan.status = RepairPlanStatus::Proposed;
    plan.authority.message = StableMessage {
        code: "pi_provider_reauth_required".to_string(),
        text: "Pi reported an expired provider sign-in. Re-sign in to the failing provider in Pi, then start a session so Ottto can confirm tracking. Test tracking is optional.".to_string(),
    };
    let approval = RepairActionApproval {
        surface: RepairApprovalSurface::None,
        setup_safe: true,
        server_backed: false,
        reason:
            "Re-authenticating a provider in Pi is a manual local action; Ottto only guides it."
                .to_string(),
    };
    plan.actions = vec![
        RepairAction {
            action: RepairActionKind::ReauthProvider,
            title: "Re-sign in to the Pi provider".to_string(),
            detail: "Run `pi` and re-authenticate the failing provider (e.g. openai-codex), then start a session so Ottto can confirm tracking. Ottto can't re-mint the provider's rotating OAuth token for you.".to_string(),
            requires_approval: false,
            destructive: false,
            approval: approval.clone(),
            backup: None,
        },
        RepairAction {
            action: RepairActionKind::VerifyTelemetry,
            title: "Test Pi tracking (optional)".to_string(),
            detail: "Ottto confirms tracking after it collects your next session. You can also run Test tracking; this optional check may use recent activity.".to_string(),
            requires_approval: false,
            destructive: false,
            approval,
            backup: None,
        },
    ];
    plan
}

fn propose_repair_plan(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    dry_run: bool,
) -> Result<RepairPlan, LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => daemon.propose_repair(token, source, dry_run),
        RequestAuthorization::TrustedCompanionApp => {
            daemon.propose_repair_for_trusted_client(source, dry_run)
        }
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

fn execute_write_config_repair(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(source) {
        return Err(LocalApiError::InvalidRequest(format!(
            "{} telemetry config patching is disabled by environment",
            source_display_name(source)
        )));
    }
    let _lease = match authorization {
        RequestAuthorization::Token(token) => daemon.acquire_repair_lock(token, source.clone())?,
        RequestAuthorization::TrustedCompanionApp => {
            daemon.acquire_repair_lock_for_trusted_client(source.clone())?
        }
        RequestAuthorization::Untrusted => return Err(LocalApiError::LocalClientNotTrusted),
    };
    repair_source_config(daemon, source)
}

fn repair_source_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            patch_claude_code_settings_with_relay_base(&machine, &relay_base_url, false)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "Pi does not support local config repair".to_string(),
        )),
    }
}

fn sweep_telemetry_keys_for_uninstall(result: &mut UninstallExecutionResult) {
    match TelemetryKeyStore::production().sweep_all() {
        Ok(sweep) => {
            result.removed_paths.extend(
                sweep
                    .removed
                    .iter()
                    .map(|reference| format!("keychain://{}", reference.target())),
            );
            result.missing_paths.extend(
                sweep
                    .missing
                    .iter()
                    .map(|reference| format!("keychain://{}", reference.target())),
            );
            result.removed_paths.extend(
                sweep
                    .removed_unindexed_services
                    .iter()
                    .map(|target| format!("keychain://{target}")),
            );
            result.warnings.extend(sweep.warnings);
        }
        Err(error) => {
            result.status = "uninstall_incomplete".to_string();
            result
                .failed_operations
                .push(format!("remove telemetry keychain items: {error}"));
        }
    }
}

fn require_non_empty_field(value: Option<&str>, field: &str) -> Result<(), LocalApiError> {
    if value.is_some_and(|candidate| !candidate.trim().is_empty()) {
        return Ok(());
    }
    Err(LocalApiError::InvalidRequest(format!(
        "{field} is required for telemetry control"
    )))
}

fn validate_control_token_with_backend(
    api_base_url: &str,
    token: &str,
    action: &TelemetryControlAction,
    source: &SourceKind,
) -> Result<BackendControlTokenClaims, LocalApiError> {
    validate_control_token_with_backend_for(
        api_base_url,
        token,
        action_slug(action),
        source_slug(source),
    )
}

fn validate_control_token_with_backend_for(
    api_base_url: &str,
    token: &str,
    action: &str,
    source: &str,
) -> Result<BackendControlTokenClaims, LocalApiError> {
    let url = api_url_with_base(api_base_url, "/api/v1/apps/control-token/validate");
    let request = BackendControlTokenValidationRequest {
        token: token.to_string(),
        source: source.to_string(),
        action: action.to_string(),
    };
    match backend_post_json::<BackendControlTokenValidationResponse>(&url, &request, &[]) {
        Ok(response) => Ok(BackendControlTokenClaims {
            organization_id: response
                .organization_id
                .filter(|value| !value.trim().is_empty()),
            user_id: response.user_id.filter(|value| !value.trim().is_empty()),
            device_id: response.device_id.filter(|value| !value.trim().is_empty()),
            key_id: response.key_id,
            token_id: response.token_id.filter(|value| !value.trim().is_empty()),
        }),
        Err(LocalApiError::Backend(details)) if matches!(details.status, Some(401) | Some(403)) => {
            Err(LocalApiError::LocalClientNotTrusted)
        }
        Err(error) => Err(error),
    }
}

fn validate_control_token_fresh(
    token: &str,
    action: &TelemetryControlAction,
    source: &SourceKind,
) -> Result<(), LocalApiError> {
    validate_control_token_fresh_for(token, action_slug(action), source_slug(source)).map(|_| ())
}

fn validate_control_token_fresh_for(
    token: &str,
    action: &str,
    source: &str,
) -> Result<u64, LocalApiError> {
    if token.trim().is_empty() {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let payload = decode_control_token_payload(token)?;
    if payload.get("type").and_then(|value| value.as_str()) != Some("apps_control") {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("source").and_then(|value| value.as_str()) != Some(source) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("action").and_then(|value| value.as_str()) != Some(action) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let exp = payload
        .get("exp")
        .and_then(|value| value.as_u64())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_secs();
    if exp <= now {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    Ok(exp)
}

/// A Codex control token proven fresh, backend-valid and bound to the
/// connected local account and Codex device.
struct CodexControlTokenAuthority {
    /// Keeps account/device authority stable through the grant transition.
    identity_lifecycle_lock: MutexGuard<'static, ()>,
    expires_at_unix: u64,
    token_id: String,
    device: LocalDeviceBinding,
    local_user_id: String,
    local_organization_id: String,
}

fn require_local_control_account(
    claims: &BackendControlTokenClaims,
    accounts: &FileAccountStore,
    binding_label: &str,
) -> Result<(String, String), LocalApiError> {
    let account = accounts.load().map_err(|_| {
        LocalApiError::LocalOperationFailed(format!(
            "{binding_label} account binding is unavailable"
        ))
    })?;
    let local_user_id = account
        .user
        .as_ref()
        .map(|user| user.id.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    let local_organization_id = account
        .organization
        .as_ref()
        .map(|organization| organization.id.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    if account.state != LocalAccountState::Connected
        || claims.user_id.as_deref() != Some(local_user_id)
        || claims.organization_id.as_deref() != Some(local_organization_id)
    {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    Ok((local_user_id.to_string(), local_organization_id.to_string()))
}

/// Prelude of the provider-daily-reference bridge. Check order is part of the
/// contract. `binding_label` names the bridge in the binding-load errors.
fn authorize_codex_control_token(
    control_token: &str,
    action_slug: &str,
    api_base_url: Option<&str>,
    requires_mutation_reservation: bool,
    binding_label: &str,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
) -> Result<CodexControlTokenAuthority, LocalApiError> {
    let expires_at_unix = validate_control_token_fresh_for(control_token, action_slug, "codex")?;
    let token_validation_base_url = control_token_validation_base_url(api_base_url)?;
    let claims = validate_control_token_with_backend_for(
        &token_validation_base_url,
        control_token,
        action_slug,
        "codex",
    )?;

    // Identity reset/replacement paths acquire this same lock around their
    // grant preflight and filesystem mutation.
    let identity_lifecycle_lock = lock_setup_run_binding();
    if requires_mutation_reservation {
        require_identity_mutation_reservation(None)?;
    }

    let (local_user_id, local_organization_id) =
        require_local_control_account(&claims, accounts, binding_label)?;
    let device = devices
        .load()
        .map_err(|_| {
            LocalApiError::LocalOperationFailed(format!(
                "{binding_label} device binding is unavailable"
            ))
        })?
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    if claims.device_id.as_deref() != Some(device.device_id.as_str())
        || !device.sources.iter().any(|source| source == "codex")
    {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let token_id = claims
        .token_id
        .as_deref()
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    Ok(CodexControlTokenAuthority {
        identity_lifecycle_lock,
        expires_at_unix,
        token_id: token_id.to_string(),
        local_user_id,
        local_organization_id,
        device,
    })
}

#[derive(Debug, Clone, Serialize)]
struct ProviderDailyReferenceControlResult {
    action: ProviderDailyReferenceControlAction,
    status: crate::provider_daily_reference::CollectorStatusV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_create_request: Option<crate::provider_daily_reference::GrantCreateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_revoke_target: Option<crate::provider_daily_reference::GrantRevokeTarget>,
}

fn provider_daily_reference_action_slug(
    action: &ProviderDailyReferenceControlAction,
) -> &'static str {
    match action {
        ProviderDailyReferenceControlAction::Prepare => "prepare_provider_daily_reference",
        ProviderDailyReferenceControlAction::Bind => "bind_provider_daily_reference",
        ProviderDailyReferenceControlAction::Revoke => "revoke_provider_daily_reference",
        ProviderDailyReferenceControlAction::ConfirmRevoked => {
            "confirm_provider_daily_reference_revoked"
        }
        ProviderDailyReferenceControlAction::Status => "provider_daily_reference_status",
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount => {
            "exclude_provider_daily_reference_current_account"
        }
        ProviderDailyReferenceControlAction::IncludeCurrentAccount => {
            "include_provider_daily_reference_current_account"
        }
    }
}

/// Drive the local Codex daily-aggregates consent state on behalf of an
/// operator who asked for it in the UI.
///
/// This command packages consent; it never creates it. Prepare records the
/// operator's explicit local consent and hands back the credential-free DTO the
/// browser POSTs; nothing collects until the backend's answer is bound, the
/// server policy approves, and the admitted build matches. All collection
/// gates from the collector are untouched by this path.
fn provider_daily_reference_control(
    action: ProviderDailyReferenceControlAction,
    control_token: SecretString,
    api_base_url: Option<String>,
    backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
    expected_account_fingerprint: Option<String>,
) -> Result<ProviderDailyReferenceControlResult, LocalApiError> {
    provider_daily_reference_control_with_stores(
        action,
        control_token,
        api_base_url,
        backend_grant,
        expected_account_fingerprint,
        &FileAccountStore::default(),
        &FileDeviceStore::default(),
        &crate::provider_daily_reference::GrantStore::default(),
        &crate::provider_daily_reference::control_token_use_store(),
        // Consent is taken over a Codex account signed in right now. Only the
        // account id leaves the login read; the token never enters this path.
        &|prepare_fallback| {
            crate::provider_daily_reference::control_account_scope(prepare_fallback)
        },
        crate::provider_daily_reference::network_disabled(),
    )
}

#[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
fn provider_daily_reference_control_with_stores(
    action: ProviderDailyReferenceControlAction,
    control_token: SecretString,
    api_base_url: Option<String>,
    backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
    expected_account_fingerprint: Option<String>,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    grants: &crate::provider_daily_reference::GrantStore,
    token_uses: &crate::cloud_sessions::CloudSessionControlTokenUseStore,
    // Read lazily: only Prepare (`true`, which may fall back to the first
    // live login) and the account privacy controls (`false`, the default
    // home's login) call it, after the token is consumed.
    provider_account_scope: &dyn Fn(bool) -> Option<String>,
    network_disabled: bool,
) -> Result<ProviderDailyReferenceControlResult, LocalApiError> {
    let CodexControlTokenAuthority {
        identity_lifecycle_lock,
        expires_at_unix,
        token_id,
        device,
        local_user_id,
        local_organization_id,
    } = authorize_codex_control_token(
        control_token.expose_secret(),
        provider_daily_reference_action_slug(&action),
        api_base_url.as_deref(),
        action != ProviderDailyReferenceControlAction::Status,
        "codex daily aggregates",
        accounts,
        devices,
    )?;

    let backend_grant_allowed = matches!(
        action,
        ProviderDailyReferenceControlAction::Bind
            | ProviderDailyReferenceControlAction::Revoke
            | ProviderDailyReferenceControlAction::ConfirmRevoked
    );
    let backend_grant_required = matches!(
        action,
        ProviderDailyReferenceControlAction::Bind
            | ProviderDailyReferenceControlAction::ConfirmRevoked
    );
    if (backend_grant_required && backend_grant.is_none())
        || (!backend_grant_allowed && backend_grant.is_some())
    {
        return Err(LocalApiError::InvalidRequest(
            "backend_grant presence does not match provider daily reference action".to_string(),
        ));
    }
    let targets_current_account = matches!(
        action,
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount
            | ProviderDailyReferenceControlAction::IncludeCurrentAccount
    );
    if targets_current_account != expected_account_fingerprint.is_some() {
        return Err(LocalApiError::InvalidRequest(
            "expected_account_fingerprint presence does not match provider daily reference action"
                .to_string(),
        ));
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_secs();
    // Consume after trusted-backend and exact local binding validation, but
    // before any local grant side effect.
    token_uses
        .consume(&token_id, expires_at_unix, now_unix)
        .map_err(|_| LocalApiError::LocalClientNotTrusted)?;

    let mut backend_create_request = None;
    let mut backend_revoke_target = None;
    let result = match action {
        ProviderDailyReferenceControlAction::Prepare => {
            let scope = provider_account_scope(true);
            let Some(provider_account_scope) = scope
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(LocalApiError::LocalOperationFailed(
                    "a signed-in Codex account is required before consent".to_string(),
                ));
            };
            grants
                .enable(
                    &crate::provider_daily_reference::GrantSetup {
                        installation_id: device.device_id.clone(),
                        organization_scope: local_organization_id.to_string(),
                        effective_user_scope: local_user_id.to_string(),
                        provider_account_scope: provider_account_scope.to_string(),
                    },
                    time::OffsetDateTime::now_utc(),
                )
                .and_then(|_| grants.grant_create_request(&device.device_id))
                .map(|request| backend_create_request = Some(request))
        }
        ProviderDailyReferenceControlAction::Bind => grants
            .bind_backend_grant(
                backend_grant
                    .as_ref()
                    .expect("backend grant presence validated"),
                &device.device_id,
            )
            .map(|_| ()),
        ProviderDailyReferenceControlAction::Revoke => grants
            .revoke(time::OffsetDateTime::now_utc())
            .and_then(|()| {
                // Completion-safe compensating cleanup: an authenticated POST
                // response can arrive after the local revoke. Binding it
                // retains only its identity - a revoked local grant is never
                // resurrected - so the DELETE has an exact target.
                if let Some(response) = backend_grant.as_ref() {
                    grants.bind_backend_grant(response, &device.device_id)?;
                }
                Ok(())
            }),
        ProviderDailyReferenceControlAction::ConfirmRevoked => grants
            .apply_backend_revocation(
                backend_grant
                    .as_ref()
                    .expect("backend grant presence validated"),
                &device.device_id,
            )
            .map(|_| ()),
        ProviderDailyReferenceControlAction::Status => Ok(()),
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount
        | ProviderDailyReferenceControlAction::IncludeCurrentAccount => {
            let scope = provider_account_scope(false);
            let Some(provider_account_scope) = scope
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(LocalApiError::LocalOperationFailed(
                    "a signed-in Codex account is required for this privacy control".to_string(),
                ));
            };
            let fingerprint = grants
                .account_fingerprint_for(provider_account_scope)
                .map_err(|_| {
                    LocalApiError::LocalOperationFailed(
                        "codex daily aggregates account attribution is unavailable".to_string(),
                    )
                })?
                .ok_or_else(|| {
                    LocalApiError::LocalOperationFailed(
                        "codex daily aggregates consent is absent".to_string(),
                    )
                })?;
            if expected_account_fingerprint.as_deref() != Some(fingerprint.as_str()) {
                return Err(LocalApiError::InvalidRequest(
                    "the signed-in Codex account changed; refresh status before changing privacy controls"
                        .to_string(),
                ));
            }
            grants.set_account_excluded(
                &fingerprint,
                action == ProviderDailyReferenceControlAction::ExcludeCurrentAccount,
            )
        }
    };
    result.map_err(|_| {
        LocalApiError::LocalOperationFailed(
            "codex daily aggregates local control failed".to_string(),
        )
    })?;

    if action == ProviderDailyReferenceControlAction::Status
        && grants
            .load()
            .map_err(|_| {
                LocalApiError::LocalOperationFailed(
                    "codex daily aggregates local control failed".to_string(),
                )
            })?
            .is_some_and(|grant| grant.backend_create_pending)
    {
        // An authenticated Status after a lost Prepare response returns the
        // create DTO again, so the browser retries the idempotent POST and
        // binds its response instead of guessing one.
        backend_create_request = Some(grants.grant_create_request(&device.device_id).map_err(
            |_| {
                LocalApiError::LocalOperationFailed(
                    "codex daily aggregates local control failed".to_string(),
                )
            },
        )?);
    }

    if action == ProviderDailyReferenceControlAction::Revoke {
        // Best effort by design: an unreconciled create has no backend id to
        // delete, and that is "nothing to delete", not a failed revoke - the
        // local stop already happened and already blocks collection.
        backend_revoke_target = grants.grant_revoke_target().ok();
    }
    #[cfg(test)]
    tests::before_daily_reference_status();
    let installation_id = devices.load().ok().flatten().map(|device| device.device_id);

    let response = ProviderDailyReferenceControlResult {
        action,
        // Built from the stores this call was handed, not from process-wide
        // state, so the reported status belongs to this installation and the
        // account actually signed in. A status that can read `enabled` while
        // every collection cycle refuses is the bug this closes.
        status: crate::provider_daily_reference::status_with_live_binding(
            grants,
            crate::provider_daily_reference::collector_status(grants, network_disabled),
            installation_id.as_deref(),
        ),

        backend_create_request,
        backend_revoke_target,
    };
    drop(identity_lifecycle_lock);
    Ok(response)
}

fn decode_control_token_payload(token: &str) -> Result<serde_json::Value, LocalApiError> {
    let mut parts = token.split('.');
    let _header = parts.next();
    let Some(payload) = parts.next() else {
        return Err(LocalApiError::LocalClientNotTrusted);
    };
    let Some(_signature) = parts.next() else {
        return Err(LocalApiError::LocalClientNotTrusted);
    };
    if parts.next().is_some() {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| LocalApiError::LocalClientNotTrusted)?;
    serde_json::from_slice(&decoded).map_err(|_| LocalApiError::LocalClientNotTrusted)
}

fn action_slug(action: &TelemetryControlAction) -> &'static str {
    match action {
        TelemetryControlAction::EnableTelemetry => "enable_telemetry",
        TelemetryControlAction::DisableTelemetry => "disable_telemetry",
        TelemetryControlAction::Status => "status",
    }
}

fn local_lifecycle_home() -> Result<PathBuf, LocalApiError> {
    local_lifecycle_home_dir()
        .map_err(|error| LocalApiError::LocalOperationFailed(error.to_string()))
}

fn refresh_agent_status_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: Option<SourceKind>,
) -> Result<Vec<ottto_protocol::AgentStatusSnapshot>, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    reconcile_agent_status_config_for_refresh(daemon, source.as_ref())?;
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    let snapshots = match authorization {
        RequestAuthorization::Token(token) => {
            daemon.refresh_agent_status(token, source, captured_at, expires_at)
        }
        RequestAuthorization::TrustedCompanionApp => {
            daemon.refresh_agent_status_for_trusted_client(source, captured_at, expires_at)
        }
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }?;
    if !crate::agent_status_refresh::active() {
        upload_agent_status_snapshots_in_background(snapshots.clone());
    }
    Ok(snapshots)
}

/// Explicit quota refresh (a user's Refresh action) of every account of the
/// source(s). Codex homes are read here, each at most once a minute or
/// `min_gap_seconds` if longer (one `codex app-server` run per home, up to its
/// timeout, before the reply). Claude accounts are marked for the collection
/// that follows, whose usage gate reads them at most once a minute and keeps
/// every hold, breaker and Retry-After; the lane's next own pass answers a
/// mark that collection missed (one already in flight).
fn request_explicit_quota_refresh(source: Option<&SourceKind>, min_gap_seconds: u64) {
    if source.map_or(true, |source| source == &SourceKind::ClaudeCode) {
        crate::agent_status::request_claude_explicit_refresh();
        crate::agent_status_refresh::request(&SourceKind::ClaudeCode);
    }
    if source.map_or(true, |source| source == &SourceKind::Codex) {
        let outcome = crate::agent_status::refresh_codex_quota_now(min_gap_seconds);
        eprintln!(
            "explicit Codex quota refresh: read={} rate_limited={}",
            outcome.read, outcome.rate_limited
        );
    }
}

fn reconcile_agent_status_config_for_refresh(
    daemon: &LocalDaemon,
    source: Option<&SourceKind>,
) -> Result<(), LocalApiError> {
    if source.is_some_and(|source| source != &SourceKind::ClaudeCode) {
        return Ok(());
    }
    reconcile_claude_statusline_for_agent_status_refresh(daemon)
}

fn reconcile_claude_statusline_for_agent_status_refresh(
    daemon: &LocalDaemon,
) -> Result<(), LocalApiError> {
    if source_patch_disabled(&SourceKind::ClaudeCode)
        || !crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode)
    {
        return Ok(());
    }
    let machine = daemon.status_for_trusted_client()?.machine;
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let support_dir = default_support_dir();
    let settings_path = home_path(".claude/settings.json");
    let _settings_guard = lock_managed_claude_settings();
    let managed_approval_before_repair = match approved_managed_claude_relay_env() {
        Ok(env) => env.is_some(),
        Err(error) => {
            eprintln!("managed Claude settings repair skipped: {error}");
            false
        }
    };
    let _ = repair_claude_statusline_for_refresh_at(
        &settings_path,
        &machine,
        &support_dir,
        &relay_base_url,
    )?;
    if managed_approval_before_repair {
        if let Err(error) = repair_registered_managed_claude_relay_settings_locked() {
            eprintln!("managed Claude settings repair skipped: {error}");
        }
    }
    Ok(())
}

fn upload_agent_status_snapshots_in_background(snapshots: Vec<AgentStatusSnapshot>) {
    let spawn_result = thread::Builder::new()
        .name("ottto-agent-status-upload".to_string())
        .spawn(move || {
            if let Err(error) = crate::snapshot_sync::upload_agent_status_snapshots(&snapshots) {
                eprintln!(
                    "manual agent status upload skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("manual agent status upload skipped: {error}");
    }
}

fn auth_start(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<AuthStartResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    // A connected Mac whose setup run Ottto no longer accepts can only recover
    // through a fresh claim: Verify and `ottto doctor` tell the user to sign
    // in, so refusing here would dead-end them. The claim keeps the bound
    // user, and completing it for that user replaces the dead binding.
    let history_pending = local_history_recovery_expected()?
        || registration_history_choice_account(&status.account)
        || history_load::<StoredHistoryBrowserClaim>(history_stores().browser.as_ref())
            .is_ok_and(|claim| claim.is_some_and(|claim| claim.registration_pending))
        || history_account_store()
            .load()
            .is_ok_and(|account| registration_history_choice_account(&account));
    if status.account.state == LocalAccountState::Connected
        && status.account.user.is_some()
        && !history_pending
        && !daemon.connected_setup_run_needs_reconnect()?
    {
        return Err(LocalApiError::InvalidRequest(
            "This Mac is already connected. Run `ottto account` to view it, or `ottto logout` before pairing a different account."
                .to_string(),
        ));
    }
    // Idempotent re-trigger: while a claim is in flight and unexpired,
    // repeated Sign-in presses return the SAME claim instead of minting a
    // parallel one. Racing claims were one writer behind the observed
    // ClaimPending/ResetRequired status flip-flop (a completion for claim A
    // landing while claim B had already replaced the pending state).
    if let Some((pending, account)) = daemon.pending_auth_claim_snapshot()? {
        if matches!(
            account.state,
            LocalAccountState::ClaimPending | LocalAccountState::ReattachRequired
        ) && !auth_claim_is_expired(&pending.expires_at)
        {
            return Ok(AuthStartResponse {
                account,
                claim_code: pending.claim_code,
                claim_url: pending.claim_url,
                nonce: pending.nonce,
                expires_at: pending.expires_at,
            });
        }
    }
    if let Some(pending) =
        resume_history_browser_claim(&status.machine, &validated_api_base_url(None)?)?
    {
        let response = begin_durable_browser_claim(daemon, pending)?;
        crate::snapshot_sync::reset_relay_authorization_backoff();
        return Ok(response);
    }
    if !history_pending {
        discard_abandoned_unconfirmed_claim_credential()?;
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = create_setup_claim(&status.machine, &nonce)?;
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let claim_url = append_nonce_to_claim_url(&claim.claim_url, &nonce);
    let response = begin_durable_browser_claim(
        daemon,
        PendingAuthClaim {
            claim_code: claim.claim_code,
            claim_token: claim.claim_token,
            nonce,
            claim_url,
            expires_at: claim.expires_at,
        },
    )?;
    crate::snapshot_sync::reset_relay_authorization_backoff();
    Ok(response)
}

fn begin_durable_browser_claim(
    daemon: &LocalDaemon,
    pending: PendingAuthClaim,
) -> Result<AuthStartResponse, LocalApiError> {
    let _identity_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let registration = history_account_store()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account));
    let response = daemon.begin_auth_with_claim(pending)?;
    let mut persisted = response.account.clone();
    if registration {
        persisted.message = Some(registration_history_choice_message());
    }
    history_account_store()
        .save(&persisted)
        .or_state_poisoned()?;
    Ok(response)
}

fn retire_refused_registration_after_browser_answer(claim_code: &str) -> Result<(), LocalApiError> {
    retire_refused_registration_after_browser_answer_with_stores(claim_code, &history_stores())
}

fn retire_refused_registration_after_browser_answer_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let browser: Option<StoredHistoryBrowserClaim> = match history_load(stores.browser.as_ref()) {
        Ok(browser) => browser,
        Err(_) if !local_history_recovery_expected()? => return Ok(()),
        Err(error) => return Err(error),
    };
    if !browser.is_some_and(|browser| {
        browser.registration_pending && browser.claim.claim_code == claim_code
    }) {
        return Ok(());
    }
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if pending.claim_commit.is_some() {
        return Ok(());
    }
    if pending.confirmed_at.is_some() {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let candidate = secret_store.load().or_state_poisoned()?;
    match inspect_device_credential_preparation(&pending, &candidate) {
        Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) if backend_error_has_status(&error, 410) => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) => Err(error),
        Ok(_) => Err(LocalApiError::IdentityMutationInProgress),
    }
}

fn history_recovery_indicator_path() -> PathBuf {
    history_support_dir().join("local-history-recovery-required")
}

fn local_history_recovery_expected() -> Result<bool, LocalApiError> {
    // Presence only: no device selector, timestamp, receipt, or credential is
    // mirrored here. The actual marker/proof remain Keychain-only. This lets a
    // locked optional Keychain be distinguished from ordinary first sign-in,
    // without changing the account captured by an identity reservation.
    match fs::symlink_metadata(history_recovery_indicator_path()) {
        Ok(metadata) if metadata.is_file() => return Ok(true),
        Ok(_) => return Err(LocalApiError::StatePoisoned),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LocalApiError::StatePoisoned),
    }
    history_account_store()
        .load()
        .map(|account| registration_history_choice_account(&account))
        .or_state_poisoned()
}

fn persist_local_release_expected() -> Result<(), LocalApiError> {
    ottto_core::write_owner_only_file_atomic(&history_recovery_indicator_path(), b"1")
        .or_state_poisoned()
}

fn clear_local_release_expected() -> Result<(), LocalApiError> {
    match fs::remove_file(history_recovery_indicator_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}

fn registration_history_choice_account(account: &LocalAccountBinding) -> bool {
    account
        .message
        .as_ref()
        .is_some_and(|m| m.code == "history_choice_required")
}

fn registration_history_choice_required(error: &LocalApiError) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(400)
        && (details.reason_code.as_deref() == Some("history_choice_required") || auth_complete_error_is_pending(error)))
}

fn registration_history_choice_message() -> StableMessage {
    StableMessage {
        code: "history_choice_required".to_string(),
        text: "Waiting for browser sign-in to finish.".to_string(),
    }
}

fn persist_registration_history_choice() -> Result<(), LocalApiError> {
    let _lock = lock_setup_run_binding();
    let store = history_account_store();
    let mut account = store.load().or_state_poisoned()?;
    // Preserve the bound identity and all credential journals. This is a
    // durable user action, not an authority transition or a failed install.
    account.state = LocalAccountState::ReattachRequired;
    account.message = Some(registration_history_choice_message());
    account.can_reconnect = Some(true);
    store.save(&account).or_state_poisoned()
}

fn registration_history_choice_error(error: LocalApiError) -> LocalApiError {
    if registration_history_choice_required(&error) {
        if let Err(error) = persist_registration_history_choice() {
            return error;
        }
    }
    error
}

fn reoffer_registration_browser_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    base: &str,
) -> Result<AuthStartResponse, LocalApiError> {
    daemon.mark_history_choice_required()?;
    if let Some((claim, _)) = daemon.pending_auth_claim_snapshot()? {
        if !auth_claim_is_expired(&claim.expires_at) {
            return begin_durable_browser_claim(daemon, claim);
        }
    }
    if let Some(claim) = resume_history_browser_claim(machine, base)? {
        return begin_durable_browser_claim(daemon, claim);
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = {
        let _lock = lock_history_recovery()?;
        create_setup_claim_with_history(
            &api_url_with_base(base, "/api/v1/setup-claims"),
            machine,
            &nonce,
            &history_stores(),
            history_now(),
        )?
    };
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let pending = PendingAuthClaim {
        claim_code: claim.claim_code,
        claim_token: claim.claim_token,
        claim_url: append_nonce_to_claim_url(&claim.claim_url, &nonce),
        nonce,
        expires_at: claim.expires_at,
    };
    begin_durable_browser_claim(daemon, pending)
}

/// A fresh claim is the explicit cancellation boundary for an older completed
/// claim that was waiting for account-switch confirmation. The journal is not
/// active authority until confirmation is authorized, so invalidate it before
/// asking the backend to mint a different immutable preparation. The binding
/// lock plus the reservation check exclude a concurrently completing claim.
fn discard_abandoned_unconfirmed_claim_credential() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.confirmed_at.is_some()
        || pending.confirmation_authorized
        || pending.preconfirm_guards_passed
        || pending.claim_commit.is_none()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    clear_pending_device_credential(
        &pending_store,
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

/// Whether a pending claim's `expires_at` is in the past (with a 30s safety
/// margin so a claim that is about to lapse mid-browser-open is not reused).
/// Unparseable timestamps count as expired so a fresh claim is minted.
fn auth_claim_is_expired(expires_at: &str) -> bool {
    use time::format_description::well_known::Rfc3339;
    let Ok(expires) = time::OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return true;
    };
    expires - time::Duration::seconds(30) <= time::OffsetDateTime::now_utc()
}

fn auth_complete(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
    nonce: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    let pending = daemon.pending_auth_claim(claim_code, nonce)?;
    complete_pending_auth_claim(daemon, &status.machine, pending)
}

fn auth_complete_pending(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    match daemon.pending_auth_claim_for_resume(claim_code) {
        Ok(pending) => complete_pending_auth_claim(daemon, &status.machine, pending),
        Err(LocalApiError::NoPendingAuthClaim) => daemon
            .completed_auth_claim_for_resume(claim_code)?
            .ok_or(LocalApiError::NoPendingAuthClaim),
        Err(error) => Err(error),
    }
}

fn complete_pending_auth_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    pending: PendingAuthClaim,
) -> Result<AuthCompleteResponse, LocalApiError> {
    // Claim completion can rotate/revoke backend device credentials. Reserve
    // identity mutation before that remote side effect, but release the
    // lifecycle mutex during network I/O. The RAII guard blocks concurrent
    // Codex cloud-task admission and clears on every return or panic.
    let identity_reservation = reserve_identity_mutation()?;
    let completion = match complete_setup_claim(&pending, machine, Some(&identity_reservation)) {
        Ok(completed) => completed,
        Err(error) => {
            log_auth_complete_backend_failure(&error);
            if let Some(reattach) = reattach_required_state(&error) {
                let _binding_lock = lock_setup_run_binding();
                daemon.mark_reattach_required(reattach.message.clone(), reattach.can_reconnect)?;
                let account = daemon.account_for_trusted_client()?;
                FileAccountStore::default()
                    .save(&account)
                    .or_state_poisoned()?;
            }
            return Err(error);
        }
    };
    let completed = completion.response;
    // Validate the relay-device payload up front so a malformed completion is
    // rejected before any staging or persistence.
    let relay_credentials = relay_device_credentials_from_claim_completion(
        &completed,
        completion.prior_device_credential.as_ref(),
    )?;
    retire_refused_registration_after_browser_answer(&pending.claim_code)?;
    let _ = finish_history_browser_claim(&pending.claim_code);
    let account = LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: completed.user.id.clone(),
            email: completed.user.email.clone(),
            display_name: completed.user.display_name.clone(),
        }),
        organization: Some(LocalAccountOrganization {
            id: completed.organization.id.clone(),
            name: completed.organization.name.clone(),
        }),
        connected_at: Some(completed.connected_at.clone()),
        last_refreshed_at: Some(completed.connected_at.clone()),
        message: Some(StableMessage {
            code: "connected".to_string(),
            text: "This Mac is connected to Ottto.".to_string(),
        }),
        can_reconnect: None,
    };
    let prepared_pending = match &relay_credentials {
        ClaimRelayDeviceCredential::Prepared(prepared) => {
            let claim_commit = PendingClaimCredentialCommit {
                account: account.clone(),
                connection: LocalConnectionBinding {
                    setup_run_id: completed.setup_run_id.clone(),
                    setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
                    machine_id: completed.machine_id.clone(),
                    claim_code: Some(pending.claim_code.clone()),
                    api_base_url: validated_api_base_url(None)?,
                },
                target_user_id: completed.user.id.clone(),
                setup_run_token_sha256: secret_sha256(&completed.setup_run_token),
                backfill_policy: completed.backfill_policy.clone(),
                backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
            };
            let mut pending = pending_device_credential_from_preparation(
                &validated_api_base_url(None)?,
                prepared,
                false,
                Some(claim_commit),
                completion.request_authority.clone(),
            )?;
            {
                let _binding_lock = lock_setup_run_binding();
                identity_reservation.validate_locked()?;
                select_owner_snapshot_namespace(
                    &mut pending,
                    &prepared.candidate_secret,
                    completion.prior_device_credential.as_ref(),
                    &FileOwnerSnapshotNamespaceStore::default(),
                    &default_support_dir(),
                )?;
            }
            stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
            stage_pending_setup_run_token(&pending, &completed.setup_run_token)?;
            let staged = FilePendingDeviceCredentialStore::default()
                .load()
                .or_state_poisoned()?
                .ok_or(LocalApiError::StatePoisoned)?;
            if staged.preparation_id != pending.preparation_id {
                return Err(LocalApiError::StatePoisoned);
            }
            Some(staged)
        }
        ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Legacy(_, _) => None,
    };
    // Claim-collision check BEFORE any persistence. Previously the new
    // setup-run token and relay-device credentials were written to the
    // keychain before the user-mismatch check fired, leaving a half-installed
    // credential set for the wrong user alongside the old account files. On a
    // mismatch the fully-completed claim is staged in memory and surfaced as a
    // switch candidate. A modern candidate may already be present in the
    // separate pending journal/Keychain account, but active account/device
    // authority remains unchanged until `auth_switch_account`.
    if let Some(candidate) = daemon.stage_account_switch_if_user_mismatch(StagedAccountSwitch {
        claim_code: pending.claim_code.clone(),
        new_account: account.clone(),
        setup_run_id: completed.setup_run_id.clone(),
        setup_run_token: completed.setup_run_token.clone(),
        setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
        machine_id: completed.machine_id.clone(),
        relay_device: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, _) => Some(device.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_secret: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(_, secret) => Some(secret.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_credential_preparation_id: prepared_pending
            .as_ref()
            .map(|pending| pending.preparation_id.clone()),
        backfill_policy: completed.backfill_policy.clone(),
        backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
    })? {
        return Err(LocalApiError::AccountSwitchCandidate {
            current_user_email: candidate.current_user_email,
            new_user_email: candidate.new_user_email,
            new_organization_name: candidate.new_organization_name,
            claim_code: candidate.claim_code,
        });
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(authorize_pending_device_credential_confirmation(
            &pending.preparation_id,
        )?),
        None => None,
    };
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(mark_pending_device_credential_guards_passed(
            &pending,
            &FilePendingDeviceCredentialStore::default(),
        )?),
        None => None,
    };
    let confirmed_pending = match (&relay_credentials, prepared_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Prepared(prepared), Some(pending)) => {
            if pending.confirmed_at.is_some() {
                Some(pending.clone())
            } else {
                let confirmed =
                    confirm_device_credential_preparation(pending, &prepared.candidate_secret)?;
                Some(mark_pending_device_credential_confirmed(
                    pending,
                    &confirmed.confirmed_at,
                    &FilePendingDeviceCredentialStore::default(),
                )?)
            }
        }
        (ClaimRelayDeviceCredential::Prepared(_), None) => {
            return Err(LocalApiError::StatePoisoned)
        }
        _ => None,
    };
    if let (ClaimRelayDeviceCredential::Prepared(prepared), Some(confirmed)) =
        (&relay_credentials, confirmed_pending.as_ref())
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        write_and_verify_pending_claim_commit(confirmed, &prepared.candidate_secret)?;
        let response = daemon.complete_auth_with_account(
            &pending.claim_code,
            &pending.nonce,
            account,
            completed.setup_run_id,
            completed.setup_run_token_expires_at,
            completed.machine_id,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    // Persist the server-issued backfill policy BEFORE committing any of the
    // new binding (token, relay credentials, account/connection files): if
    // this write failed after the binding were already durable, the daemon
    // would come up connected without the cutoff and the next snapshot sync
    // would re-attribute the previous owner's pre-cutoff history to the new
    // account. A stray cutoff for a never-installed binding is harmless; a
    // binding without its cutoff is not.
    persist_claim_backfill_policy(
        completed.backfill_policy.as_deref(),
        completed.backfill_cutoff_at.as_deref(),
        &completed.user.id,
        match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, secret) => Some(
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None),
            ),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&completed.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (&relay_credentials, confirmed_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Legacy(device, secret), _) => {
            persist_relay_device_credentials_locked(device, secret, Some(&identity_reservation))?;
            true
        }
        (ClaimRelayDeviceCredential::Prepared(_), _) => return Err(LocalApiError::StatePoisoned),
        (ClaimRelayDeviceCredential::None, _) => false,
    };
    let response = daemon.complete_auth_with_account(
        &pending.claim_code,
        &pending.nonce,
        account.clone(),
        completed.setup_run_id.clone(),
        completed.setup_run_token_expires_at.clone(),
        completed.machine_id.clone(),
    )?;
    FileAccountStore::default()
        .save(&account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: completed.setup_run_id,
            setup_run_token_expires_at: completed.setup_run_token_expires_at,
            machine_id: completed.machine_id,
            claim_code: Some(pending.claim_code),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Persist the additive claim-completion backfill policy into the snapshot
/// backfill state (`snapshot_backfill_state.json`). An unwritable state file is
/// a poisoned-state error for `"from"` decisions — proceeding without the
/// cutoff would double-count the previous owner's history at org level.
fn persist_claim_backfill_policy(
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
    namespace: Option<String>,
) -> Result<(), LocalApiError> {
    let support_dir = default_support_dir();
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &support_dir,
        policy,
        cutoff_at,
        user_id,
        namespace.as_deref(),
    )
    .map_err(|error| {
        eprintln!("ottto-service: persisting claim backfill policy failed: {error}");
        LocalApiError::StatePoisoned
    })
}

/// Confirmed account switch (`auth_switch_account`): consume the staged claim
/// completion for `claim_code`, best-effort disconnect the OLD cloud binding
/// (tolerating auth failures and an already-deleted account), clear the old
/// local artifacts, and install the new binding in one in-memory state
/// transition. Status readers never observe an intermediate
/// `ResetRequired`→`NotConnected` hop — the binding goes straight to the new
/// `Connected` account.
fn auth_switch_account(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    daemon.require_staged_account_switch(claim_code)?;
    let staged_snapshot = daemon.staged_account_switch_snapshot(claim_code)?;
    if let Some(preparation_id) = staged_snapshot
        .relay_device_credential_preparation_id
        .as_deref()
    {
        // This bit is only the user's durable approval. The reservation is
        // revalidated immediately before every confirm, including startup
        // recovery after a crash at the next instruction.
        authorize_pending_device_credential_confirmation(preparation_id)?;
    }
    // Reserve before `take_staged_account_switch`, which mutates the
    // in-memory switch state.
    let identity_reservation = reserve_identity_mutation()?;
    let staged = daemon.take_staged_account_switch(claim_code)?;
    if staged.relay_device_credential_preparation_id.is_none() {
        disconnect_previous_binding_best_effort(
            daemon,
            staged
                .relay_device
                .as_ref()
                .map(|device| device.device_id.as_str()),
        );
    }
    match install_staged_account_switch(daemon, &staged, &identity_reservation) {
        Ok(response) => Ok(response),
        Err(error) => {
            // Keep the staged completion so the user can retry the confirm
            // (e.g. after a transient keychain/file failure) without redoing
            // the whole browser claim.
            let _ = daemon.restore_staged_account_switch(staged);
            Err(error)
        }
    }
}

/// Best-effort cloud disconnect of the binding being replaced. Failures are
/// tolerated by design: the old account may already be deleted server-side
/// (401/404), the token may be unrefreshable, or the network may be down. The
/// switch proceeds either way; the backend reconciles a dangling setup run on
/// its side.
///
/// The request also asks the server to release the previous device
/// registration, unless the incoming binding reuses the same device id: a
/// release must never revoke the credential the switch is about to install.
fn disconnect_previous_binding_best_effort(daemon: &LocalDaemon, incoming_device_id: Option<&str>) {
    let connection = match daemon.connection_for_authorized_client() {
        Ok(Some(connection)) => connection,
        Ok(None) | Err(_) => return,
    };
    let Ok(setup_run_token) = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() else {
        return;
    };
    let Ok(api_base_url) = validated_api_base_url(Some(connection.api_base_url.as_str())) else {
        return;
    };
    let release =
        load_device_release_proof().filter(|proof| releasable_on_switch(proof, incoming_device_id));
    if let Err(error) = disconnect_setup_run_with_refresh(
        &api_base_url,
        &connection,
        &setup_run_token,
        release.as_ref(),
    ) {
        eprintln!(
            "ottto-service: account switch: cloud disconnect of previous binding skipped: {error}"
        );
    }
}

fn releasable_on_switch(proof: &DeviceReleaseProof, incoming_device_id: Option<&str>) -> bool {
    incoming_device_id.map_or(true, |incoming| incoming != proof.device_id)
}

fn install_staged_account_switch(
    daemon: &LocalDaemon,
    staged: &StagedAccountSwitch,
    identity_reservation: &IdentityMutationReservation,
) -> Result<AuthCompleteResponse, LocalApiError> {
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let modern_credential = if let Some(preparation_id) =
        staged.relay_device_credential_preparation_id.as_deref()
    {
        if staged.relay_device.is_some() || staged.relay_device_secret.is_some() {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending_store = FilePendingDeviceCredentialStore::default();
        let pending = pending_store
            .load()
            .or_state_poisoned()?
            .ok_or(LocalApiError::StatePoisoned)?;
        if pending.preparation_id != preparation_id {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending = authorize_pending_device_credential_confirmation(&pending.preparation_id)?;
        let pending = mark_pending_device_credential_guards_passed(&pending, &pending_store)?;
        let candidate_secret = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .or_state_poisoned()?;
        let confirmed_pending = if pending.confirmed_at.is_some() {
            pending
        } else {
            let confirmed = confirm_device_credential_preparation(&pending, &candidate_secret)?;
            mark_pending_device_credential_confirmed(
                &pending,
                &confirmed.confirmed_at,
                &pending_store,
            )?
        };
        // Only now may the old local/cloud binding be disconnected: every
        // earlier failure cut retained usable old authority.
        disconnect_previous_binding_best_effort(
            daemon,
            Some(confirmed_pending.device.device_id.as_str()),
        );
        Some((confirmed_pending, candidate_secret))
    } else {
        None
    };
    if let Some((pending, candidate_secret)) = modern_credential.as_ref() {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        let claim = pending
            .claim_commit
            .as_ref()
            .ok_or(LocalApiError::StatePoisoned)?;
        if claim.account != staged.new_account
            || claim.connection.setup_run_id != staged.setup_run_id
            || claim.connection.setup_run_token_expires_at != staged.setup_run_token_expires_at
            || claim.connection.machine_id != staged.machine_id
            || claim.connection.claim_code.as_deref() != Some(staged.claim_code.as_str())
            || claim.backfill_policy != staged.backfill_policy
            || claim.backfill_cutoff_at != staged.backfill_cutoff_at
        {
            return Err(LocalApiError::StatePoisoned);
        }
        write_and_verify_pending_claim_commit(pending, candidate_secret)?;
        let response = daemon.install_switched_account(
            staged.new_account.clone(),
            staged.setup_run_id.clone(),
            staged.setup_run_token_expires_at.clone(),
            staged.machine_id.clone(),
            &staged.claim_code,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    reset_local_account_files_locked(Some(identity_reservation))?;
    let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
    let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
    // Persist the server-issued backfill policy BEFORE committing the new
    // binding (see auth claim completion for the failure-ordering rationale):
    // a same-org takeover must not re-attribute the previous owner's
    // already-ingested history to the new account.
    persist_claim_backfill_policy(
        staged.backfill_policy.as_deref(),
        staged.backfill_cutoff_at.as_deref(),
        staged
            .new_account
            .user
            .as_ref()
            .map(|user| user.id.as_str())
            .unwrap_or_default(),
        staged
            .relay_device
            .as_ref()
            .zip(staged.relay_device_secret.as_deref())
            .map(|(device, secret)| {
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None)
            }),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&staged.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (
        &staged.relay_device,
        &staged.relay_device_secret,
        modern_credential.as_ref(),
    ) {
        (Some(device), Some(secret), None) => {
            persist_relay_device_credentials_locked(device, secret, Some(identity_reservation))?;
            true
        }
        (None, None, Some(_)) => return Err(LocalApiError::StatePoisoned),
        (None, None, None) => false,
        _ => return Err(LocalApiError::StatePoisoned),
    };
    let response = daemon.install_switched_account(
        staged.new_account.clone(),
        staged.setup_run_id.clone(),
        staged.setup_run_token_expires_at.clone(),
        staged.machine_id.clone(),
        &staged.claim_code,
    )?;
    FileAccountStore::default()
        .save(&staged.new_account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: staged.setup_run_id.clone(),
            setup_run_token_expires_at: staged.setup_run_token_expires_at.clone(),
            machine_id: staged.machine_id.clone(),
            claim_code: Some(staged.claim_code.clone()),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Whether a terminal backend auth failure indicates the bound account (or its
/// setup run/device row) no longer exists server-side — as opposed to an
/// expired/invalid token, which is recoverable via refresh. Used to transition
/// the binding to the unbound-equivalent `account_not_found` state so the next
/// sign-in by ANY user proceeds as a fresh first claim.
pub(crate) fn backend_error_indicates_account_gone(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status == Some(404)
        && (details.endpoint.contains("/setup-runs/")
            || details.endpoint.contains("/local-client/"))
    {
        return true;
    }
    if !matches!(details.status, Some(401) | Some(403)) {
        return false;
    }
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let body = body.to_ascii_lowercase();
    body.contains("account_not_found")
        || body.contains("user_not_found")
        || body.contains("workspace_not_found")
        || body.contains("account no longer exists")
        || body.contains("user no longer exists")
        || body.contains("workspace no longer exists")
}

fn log_auth_complete_backend_failure(error: &LocalApiError) {
    if auth_complete_error_is_pending(error) {
        return;
    }
    match error {
        LocalApiError::Backend(details) => {
            let status = details
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string());
            let body = details
                .body_excerpt
                .as_deref()
                .unwrap_or("backend returned no response body");
            eprintln!(
                "ottto-service: auth_complete backend request failed endpoint={} status={} kind={:?} body_excerpt={}",
                auth_complete_log_endpoint(&details.endpoint),
                status,
                details.kind,
                body,
            );
        }
        LocalApiError::TimedOut(detail) => {
            eprintln!(
                "ottto-service: auth_complete backend request timed out endpoint=/api/v1/setup-claims/[claim]/local-client/complete detail={}",
                redact_inline(detail),
            );
        }
        _ => {}
    }
}

/// Browser approval and local claim completion are separate steps. The backend
/// returns this bounded 400 while the owner is still looking at the claim page;
/// it is an expected polling result, not a rejected pairing attempt.
fn auth_complete_error_is_pending(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status != Some(400) {
        return false;
    }
    details.body_excerpt.as_deref().is_some_and(|body| {
        body.to_ascii_lowercase()
            .contains("setup claim session is pending")
    })
}

fn auth_complete_log_endpoint(endpoint: &str) -> String {
    let marker = "/api/v1/setup-claims/";
    let Some(start) = endpoint.find(marker) else {
        return endpoint.to_string();
    };
    let prefix_end = start + marker.len();
    let Some(suffix_start) = endpoint[prefix_end..].find("/local-client/complete") else {
        return endpoint.to_string();
    };
    let suffix_index = prefix_end + suffix_start;
    format!(
        "{}[claim]{}",
        &endpoint[..prefix_end],
        &endpoint[suffix_index..]
    )
}

enum ClaimRelayDeviceCredential {
    None,
    Legacy(LocalDeviceBinding, String),
    Prepared(DeviceCredentialPreparationApiResponse),
}

/// Validate and materialize the relay-device credential transition from a
/// claim completion without persisting anything. Modern and legacy forms are
/// mutually exclusive so a malformed response cannot silently downgrade after
/// the server has created a preparation.
fn relay_device_credentials_from_claim_completion(
    completed: &SetupClaimCompleteResponse,
    prior: Option<&PriorDeviceCredential>,
) -> Result<ClaimRelayDeviceCredential, LocalApiError> {
    if let Some(prepared) = &completed.relay_device_credential_preparation {
        if completed.relay_device.is_some() || completed.relay_device_secret.is_some() {
            return Err(claim_completion_response_unexpected(
                "claim completion mixed prepared and active relay-device credentials",
            ));
        }
        validate_device_credential_preparation(
            "/api/v1/setup-claims/[claim]/local-client/complete",
            prepared,
            prior,
        )?;
        return Ok(ClaimRelayDeviceCredential::Prepared(prepared.clone()));
    }
    match (&completed.relay_device, &completed.relay_device_secret) {
        (None, None) => Ok(ClaimRelayDeviceCredential::None),
        (Some(device), Some(device_secret)) => {
            if device.sources.is_empty() || device_secret.trim().is_empty() {
                return Err(claim_completion_response_unexpected(
                    "claim completion returned incomplete relay-device credentials",
                ));
            }
            Ok(ClaimRelayDeviceCredential::Legacy(
                LocalDeviceBinding {
                    device_id: device.id.clone(),
                    machine_id: device
                        .machine_id
                        .clone()
                        .or_else(|| completed.machine_id.clone()),
                    sources: device.sources.clone(),
                },
                device_secret.clone(),
            ))
        }
        _ => Err(claim_completion_response_unexpected(
            "claim completion returned partial relay-device credentials",
        )),
    }
}

#[cfg(test)]
fn persist_relay_device_credentials(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    persist_relay_device_credentials_locked(device, device_secret, None)
}

fn persist_relay_device_credentials_locked(
    device: &LocalDeviceBinding,
    device_secret: &str,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    let device_store = FileDeviceStore::default();
    let current_device = device_store.load().or_state_poisoned()?;

    let secret_store = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    let current_secret = match current_device {
        Some(_) => match secret_store.load() {
            Ok(secret) => Some(secret),
            Err(TokenStoreError::Missing) => None,
            Err(_) => return Err(LocalApiError::StatePoisoned),
        },
        // With no active device binding, a stray old secret is not usable
        // authority and does not need to be read for rollback. This also lets
        // first registration use the owner-only fallback when Keychain reads
        // are transiently unavailable.
        None => None,
    };
    secret_store.save(device_secret).or_state_poisoned()?;
    if device_store.save(device).is_ok() {
        return Ok(());
    }

    // The device binding is an atomic file replace, but the credential spans
    // that file and Keychain. Restore the exact prior secret on any file-side
    // failure so callers never observe a durably half-rotated pair.
    let rollback = match current_secret {
        Some(secret) => secret_store.save(&secret),
        None => secret_store.delete(),
    };
    if rollback.is_err() {
        return Err(LocalApiError::StatePoisoned);
    }
    Err(LocalApiError::StatePoisoned)
}

fn pending_device_credential_from_preparation(
    api_base_url: &str,
    prepared: &DeviceCredentialPreparationApiResponse,
    confirmation_authorized: bool,
    claim_commit: Option<PendingClaimCredentialCommit>,
    request_authority: PendingDeviceCredentialRequestAuthority,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    Ok(PendingDeviceCredentialPreparation {
        schema_version: PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        capability: prepared.capability.clone(),
        preparation_id: prepared.preparation_id.clone(),
        api_base_url: validated_api_base_url(Some(api_base_url))?,
        expires_at: prepared.expires_at.clone(),
        credential_generation: prepared.credential_generation,
        secret_commitment_sha256: secret_sha256(&prepared.candidate_secret),
        request_authority: Some(request_authority),
        device: LocalDeviceBinding {
            device_id: prepared.device.id.clone(),
            machine_id: prepared.device.machine_id.clone(),
            sources: prepared.device.sources.clone(),
        },
        confirmation_authorized,
        preconfirm_guards_passed: false,
        claim_commit,
        confirmed_at: None,
    })
}

fn authorize_pending_device_credential_confirmation(
    preparation_id: &str,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    let store = FilePendingDeviceCredentialStore::default();
    let mut pending = store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.preparation_id != preparation_id {
        return Err(LocalApiError::StatePoisoned);
    }
    if pending.confirmation_authorized {
        return Ok(pending);
    }
    pending.confirmation_authorized = true;
    store.save(&pending).or_state_poisoned()?;
    if store.load().or_state_poisoned()?.as_ref() != Some(&pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(pending)
}

fn mark_pending_device_credential_guards_passed(
    pending: &PendingDeviceCredentialPreparation,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if pending.confirmed_at.is_some() {
        return if pending.confirmation_authorized && pending.preconfirm_guards_passed {
            Ok(pending.clone())
        } else {
            Err(LocalApiError::StatePoisoned)
        };
    }
    if !pending.confirmation_authorized {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut guarded = pending.clone();
    guarded.preconfirm_guards_passed = true;
    pending_store.save(&guarded).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&guarded) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(guarded)
}

fn stage_pending_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    stage_pending_device_credential_with_stores(
        pending,
        candidate_secret,
        &FilePendingDeviceCredentialStore::default(),
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

fn stage_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_candidate_secret(pending, candidate_secret).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    let existing = pending_store.load().or_state_poisoned()?;
    let effective_pending = if let Some(current) = existing.as_ref() {
        // An idempotent server retry must reproduce the entire immutable
        // preparation and candidate. Never replace a same-ID candidate or
        // mutate its account commit merely because the identifier matches.
        let mut immutable = current.clone();
        immutable.confirmation_authorized = pending.confirmation_authorized;
        immutable.preconfirm_guards_passed = pending.preconfirm_guards_passed;
        immutable.confirmed_at = pending.confirmed_at.clone();
        if immutable != *pending {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        match pending_secret_store.load() {
            Ok(stored) if stored == candidate_secret => return Ok(()),
            Ok(_) => return Err(LocalApiError::StatePoisoned),
            Err(TokenStoreError::Missing) => {}
            Err(_) => return Err(LocalApiError::StatePoisoned),
        }
        current
    } else {
        pending
    };

    pending_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    if pending_store.save(effective_pending).is_err() {
        // A newly written orphan candidate is not active authority. Remove it
        // when possible; if deletion itself fails, the active credential and
        // device binding are still unchanged and usable.
        if existing.is_none() {
            let _ = pending_secret_store.delete();
        }
        return Err(LocalApiError::StatePoisoned);
    }
    let stored_secret = pending_secret_store.load().or_state_poisoned()?;
    let stored_pending = pending_store.load().or_state_poisoned()?;
    if stored_secret != candidate_secret || stored_pending.as_ref() != Some(effective_pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn stage_pending_setup_run_token(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
) -> Result<(), LocalApiError> {
    let store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    stage_pending_setup_run_token_with_store(pending, setup_run_token, &store)
}

fn stage_pending_setup_run_token_with_store<S: ControlTokenStore + ?Sized>(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
    store: &S,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if setup_run_token.trim().is_empty()
        || claim.setup_run_token_sha256 != secret_sha256(setup_run_token)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match store.load() {
        Ok(current) if current == setup_run_token => return Ok(()),
        // A different value cannot belong to this hash-bound journal. It is
        // an inert orphan from a cut before the journal write and is safe to
        // replace with the exact server-reproduced token.
        // The same recovery is safe when the old value cannot be read (for
        // example, while macOS is re-resolving a replaced login Keychain):
        // the exact journal-bound value is written and then read back before
        // this function succeeds.
        Ok(_) | Err(_) => {}
    }
    store.save(setup_run_token).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != setup_run_token {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(crate) fn secret_sha256(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

pub(crate) fn secret_commitment_matches(commitment: &str, secret: &str) -> bool {
    constant_work_eq(commitment.as_bytes(), secret_sha256(secret).as_bytes())
}

fn constant_work_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_pending_candidate_secret(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    if candidate_secret.trim().is_empty()
        || !valid_secret_commitment(&pending.secret_commitment_sha256)
        || !secret_commitment_matches(&pending.secret_commitment_sha256, candidate_secret)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn valid_secret_commitment(commitment: &str) -> bool {
    commitment.len() == 71
        && commitment.starts_with("sha256:")
        && commitment[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_pending_prior_credential_binding(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<(), LocalApiError> {
    let Some(authority) = pending.request_authority.as_ref() else {
        // Additive compatibility for a v2 journal created by an older binary.
        return if pending.schema_version == OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
            Err(LocalApiError::StatePoisoned)
        } else {
            Ok(())
        };
    };
    if !matches!(authority.flow.as_str(), "register" | "setup_claim")
        || !valid_secret_commitment(&authority.credential_preparation_idempotency_key)
        || authority.machine_id.trim().is_empty()
        || authority.installation_id.trim().is_empty()
        || authority
            .identity_continuity_capability
            .as_deref()
            .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
        || authority
            .canonical_snapshot_namespace
            .as_deref()
            .is_some_and(|namespace| {
                authority.flow != "setup_claim"
                    || (pending.schema_version == PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION
                        && authority.prior_device_id.is_none())
                    || !crate::hex::is_sha256_lower(namespace)
            })
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if authority.incoming_snapshot_namespace.is_some()
        && (pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
            || authority.flow != "setup_claim")
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match (
        authority.prior_device_id.as_deref(),
        authority.prior_device_sources.as_deref(),
        authority.prior_secret_commitment_sha256.as_deref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(device_id), Some(sources), Some(commitment))
            if !device_id.trim().is_empty()
                && !sources.is_empty()
                && authority.identity_continuity_capability.as_deref()
                    == Some(IDENTITY_CONTINUITY_CAPABILITY)
                && valid_secret_commitment(commitment) =>
        {
            Ok(())
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

fn mark_pending_device_credential_confirmed(
    pending: &PendingDeviceCredentialPreparation,
    confirmed_at: &str,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if !pending.confirmation_authorized || !pending.preconfirm_guards_passed {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut confirmed = pending.clone();
    confirmed.confirmed_at = Some(confirmed_at.to_string());
    pending_store.save(&confirmed).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&confirmed) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(confirmed)
}

fn write_and_verify_active_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let expected_binding = LocalDeviceCredentialBinding {
        device: pending.device.clone(),
        credential_generation: pending.credential_generation,
        continuity: DeviceCredentialContinuity {
            owner: pending_credential_owner(pending),
            snapshot_namespace: pending_snapshot_alias(pending),
        },
    };

    active_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    device_store
        .save_with_credential_generation(&expected_binding)
        .or_state_poisoned()?;

    let active_secret = active_secret_store.load().or_state_poisoned()?;
    let active_binding = device_store
        .load_with_credential_generation()
        .or_state_poisoned()?;
    if active_secret != candidate_secret || active_binding.as_ref() != Some(&expected_binding) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

/// The journaled same-account namespace, bound to the staged candidate secret.
fn pending_snapshot_alias(
    pending: &PendingDeviceCredentialPreparation,
) -> Option<SnapshotNamespaceAlias> {
    let namespace = pending
        .request_authority
        .as_ref()?
        .canonical_snapshot_namespace
        .clone()?;
    Some(SnapshotNamespaceAlias {
        namespace,
        secret_commitment_sha256: pending.secret_commitment_sha256.clone(),
    })
}

fn clear_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    pending_store.reset().or_state_poisoned()?;
    let _ = pending_secret_store.delete();
    let _ = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT).delete();
    Ok(())
}

pub(crate) fn promote_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    // A failed marker write keeps the candidate staged, so recovery retries both.
    if let Ok(Some(current)) = device_store.load() {
        crate::snapshot_sync::disable_sources_dropped_from_grant(
            &default_support_dir(),
            &current,
            &pending.device,
        )
        .or_state_poisoned()?;
    }
    // After server confirmation the old active secret may already be invalid.
    // Never roll it back on a file-side failure: keep the separately staged
    // candidate intact so restart recovery can finish the same generation.
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        device_store,
        active_secret_store,
    )?;

    // Delete metadata first. A crash between these operations leaves only an
    // inert orphan Keychain entry while the verified active pair keeps working.
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn backend_error_has_status(error: &LocalApiError, status: u16) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrunedDeviceCredentialProbe {
    Confirmed,
    Inactive,
}

fn pending_device_credential_is_past_expiry(pending: &PendingDeviceCredentialPreparation) -> bool {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(&pending.expires_at, &Rfc3339)
        .is_ok_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
}

fn relay_auth_local_error(url: &str, status: u16) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: safe_backend_endpoint(url),
        status: Some(status),
        body_excerpt: None,
        reason_code: None,
    })
}

fn probe_pruned_device_credential_authority(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<PrunedDeviceCredentialProbe, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/devices/{}/relay-token",
            pending.device.device_id
        ),
    );
    let source = pending
        .device
        .sources
        .first()
        .ok_or(LocalApiError::StatePoisoned)?;
    let body = relay_token_request_payload(&pending.device, source);
    let mut probe =
        crate::relay_auth::Probe::begin(&api_base_url, &pending.device, candidate_secret, source)
            .map_err(|held| relay_auth_local_error(&url, held.status))?;
    match backend_post_json::<serde_json::Value>(
        &url,
        &body,
        &[("X-Ottto-Device-Secret", candidate_secret)],
    ) {
        Ok(_) => {
            probe.success();
            Ok(PrunedDeviceCredentialProbe::Confirmed)
        }
        Err(error)
            if matches!(
                &error,
                LocalApiError::Backend(details) if details.status == Some(401)
            ) && pending_device_credential_is_past_expiry(pending) =>
        {
            probe.reject(401);
            Ok(PrunedDeviceCredentialProbe::Inactive)
        }
        Err(error) => {
            if let LocalApiError::Backend(details) = &error {
                if let Some(status @ (401 | 403)) = details.status {
                    probe.reject(status);
                }
            }
            Err(error)
        }
    }
}

fn discard_server_inactive_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn write_and_verify_pending_claim_commit(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
        || claim.target_user_id.trim().is_empty()
        || claim.connection.setup_run_id.trim().is_empty()
        || claim
            .connection
            .claim_code
            .as_deref()
            .map_or(true, str::is_empty)
        || claim
            .account
            .user
            .as_ref()
            .map_or(true, |user| user.id != claim.target_user_id)
        || validated_api_base_url(Some(&claim.connection.api_base_url))?
            != claim.connection.api_base_url
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let pending_setup_token_store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    let setup_run_token = pending_setup_token_store.load().or_state_poisoned()?;
    if claim.setup_run_token_sha256 != secret_sha256(&setup_run_token) {
        return Err(LocalApiError::StatePoisoned);
    }

    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    // The attribution boundary must become durable before any credential or
    // account binding from the new claim. This operation is idempotent.
    persist_claim_backfill_policy(
        claim.backfill_policy.as_deref(),
        claim.backfill_cutoff_at.as_deref(),
        &claim.target_user_id,
        Some(crate::snapshot_sync::snapshot_destination_namespace(
            &pending.device,
            candidate_secret,
            pending_snapshot_alias(pending).as_ref(),
        )),
    )?;
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        &FileDeviceStore::default(),
        &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&setup_run_token)
        .or_state_poisoned()?;
    FileAccountStore::default()
        .save(&claim.account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&claim.connection)
        .or_state_poisoned()?;

    let active_setup_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .or_state_poisoned()?;
    let active_account = FileAccountStore::default().load().or_state_poisoned()?;
    let active_connection = FileConnectionStore::default().load().or_state_poisoned()?;
    if active_setup_token != setup_run_token
        || active_account != claim.account
        || active_connection.as_ref() != Some(&claim.connection)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    publish_owner_snapshot_history(pending, &FileOwnerSnapshotNamespaceStore::default())?;
    Ok(())
}

/// Resume an exact prepared generation before relays start. Local wall-clock
/// expiry never deletes a pending candidate: only a definitive server 410 can
/// prove an unconfirmed preparation is safe to discard.
pub fn recover_pending_device_credential_at_startup() -> Result<bool, LocalApiError> {
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending_secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(false);
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_prior_credential_binding(&pending).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let candidate_secret = pending_secret_store.load().or_state_poisoned()?;
    validate_pending_candidate_secret(&pending, &candidate_secret)?;
    if pending.confirmed_at.is_none() && !pending.confirmation_authorized {
        return match inspect_device_credential_preparation(&pending, &candidate_secret) {
            Ok(status) if status.status == "pending" => Ok(false),
            Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            // A server-confirmed switch that was never locally authorized is
            // an invariant violation. Retain both halves for operator recovery;
            // never silently install or discard it.
            Ok(_) => Err(LocalApiError::StatePoisoned),
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => Err(LocalApiError::StatePoisoned),
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        Ok(false)
                    }
                }
            }
            Err(error) => Err(error),
        };
    }
    if pending.confirmed_at.is_some()
        && (!pending.confirmation_authorized || !pending.preconfirm_guards_passed)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let identity_reservation = reserve_identity_mutation()?;
    // A persisted guard bit records the prior process's cut, but it is never
    // authority to confirm. Revalidate a fresh reservation at the last
    // possible point before confirm/promotion.
    let pending = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        if pending.confirmed_at.is_none() {
            mark_pending_device_credential_guards_passed(&pending, &pending_store)?
        } else {
            pending
        }
    };
    let confirmed = if pending.confirmed_at.is_some() {
        pending
    } else {
        match confirm_device_credential_preparation(&pending, &candidate_secret) {
            Ok(receipt) => mark_pending_device_credential_confirmed(
                &pending,
                &receipt.confirmed_at,
                &pending_store,
            )?,
            Err(error) if registration_history_choice_required(&error) => {
                // The lower-level refusal persisted the browser re-offer. Leave
                // the same pending candidate and old credential pair intact.
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => {
                        mark_pending_device_credential_confirmed(
                            &pending,
                            &current_rfc3339_timestamp(),
                            &pending_store,
                        )?
                    }
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        return Ok(false);
                    }
                }
            }
            Err(error) => return Err(error),
        }
    };
    let _identity_lifecycle_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    if confirmed.claim_commit.is_some() {
        write_and_verify_pending_claim_commit(&confirmed, &candidate_secret)?;
        clear_pending_device_credential(&pending_store, &pending_secret_store)?;
    } else {
        promote_pending_device_credential_with_stores(
            &confirmed,
            &candidate_secret,
            &pending_store,
            &pending_secret_store,
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    Ok(true)
}

#[cfg(test)]
fn save_relay_device_binding(device: &LocalDeviceBinding) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    save_relay_device_binding_locked(device, None)
}

#[cfg(test)]
fn save_relay_device_binding_locked(
    device: &LocalDeviceBinding,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileDeviceStore::default().save(device).or_state_poisoned()
}

fn claim_completion_response_unexpected(detail: &str) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: "/api/v1/setup-claims/[claim]/local-client/complete".to_string(),
        status: None,
        body_excerpt: Some(detail.to_string()),
        reason_code: None,
    })
}

/// `only_if_bound`: reset only while this setup run is still the bound one
/// (the automatic reset after a terminal refresh answer about it).
fn auth_reset(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    local_only: bool,
    forget_installation: bool,
    only_if_bound: Option<&LocalConnectionBinding>,
) -> Result<AuthResetResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    // Both ordinary and explicit local-only logout replace account/device
    // authority, so both drain admitted Codex cloud-task I/O first.
    let identity_reservation = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        require_setup_run_still_bound(daemon, only_if_bound)?;
        reserve_identity_mutation_locked()?
    };
    let mut cloud_disconnect: Option<SetupRunDisconnectResponse> = None;
    let mut setup_run_already_ended = false;
    let mut released_without_setup_run = false;

    if !local_only {
        let connection = daemon
            .connection_for_authorized_client()?
            .ok_or_else(|| cloud_logout_requires_connection_error(forget_installation))?;
        let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .map_err(|_| cloud_logout_requires_connection_error(forget_installation))?;
        let api_base_url = validated_api_base_url(Some(connection.api_base_url.as_str()))?;
        // Read the release proof before any local deletion below; the server
        // revokes this Mac's registration only when both halves authenticate.
        let release = load_device_release_proof();
        match disconnect_setup_run_with_refresh(
            &api_base_url,
            &connection,
            &setup_run_token,
            release.as_ref(),
        ) {
            Ok(disconnect) => cloud_disconnect = Some(disconnect),
            // Ottto already ended this run, so it can never be disconnected.
            // This Mac can still release its own registration with its device
            // secret, which needs no setup run; once Ottto confirms, the reset
            // continues exactly like a successful cloud logout. Otherwise a
            // plain logout falls through to the local-only cleanup (prior
            // device proof kept for reconnecting) and reports that Ottto was
            // not changed; forgetting the installation still needs the
            // release, and every other failure still aborts with local state
            // intact.
            Err(error)
                if terminal_refresh_rejection(&error)
                    == Some(TerminalRefreshRejection::SetupRunEnded) =>
            {
                if release
                    .as_ref()
                    .is_some_and(|release| release_device_without_setup_run(&api_base_url, release))
                {
                    released_without_setup_run = true;
                } else if forget_installation {
                    return Err(error);
                } else {
                    setup_run_already_ended = true;
                }
            }
            Err(error) => return Err(error),
        }
    }
    let local_only = local_only || setup_run_already_ended;

    // Every local deletion, Keychain included, happens under the identity
    // lifecycle lock after the binding is rechecked, so a setup run attached
    // meanwhile (which takes the same lock) is never cleared by this reset.
    let mut reset = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        require_setup_run_still_bound(daemon, only_if_bound)?;
        let retain_active = seed_owner_snapshot_history_for_logout()?;
        if local_only && retain_active {
            retain_prior_device_credential_for_logout()?;
        } else if local_only {
            // A partial promotion may mix the active file and secret halves.
            // Existing history stays intact; that mixed pair is not
            // predecessor authority for a later registration.
            clear_prior_device_selector()?;
        }
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        if !local_only || forget_installation {
            // The public selector is the usable half of a retained predecessor
            // credential. A destructive reset must durably remove it before
            // reporting success. The now-unusable Keychain half is deleted
            // best-effort below so a locked Keychain cannot strand the reset.
            clear_prior_device_selector()?;
        }
        reset_local_account_files_locked(Some(&identity_reservation))?;
        if forget_installation {
            forget_installation_state_locked()?;
        }
        let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
        let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        if !local_only || forget_installation {
            let _ = KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        }
        daemon.reset_account_for_authorized_client()?
    };
    reset.local_only = local_only;
    reset.cloud_disconnected = cloud_disconnect.is_some();
    reset.setup_run_id = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.setup_run_id.clone());
    reset.disconnected_at = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.disconnected_at.clone());
    reset.device_released = if released_without_setup_run {
        Some(true)
    } else {
        cloud_disconnect
            .as_ref()
            .map(|disconnect| disconnect.device_released)
    };
    reset.message = if released_without_setup_run {
        released_without_setup_run_message(forget_installation)
    } else if setup_run_already_ended {
        StableMessage {
            code: "setup_run_already_ended".to_string(),
            text: "Ottto had already ended this Mac's setup run, so nothing changed in Ottto and this Mac's server registration was not released. Active local credentials were cleared; prior device proof was retained securely for reconnection."
                .to_string(),
        }
    } else {
        auth_reset_message(forget_installation, reset.device_released)
    };
    Ok(reset)
}

const FORGOTTEN_INSTALLATION: &str = "Installation identity and credentials were cleared. Collected state and local sync receipts stay; only uninstall deletes them. Agent source data was not changed. Restart ottto-service before pairing.";

/// `device_released` is `None` for a local-only reset, which never contacts
/// Ottto, and the server's answer for a cloud reset.
fn auth_reset_message(forget_installation: bool, device_released: Option<bool>) -> StableMessage {
    const NOT_RELEASED: &str = "Ottto did not confirm releasing this Mac's server registration, so it may still be active; the account that owns it can disconnect this Mac on its Apps page (Disconnect).";
    const STILL_REGISTERED: &str = "This Mac may still be registered to the previous Ottto account on the server. If that account was deleted or already disconnected this Mac, sign in and choose Replace it on the claim page. Otherwise a different account can connect it only after the previous account disconnects this Mac on its Apps page (Disconnect). The normal path is `ottto logout --forget-installation --confirm` without --local-only, which releases the registration first.";
    const FORGOTTEN: &str = FORGOTTEN_INSTALLATION;
    let (code, text) = match (forget_installation, device_released) {
        (true, None) => (
            "installation_forgotten",
            format!("Ottto was not contacted. {FORGOTTEN} {STILL_REGISTERED}"),
        ),
        (true, Some(true)) => (
            "installation_forgotten",
            format!(
                "This Mac was disconnected from Ottto and its server registration was released. {FORGOTTEN}"
            ),
        ),
        (true, Some(false)) => (
            "installation_forgotten",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED} {FORGOTTEN}"),
        ),
        (false, None) => (
            "local_disconnect_complete",
            "Active local credentials were cleared without changing cloud state; prior device proof was retained securely for reconnection."
                .to_string(),
        ),
        (false, Some(true)) => (
            "cloud_disconnect_complete",
            "This Mac was disconnected from Ottto and its server registration was released."
                .to_string(),
        ),
        (false, Some(false)) => (
            "cloud_disconnect_complete",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED}"),
        ),
    };
    StableMessage {
        code: code.to_string(),
        text,
    }
}

/// A cloud reset whose setup run had already ended, after this Mac released
/// its own server registration directly.
fn released_without_setup_run_message(forget_installation: bool) -> StableMessage {
    const RELEASED: &str = "This Mac's Ottto connection had expired, so it released its server registration directly and was logged out.";
    if forget_installation {
        StableMessage {
            code: "installation_forgotten".to_string(),
            text: format!("{RELEASED} {FORGOTTEN_INSTALLATION}"),
        }
    } else {
        StableMessage {
            code: "device_released_after_run_ended".to_string(),
            text: RELEASED.to_string(),
        }
    }
}

fn forget_installation_state_locked() -> Result<(), LocalApiError> {
    // This explicit identity-forget action closes the old local ceremony.
    // Complete secure cleanup BEFORE replacing the installation identity.
    {
        let _history_lock = lock_history_recovery()?;
        let stores = history_stores();
        clear_local_release(&stores)?;
        stores.browser.delete().or_state_poisoned()?;
    }
    // Collected state, caches and receipts stay; only uninstall deletes them.
    FileMachineStore::default().reset().or_state_poisoned()?;
    Ok(())
}

#[cfg(test)]
fn reset_local_account_files() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reset_local_account_files_locked(None)
}

fn reset_local_account_files_locked(
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileAccountStore::default().reset().or_state_poisoned()?;
    FileConnectionStore::default().reset().or_state_poisoned()?;
    FileDeviceStore::default().reset().or_state_poisoned()?;
    Ok(())
}

fn cloud_logout_requires_connection_error(forget_installation: bool) -> LocalApiError {
    LocalApiError::InvalidRequest(if forget_installation {
        "logout --forget-installation requires an active Ottto cloud connection to release this Mac's server registration; use --local-only --forget-installation only to clear local state without updating Ottto"
            .to_string()
    } else {
        "logout requires an active Ottto cloud connection; use --local-only only to clear local state without updating Ottto"
            .to_string()
    })
}

#[derive(Clone, Serialize, Deserialize)]
struct SetupClaimCreateResponse {
    #[serde(default)]
    client_nonce: Option<String>,
    claim_code: String,
    claim_token: String,
    claim_url: String,
    expires_at: String,
}

impl std::fmt::Debug for SetupClaimCreateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupClaimCreateResponse([redacted])")
    }
}

#[derive(Debug, Deserialize)]
struct SetupClaimCompleteResponse {
    setup_run_id: String,
    setup_run_token: String,
    setup_run_token_expires_at: String,
    machine_id: Option<String>,
    relay_device: Option<SetupClaimCompleteRelayDevice>,
    relay_device_secret: Option<String>,
    #[serde(default)]
    relay_device_credential_preparation: Option<DeviceCredentialPreparationApiResponse>,
    connected_at: String,
    user: SetupClaimCompleteUser,
    organization: SetupClaimCompleteOrganization,
    /// Additive local-history backfill policy ("full" | "from"); absent on old
    /// backends, which means full-backfill behavior (same as "full").
    #[serde(default)]
    backfill_policy: Option<String>,
    /// Server-UTC takeover moment accompanying `backfill_policy: "from"`.
    #[serde(default)]
    backfill_cutoff_at: Option<String>,
}

/// Claim completion plus the exact prior authority snapshot used to authorize
/// it. Deliberately has no `Debug` implementation because it owns a Keychain
/// secret until the non-secret recovery journal is staged.
struct SetupClaimCompletion {
    response: SetupClaimCompleteResponse,
    prior_device_credential: Option<PriorDeviceCredential>,
    request_authority: PendingDeviceCredentialRequestAuthority,
}

#[derive(Debug, Deserialize)]
struct SetupClaimCompleteRelayDevice {
    id: String,
    machine_id: Option<String>,
    sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SetupClaimCompleteUser {
    id: String,
    email: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetupClaimCompleteOrganization {
    id: String,
    name: String,
}

fn create_setup_claim(
    machine: &MachineIdentity,
    nonce: &str,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let url = api_url("/api/v1/setup-claims");
    let _receipt_lock = lock_history_recovery()?;
    create_setup_claim_with_history(&url, machine, nonce, &history_stores(), history_now())
}

const REVOCATION_RECEIPT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
static REVOCATION_RECEIPT_LOCK: Mutex<()> = Mutex::new(());

fn history_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn lock_history_recovery() -> Result<MutexGuard<'static, ()>, LocalApiError> {
    REVOCATION_RECEIPT_LOCK.lock().or_state_poisoned()
}

struct HistoryStores {
    receipt: Box<dyn ControlTokenStore>,
    marker: Box<dyn ControlTokenStore>,
    proof: Box<dyn ControlTokenStore>,
    browser: Box<dyn ControlTokenStore>,
}

fn history_support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return ottto_core::token_store::isolated_test_secret_dir()
            .expect("isolated history test store")
            .join(format!("history-{:?}", std::thread::current().id()));
    }
    default_support_dir()
}

fn history_account_store() -> FileAccountStore {
    FileAccountStore::new(history_support_dir().join("account.json"))
}
fn history_connection_store() -> FileConnectionStore {
    FileConnectionStore::new(history_support_dir().join("connection.json"))
}

fn history_stores() -> HistoryStores {
    HistoryStores {
        receipt: history_secret_store(OTTTO_REVOCATION_RECEIPT_ACCOUNT),
        marker: history_secret_store(HISTORY_MARKER_ACCOUNT),
        proof: history_secret_store(HISTORY_PROOF_ACCOUNT),
        browser: history_secret_store(HISTORY_BROWSER_ACCOUNT),
    }
}

fn history_secret_store(account: &'static str) -> Box<dyn ControlTokenStore> {
    #[cfg(not(test))]
    {
        Box::new(KeychainSecretStore::keychain_only(account))
    }
    #[cfg(test)]
    {
        // Synthetic stores survive a daemon reload, without ever touching the
        // host Keychain or writing a receipt/device proof to a fixture file.
        use ottto_core::token_store::MemoryTokenStore;
        type TestHistoryStores = Mutex<BTreeMap<(PathBuf, &'static str), MemoryTokenStore>>;
        static STORES: std::sync::OnceLock<TestHistoryStores> = std::sync::OnceLock::new();
        let mut stores = STORES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        Box::new(
            stores
                .entry((history_support_dir(), account))
                .or_default()
                .clone(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRevocationReceipt {
    revocation_receipt: SecretString,
    received_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalReleaseMarker {
    device_id: String,
    api_base_url: String,
    released_at: i64,
    #[serde(default)]
    cleanup_required: bool,
    #[serde(default)]
    ceremony_closed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalReleaseProof {
    device_id: String,
    device_secret: SecretString,
}

// This contains claim credentials and a nonce. Never derive Debug or put it in
// account.json; only the non-secret re-offer message belongs in that file.
#[derive(Serialize, Deserialize)]
struct StoredHistoryBrowserClaim {
    installation_id: String,
    account_scope: Option<String>,
    api_base_url: String,
    setup_run_id: Option<String>,
    #[serde(default)]
    registration_pending: bool,
    nonce: SecretString,
    claim: SetupClaimCreateResponse,
}

fn history_load<T: DeserializeOwned>(
    store: &dyn ControlTokenStore,
) -> Result<Option<T>, LocalApiError> {
    match store.load() {
        Ok(encoded) => serde_json::from_str(&encoded).map(Some).or_state_poisoned(),
        Err(TokenStoreError::Missing) => Ok(None),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}
fn history_save<T: Serialize>(
    store: &dyn ControlTokenStore,
    value: &T,
) -> Result<(), LocalApiError> {
    let encoded = serde_json::to_string(value).or_state_poisoned()?;
    store.save(&encoded).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != encoded {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn stage_local_release(
    api_base_url: &str,
    release: &DeviceReleaseProof,
    stores: &HistoryStores,
    now: i64,
) -> Result<(), LocalApiError> {
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    let existing: Option<LocalReleaseMarker> = history_load(stores.marker.as_ref())?;
    // Preserve the original boundary across a refresh/retry of the release.
    let same_release = existing.as_ref().is_some_and(|m| {
        m.device_id == release.device_id
            && m.api_base_url == api_base_url
            && !m.ceremony_closed
            && now
                .checked_sub(m.released_at)
                .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if !same_release {
        stores.receipt.delete().or_state_poisoned()?;
        stores.browser.delete().or_state_poisoned()?;
    }
    let released_at = existing
        .filter(|_| same_release)
        .map_or(now, |m| m.released_at);
    history_save(
        stores.proof.as_ref(),
        &LocalReleaseProof {
            device_id: release.device_id.clone(),
            device_secret: SecretString::new(&release.device_secret),
        },
    )?;
    history_save(
        stores.marker.as_ref(),
        &LocalReleaseMarker {
            device_id: release.device_id.clone(),
            api_base_url,
            released_at,
            cleanup_required: false,
            ceremony_closed: false,
        },
    )?;
    persist_local_release_expected()
}

fn remember_revocation_receipt(
    device_released: bool,
    receipt: Option<SecretString>,
    stores: &HistoryStores,
    now: i64,
) {
    if device_released {
        // The marker and own-device proof were durably staged BEFORE release.
        // A missing receipt or failed write is recovered by the re-issue API.
        if let Some(receipt) = receipt.filter(|s| !s.expose_secret().trim().is_empty()) {
            let _ = history_save(
                stores.receipt.as_ref(),
                &StoredRevocationReceipt {
                    revocation_receipt: receipt,
                    received_at: now,
                },
            );
        }
    }
}

fn clear_local_release(stores: &HistoryStores) -> Result<(), LocalApiError> {
    // Marker is last: any partial cleanup remains a recoverable pending action.
    if let Some(mut marker) = history_load::<LocalReleaseMarker>(stores.marker.as_ref())? {
        marker.cleanup_required = true;
        marker.ceremony_closed = true;
        history_save(stores.marker.as_ref(), &marker)?;
    }
    stores.receipt.delete().or_state_poisoned()?;
    stores.proof.delete().or_state_poisoned()?;
    clear_local_release_expected()?;
    stores.marker.delete().or_state_poisoned()
}

#[derive(Debug, Deserialize)]
struct RevocationReceiptRecoveryResponse {
    outcome: String,
    #[serde(default)]
    revocation_receipt: Option<SecretString>,
    #[serde(default)]
    claim_code: Option<SecretString>,
    #[serde(default)]
    claim_token: Option<SecretString>,
    #[serde(default)]
    client_nonce: Option<SecretString>,
}

enum ReceiptRecovery {
    Receipt(SecretString),
    Claim(SetupClaimCreateResponse),
    Refused,
}

fn reissue_revocation_receipt(
    marker: &LocalReleaseMarker,
    proof: &LocalReleaseProof,
) -> Result<ReceiptRecovery, LocalApiError> {
    let base = validated_api_base_url(Some(&marker.api_base_url))?;
    if marker.device_id != proof.device_id
        || marker.device_id.is_empty()
        || !marker
            .device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let url = api_url_with_base(
        &base,
        &format!(
            "/api/v1/telemetry/devices/{}/revocation-receipt",
            marker.device_id
        ),
    );
    let response: RevocationReceiptRecoveryResponse = match backend_post_json(
        &url,
        &json!({}),
        &[("X-Ottto-Device-Secret", proof.device_secret.expose_secret())],
    ) {
        Ok(response) => response,
        Err(LocalApiError::Backend(ref details))
            if matches!(details.status, Some(401 | 409))
                && details.reason_code.as_deref().is_some_and(|code| {
                    matches!(
                        code,
                        "device_secret_invalid"
                            | "device_reactivated"
                            | "origin_not_local_switch"
                            | "release_window_expired"
                            | "ceremony_closed"
                    )
                }) =>
        {
            eprintln!(
                "ottto-service: local history recovery outcome={}",
                details.reason_code.as_deref().unwrap()
            );
            return Ok(ReceiptRecovery::Refused);
        }
        // Daemon-first rollout: old servers do not expose this endpoint yet.
        Err(LocalApiError::Backend(ref details)) if matches!(details.status, Some(404 | 405)) => {
            eprintln!("ottto-service: local history recovery outcome=receipt_reissue_unavailable");
            return Ok(ReceiptRecovery::Refused);
        }
        Err(error) => return Err(error),
    };
    match response.outcome.as_str() {
        "receipt_issued" => {
            let receipt = response
                .revocation_receipt
                .filter(|s| !s.expose_secret().trim().is_empty())
                .ok_or(LocalApiError::StatePoisoned)?;
            eprintln!("ottto-service: local history recovery outcome=receipt_issued");
            Ok(ReceiptRecovery::Receipt(receipt))
        }
        "claim_recovered" => {
            let code = response.claim_code.ok_or(LocalApiError::StatePoisoned)?;
            let token = response.claim_token.ok_or(LocalApiError::StatePoisoned)?;
            let nonce = response.client_nonce.ok_or(LocalApiError::StatePoisoned)?;
            if !code
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(LocalApiError::StatePoisoned);
            }
            #[derive(Deserialize)]
            struct ClaimStatus {
                claim_url: String,
                expires_at: String,
            }
            let status: ClaimStatus = backend_get_json(
                &api_url_with_base(
                    &base,
                    &format!("/api/v1/setup-claims/{}", code.expose_secret()),
                ),
                &[],
            )?;
            eprintln!("ottto-service: local history recovery outcome=claim_recovered");
            Ok(ReceiptRecovery::Claim(SetupClaimCreateResponse {
                claim_code: code.expose_secret().to_string(),
                claim_token: token.expose_secret().to_string(),
                client_nonce: Some(nonce.expose_secret().to_string()),
                claim_url: status.claim_url,
                expires_at: status.expires_at,
            }))
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

fn persist_history_browser_claim(
    claim: &SetupClaimCreateResponse,
    nonce: &str,
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    history_save(
        stores.browser.as_ref(),
        &StoredHistoryBrowserClaim {
            installation_id: machine.installation_id.clone(),
            account_scope: machine.account_scope.clone(),
            api_base_url: base.to_string(),
            setup_run_id: history_connection_store()
                .load()
                .or_state_poisoned()?
                .filter(|c| c.api_base_url == base)
                .map(|c| c.setup_run_id),
            registration_pending: history_account_store()
                .load()
                .is_ok_and(|account| registration_history_choice_account(&account)),
            nonce: SecretString::new(claim.client_nonce.as_deref().unwrap_or(nonce)),
            claim: claim.clone(),
        },
    )
}

fn create_setup_claim_with_history(
    url: &str,
    machine: &MachineIdentity,
    nonce: &str,
    stores: &HistoryStores,
    now: i64,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let base = validated_api_base_url(Some(
        url.strip_suffix("/api/v1/setup-claims")
            .ok_or(LocalApiError::StatePoisoned)?,
    ))?;
    let expected = local_history_recovery_expected()?;
    let mut marker: Option<LocalReleaseMarker> = match history_load(stores.marker.as_ref()) {
        Ok(marker) => marker,
        Err(_) if !expected => None,
        Err(error) => return Err(error),
    };
    if marker.as_ref().is_some_and(|m| {
        m.ceremony_closed
            || now
                .checked_sub(m.released_at)
                .is_some_and(|age| age >= REVOCATION_RECEIPT_MAX_AGE_SECONDS)
    }) {
        clear_local_release(stores)?;
        marker = None;
    }
    // Only a release or registration refusal needs durable recovery. Existing
    // first-time and same-account sign-in still works with file-only stores.
    if marker.is_none() && !local_history_recovery_expected()? {
        return backend_post_json(url, &setup_claim_create_body(machine, nonce), &[]);
    }
    if marker.is_none()
        && expected
        && !history_account_store()
            .load()
            .is_ok_and(|a| registration_history_choice_account(&a))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let stored = history_load::<StoredRevocationReceipt>(stores.receipt.as_ref());
    let mut receipt = stored.ok().flatten().filter(|r| {
        now.checked_sub(r.received_at)
            .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if let Some(marker) = &marker {
        if marker.api_base_url != base {
            return Err(LocalApiError::StatePoisoned);
        }
        if receipt.is_none() || marker.cleanup_required {
            let proof = history_load::<LocalReleaseProof>(stores.proof.as_ref())?
                .ok_or(LocalApiError::StatePoisoned)?;
            match reissue_revocation_receipt(marker, &proof)? {
                ReceiptRecovery::Receipt(value) => {
                    history_save(
                        stores.receipt.as_ref(),
                        &StoredRevocationReceipt {
                            revocation_receipt: value.clone(),
                            received_at: now,
                        },
                    )?;
                    receipt = Some(StoredRevocationReceipt {
                        revocation_receipt: value,
                        received_at: now,
                    });
                }
                ReceiptRecovery::Claim(claim) => {
                    persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
                    return Ok(claim);
                }
                ReceiptRecovery::Refused => {
                    receipt = None;
                }
            }
        }
    } else if receipt.is_none() {
        // No released-local marker means an ordinary first/same-device claim.
        // A corrupt orphan receipt is purged, never logged or sent.
        stores.receipt.delete().or_state_poisoned()?;
    }
    let mut body = setup_claim_create_body(machine, nonce);
    if let Some(receipt) = &receipt {
        body["revocation_receipt"] = json!(receipt.revocation_receipt.expose_secret());
    }
    let response = crate::retry_tls::credential_agent()
        .post(url)
        .set("Accept", "application/json")
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_json(&body);
    match response {
        Ok(response) => {
            let response = backend_success(url, response)?;
            let claim: SetupClaimCreateResponse = response
                .into_json()
                .map_err(|error| backend_response_unexpected(url, error.to_string()))?;
            if claim.claim_code.trim().is_empty()
                || claim.claim_token.trim().is_empty()
                || claim.claim_url.trim().is_empty()
            {
                return Err(LocalApiError::StatePoisoned);
            }
            // Durable browser handoff precedes secret cleanup. Even a lost local
            // reply/restart returns this exact ceremony and its original nonce.
            persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
            if stores.receipt.delete().is_err() {
                if let Some(mut marker) = marker {
                    marker.cleanup_required = true;
                    history_save(stores.marker.as_ref(), &marker)?;
                }
            }
            Ok(claim)
        }
        Err(error) => {
            if matches!(&error, ureq::Error::Status(status, _) if definitive_claim_refusal(*status))
            {
                clear_local_release(stores)?;
            }
            Err(backend_error_from_ureq(url, error))
        }
    }
}

fn definitive_claim_refusal(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 425 | 429)
}

fn resume_history_browser_claim(
    machine: &MachineIdentity,
    base: &str,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let _lock = lock_history_recovery()?;
    resume_history_browser_claim_with_stores(machine, base, &history_stores())
}

fn resume_history_browser_claim_with_stores(
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let stored = match history_load::<StoredHistoryBrowserClaim>(stores.browser.as_ref()) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Ok(None),
        Err(_) if !local_history_recovery_expected()? => return Ok(None),
        Err(_) if history_load::<LocalReleaseMarker>(stores.marker.as_ref())?.is_some() => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    if stored.installation_id != machine.installation_id
        || stored.account_scope != machine.account_scope
        || stored.api_base_url != base
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if auth_claim_is_expired(&stored.claim.expires_at) {
        return Ok(None);
    }
    Ok(Some(PendingAuthClaim {
        claim_code: stored.claim.claim_code,
        claim_token: stored.claim.claim_token,
        nonce: stored.nonce.expose_secret().to_string(),
        claim_url: append_nonce_to_claim_url(&stored.claim.claim_url, stored.nonce.expose_secret()),
        expires_at: stored.claim.expires_at,
    }))
}

fn finish_history_browser_claim(claim_code: &str) -> Result<(), LocalApiError> {
    let _lock = lock_history_recovery()?;
    finish_history_browser_claim_with_stores(claim_code, &history_stores())
}

fn finish_history_browser_claim_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let stored: Option<StoredHistoryBrowserClaim> = history_load(stores.browser.as_ref())?;
    if !stored.is_some_and(|stored| stored.claim.claim_code == claim_code) {
        return Ok(());
    }
    clear_local_release(stores)?;
    stores.browser.delete().or_state_poisoned()
}

fn setup_claim_create_body(machine: &MachineIdentity, nonce: &str) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
        "client_nonce": nonce,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

fn complete_setup_claim(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
    identity_reservation: Option<&IdentityMutationReservation>,
) -> Result<SetupClaimCompletion, LocalApiError> {
    let url = api_url(&format!(
        "/api/v1/setup-claims/{}/local-client/complete",
        claim.claim_code
    ));
    // Snapshot established file + Keychain authority under the identity
    // lifecycle fence. Network I/O runs without the mutex, while the
    // reservation prevents legitimate local writers from rotating authority.
    let prior_device_credential = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        prior_device_credential_for_registration()?
    };
    let request_authority = device_credential_request_authority(
        "setup_claim",
        &claim.claim_code,
        machine,
        prior_device_credential.as_ref(),
        prior_device_credential
            .as_ref()
            .map(|_| IDENTITY_CONTINUITY_CAPABILITY),
    );
    let mut body = setup_claim_complete_body(claim, machine);
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "credential_preparation_capability".to_string(),
            json!(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY),
        );
        object.insert(
            "credential_preparation_idempotency_key".to_string(),
            json!(request_authority
                .credential_preparation_idempotency_key
                .clone()),
        );
    }
    if let Some(prior) = prior_device_credential.as_ref() {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "identity_continuity_capability".to_string(),
                json!(IDENTITY_CONTINUITY_CAPABILITY),
            );
            object.insert("relay_device_id".to_string(), json!(prior.device_id));
            object.insert(
                "relay_device_sources".to_string(),
                json!(prior.device_sources),
            );
            object.insert(
                "prior_device_secret".to_string(),
                json!(prior.device_secret),
            );
        }
    }
    let response = backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Setup-Claim-Token", claim.claim_token.as_str())],
    )?;
    // Revalidate immediately after the remote preparation and before any
    // journal write. This catches out-of-band Keychain mutation in addition
    // to file/account mutations fenced by the reservation snapshot.
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        let current = prior_device_credential_for_registration()?;
        if !same_prior_device_authority(prior_device_credential.as_ref(), current.as_ref()) {
            return Err(LocalApiError::StatePoisoned);
        }
    }
    Ok(SetupClaimCompletion {
        response,
        prior_device_credential,
        request_authority,
    })
}

fn setup_claim_complete_body(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
) -> serde_json::Value {
    json!({
        "nonce": claim.nonce,
        "machine_id": machine.machine_id,
        "machine_identity_capability": MACHINE_IDENTITY_CAPABILITY,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
    })
}

fn api_url(path: &str) -> String {
    let base =
        std::env::var("OTTTO_API_BASE_URL").unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string());
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn append_nonce_to_claim_url(claim_url: &str, nonce: &str) -> String {
    let separator = if claim_url.contains('?') { '&' } else { '?' };
    format!("{claim_url}{separator}nonce={nonce}")
}

fn to_value(value: impl Serialize) -> Result<serde_json::Value, LocalApiError> {
    serde_json::to_value(value).or_state_poisoned()
}

/// Maps any failure of a local state read or write to `StatePoisoned`; the
/// cause is not reported.
trait OrStatePoisoned<T> {
    fn or_state_poisoned(self) -> Result<T, LocalApiError>;
}

impl<T, E> OrStatePoisoned<T> for Result<T, E> {
    fn or_state_poisoned(self) -> Result<T, LocalApiError> {
        self.map_err(|_| LocalApiError::StatePoisoned)
    }
}

#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    schema_version: u16,
    product: String,
    version: String,
    channel: ReleaseChannel,
    commit: String,
    min_supported_version: String,
    min_protocol_version: u16,
    supported_install_owners: Vec<InstallOwner>,
    #[serde(default)]
    release_notes: Option<String>,
    rollback: ReleaseRollback,
    #[serde(default)]
    artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug, Deserialize)]
struct ReleaseRollback {
    strategy: String,
    immutable_prefix: String,
    latest_manifest_url: String,
    preserve_failed_version: bool,
}

#[derive(Debug, Deserialize)]
struct ReleaseArtifact {
    kind: String,
    platform: String,
    arch: String,
    url: String,
}

fn check_update_state() -> UpdateState {
    let current_version = compiled_release_version();
    let local_channel = local_release_channel();
    let checked_at = Some(current_rfc3339());
    let build_id = compiled_build_id();
    let install_owner = detect_install_owner();

    let manifest_url = std::env::var("OTTTO_RELEASE_MANIFEST_URL")
        .unwrap_or_else(|_| default_release_manifest_url(&local_channel));
    let manifest = crate::retry_tls::agent()
        .get(&manifest_url)
        .set("Accept", "application/json")
        .timeout(Duration::from_secs(5))
        .call()
        .ok()
        .and_then(|response| response.into_json::<ReleaseManifest>().ok());

    let Some(manifest) = manifest else {
        return UpdateState {
            current_version,
            latest_version: None,
            channel: local_channel,
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: None,
            min_protocol_version: None,
            checked_at,
            reason: Some("release manifest was unavailable".to_string()),
            download_url: None,
            build_id,
            update_command: None,
            update_instructions: None,
            release_notes: None,
        };
    };

    update_state_from_manifest(
        manifest,
        current_version,
        local_channel,
        checked_at,
        build_id,
        install_owner,
    )
}

fn update_state_from_manifest(
    manifest: ReleaseManifest,
    current_version: String,
    local_channel: ReleaseChannel,
    checked_at: Option<String>,
    build_id: Option<String>,
    install_owner: InstallOwner,
) -> UpdateState {
    if let Some(reason) = release_manifest_metadata_error(&manifest) {
        let download_url = app_download_url(&manifest);
        let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
        return UpdateState {
            current_version,
            latest_version: Some(manifest.version),
            channel: local_channel,
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: Some(manifest.min_supported_version),
            min_protocol_version: Some(manifest.min_protocol_version),
            checked_at,
            reason: Some(reason),
            download_url,
            build_id: build_id.or(Some(manifest.commit)),
            update_command: None,
            update_instructions: None,
            release_notes,
        };
    }

    if manifest.channel != local_channel {
        let download_url = app_download_url(&manifest);
        let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
        let latest_version = manifest.version.clone();
        let manifest_channel = manifest.channel.clone();
        return UpdateState {
            current_version,
            latest_version: Some(latest_version),
            channel: local_channel.clone(),
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: Some(manifest.min_supported_version),
            min_protocol_version: Some(manifest.min_protocol_version),
            checked_at,
            reason: Some(format!(
                "local {local_channel:?} build cannot be compared to {manifest_channel:?} release metadata"
            )),
            download_url,
            build_id: build_id.or(Some(manifest.commit)),
            update_command: None,
            update_instructions: None,
            release_notes,
        };
    }

    let manifest_tuple = version_tuple(&manifest.version);
    let current_tuple = version_tuple(&current_version);
    // Pre-release channels (dev/preview) ship versions like `0.1.0-dev-AAAA`. The
    // semver tuple collapses every dev build to (0,1,0), so we also compare the
    // recorded git commit when the tuple is equal. Without this, every dev user
    // is told they are current even when a newer build sits in the manifest.
    let build_differs = build_id
        .as_ref()
        .map_or(current_version != manifest.version, |local| {
            !commits_equivalent(local, &manifest.commit)
        });
    let update_available =
        manifest_tuple > current_tuple || (manifest_tuple == current_tuple && build_differs);
    let below_min_supported = current_tuple < version_tuple(&manifest.min_supported_version);
    let protocol_incompatible = PROTOCOL_VERSION < manifest.min_protocol_version;
    let gate = if below_min_supported || protocol_incompatible {
        UpdateGate::HardBlock
    } else if update_available {
        UpdateGate::SoftWarn
    } else {
        UpdateGate::Current
    };
    let update_required = !matches!(gate, UpdateGate::Current);
    let download_url = app_download_url(&manifest);
    let reason = if protocol_incompatible {
        Some(format!(
            "release requires local protocol v{}; this build supports v{}",
            manifest.min_protocol_version, PROTOCOL_VERSION
        ))
    } else if below_min_supported {
        Some(format!(
            "current version is below the minimum supported version {}",
            manifest.min_supported_version
        ))
    } else if update_available {
        if manifest_tuple > current_tuple {
            Some("A newer Ottto app is available.".to_string())
        } else {
            Some(format!(
                "A newer Ottto app build is available ({})",
                manifest.commit
            ))
        }
    } else {
        Some("You are running the latest available version.".to_string())
    };
    let (update_command, update_instructions) = if update_required {
        update_route_for_owner(install_owner, &manifest.supported_install_owners)
    } else {
        (None, None)
    };
    let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
    UpdateState {
        current_version,
        latest_version: Some(manifest.version),
        channel: local_channel,
        status: if update_required {
            UpdateStatus::UpdateAvailable
        } else {
            UpdateStatus::Current
        },
        gate,
        install_owner,
        min_supported_version: Some(manifest.min_supported_version),
        min_protocol_version: Some(manifest.min_protocol_version),
        checked_at,
        reason,
        download_url,
        build_id: build_id.or(Some(manifest.commit)),
        update_command,
        update_instructions,
        release_notes,
    }
}

fn normalized_release_notes(release_notes: Option<&str>) -> Option<String> {
    release_notes
        .map(str::trim)
        .filter(|notes| !notes.is_empty())
        .map(ToOwned::to_owned)
}

fn release_manifest_metadata_error(manifest: &ReleaseManifest) -> Option<String> {
    if manifest.schema_version != 1 {
        return Some(format!(
            "unsupported release manifest schema_version {}",
            manifest.schema_version
        ));
    }
    if manifest.product != "ottto-local-platform" {
        return Some(format!(
            "unexpected release manifest product {}",
            manifest.product
        ));
    }
    if manifest.min_supported_version.trim().is_empty() {
        return Some("release manifest is missing min_supported_version".to_string());
    }
    if manifest.min_protocol_version == 0 {
        return Some("release manifest has invalid min_protocol_version".to_string());
    }
    if manifest.supported_install_owners.is_empty() {
        return Some("release manifest must list supported install owners".to_string());
    }
    if manifest.rollback.strategy != "channel_latest_pointer" {
        return Some(
            "release manifest is missing channel_latest_pointer rollback metadata".to_string(),
        );
    }
    if manifest.rollback.immutable_prefix.trim().is_empty()
        || !valid_update_manifest_url(&manifest.rollback.immutable_prefix)
    {
        return Some("release manifest has invalid rollback immutable_prefix".to_string());
    }
    if manifest.rollback.latest_manifest_url.trim().is_empty()
        || !valid_update_manifest_url(&manifest.rollback.latest_manifest_url)
        || !manifest
            .rollback
            .latest_manifest_url
            .ends_with("/release-manifest.json")
    {
        return Some("release manifest has invalid rollback latest_manifest_url".to_string());
    }
    if !manifest.rollback.preserve_failed_version {
        return Some(
            "release manifest rollback must preserve failed versioned artifacts".to_string(),
        );
    }
    if manifest.artifacts.is_empty() {
        return Some("release manifest has no artifacts".to_string());
    }
    let immutable_prefix = format!(
        "{}/",
        manifest.rollback.immutable_prefix.trim_end_matches('/')
    );
    if manifest
        .artifacts
        .iter()
        .any(|artifact| !artifact.url.starts_with(&immutable_prefix))
    {
        return Some(
            "release manifest artifact URL is outside rollback immutable_prefix".to_string(),
        );
    }
    None
}

fn valid_update_manifest_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://[::1]")
}

fn update_route_for_owner(
    install_owner: InstallOwner,
    supported_install_owners: &[InstallOwner],
) -> (Option<String>, Option<String>) {
    if !install_owner_supported(install_owner, supported_install_owners) {
        return (
            None,
            Some(format!(
                "This release manifest does not advertise an update route for {} installs. Install the latest Ottto local platform from the Apps page.",
                install_owner_label(install_owner)
            )),
        );
    }

    match install_owner {
        InstallOwner::Homebrew => (
            Some("brew update && brew upgrade ottto".to_string()),
            Some("Update this Homebrew-managed install with brew.".to_string()),
        ),
        InstallOwner::HostedInstaller => (
            Some("curl -fsSL https://ottto.net/install.sh | bash".to_string()),
            Some(
                "Update this hosted-installer install by rerunning the Ottto installer."
                    .to_string(),
            ),
        ),
        InstallOwner::AppBundle => (
            None,
            Some(
                "Update this app-bundled install by installing the latest Ottto.app release."
                    .to_string(),
            ),
        ),
        InstallOwner::Dev => (
            None,
            Some(
                "Dev-owned installs must be updated with an explicit developer command."
                    .to_string(),
            ),
        ),
        InstallOwner::Unknown => (
            None,
            Some("Install the latest Ottto local platform from the Apps page.".to_string()),
        ),
    }
}

fn install_owner_supported(
    install_owner: InstallOwner,
    supported_install_owners: &[InstallOwner],
) -> bool {
    install_owner == InstallOwner::Unknown || supported_install_owners.contains(&install_owner)
}

fn install_owner_label(install_owner: InstallOwner) -> &'static str {
    match install_owner {
        InstallOwner::Homebrew => "Homebrew",
        InstallOwner::HostedInstaller => "hosted-installer",
        InstallOwner::AppBundle => "app-bundled",
        InstallOwner::Dev => "dev",
        InstallOwner::Unknown => "unknown-owner",
    }
}

fn detect_install_owner() -> InstallOwner {
    std::env::current_exe()
        .ok()
        .as_deref()
        .map(install_owner_for_path)
        .unwrap_or(InstallOwner::Unknown)
}

/// Best-effort: surface the AI-generated machine icon (persisted by the snapshot
/// sync from the backend response) on `status.machine.icon_url`, so the Companion
/// footer matches the web /apps machine identity. Any failure leaves it unset and
/// the app falls back to its procedural glyph.
fn inject_machine_icon(status_value: &mut serde_json::Value) {
    apply_machine_icon(status_value, load_persisted_machine_icon());
}

fn apply_machine_icon(status_value: &mut serde_json::Value, icon: Option<(String, String)>) {
    let Some((icon_machine_id, icon_url)) = icon else {
        return;
    };
    if icon_url.is_empty() {
        return;
    }
    let Some(machine) = status_value
        .get_mut("machine")
        .and_then(|m| m.as_object_mut())
    else {
        return;
    };
    let matches =
        machine.get("machine_id").and_then(|v| v.as_str()) == Some(icon_machine_id.as_str());
    if matches {
        machine.insert("icon_url".to_string(), serde_json::Value::String(icon_url));
    }
}

fn load_persisted_machine_icon() -> Option<(String, String)> {
    let path = ottto_core::default_support_dir().join("machine_icon.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let machine_id = value.get("machine_id")?.as_str()?.to_string();
    let icon_url = value.get("icon_url")?.as_str()?.to_string();
    Some((machine_id, icon_url))
}

#[cfg(test)]
mod machine_icon_tests {
    use super::apply_machine_icon;

    #[test]
    fn injects_icon_when_machine_matches() {
        let mut status =
            serde_json::json!({ "machine": { "machine_id": "otm_x", "hostname": "h" } });
        apply_machine_icon(
            &mut status,
            Some(("otm_x".to_string(), "https://icon.png".to_string())),
        );
        assert_eq!(
            status["machine"]["icon_url"],
            serde_json::json!("https://icon.png")
        );
    }

    #[test]
    fn skips_on_mismatch_empty_or_none() {
        let mut status = serde_json::json!({ "machine": { "machine_id": "otm_x" } });
        apply_machine_icon(
            &mut status,
            Some(("otm_other".to_string(), "https://icon.png".to_string())),
        );
        assert!(status["machine"].get("icon_url").is_none());
        apply_machine_icon(&mut status, Some(("otm_x".to_string(), String::new())));
        assert!(status["machine"].get("icon_url").is_none());
        apply_machine_icon(&mut status, None);
        assert!(status["machine"].get("icon_url").is_none());
    }
}

fn service_owner_state(client_owner: InstallOwner) -> ServiceOwnerState {
    let daemon_owner = detect_install_owner();
    let owner_state = local_lifecycle_home_dir().ok().map(|home| {
        let plist_path = crate::macos_service::launch_agent_path(&home);
        crate::macos_service::inspect_launch_agent_owner(
            &plist_path,
            std::env::current_exe().ok().as_deref(),
        )
    });
    let (plist_owner, loaded_owner, plist_exists, launchd_loaded, mut owner_drift) =
        if let Some(owner_state) = owner_state {
            (
                owner_state.plist_owner,
                owner_state.loaded_owner,
                owner_state.plist_exists,
                owner_state.loaded,
                owner_state.owner_drift,
            )
        } else {
            (
                InstallOwner::Unknown,
                InstallOwner::Unknown,
                false,
                false,
                false,
            )
        };

    owner_drift |= client_owner_conflict(client_owner, daemon_owner)
        || client_owner_conflict(client_owner, plist_owner)
        || client_owner_conflict(client_owner, loaded_owner);

    ServiceOwnerState {
        daemon_owner,
        plist_owner,
        loaded_owner,
        client_owner,
        owner_drift,
        plist_exists,
        launchd_loaded,
        repair_command: owner_repair_command(preferred_repair_owner(
            client_owner,
            loaded_owner,
            plist_owner,
            daemon_owner,
        ))
        .map(ToString::to_string),
        detail: Some(owner_state_detail(owner_drift, client_owner, daemon_owner)),
    }
}

fn client_owner_conflict(client_owner: InstallOwner, service_owner: InstallOwner) -> bool {
    if client_owner == InstallOwner::Unknown || service_owner == InstallOwner::Unknown {
        return false;
    }
    if client_owner == service_owner {
        return false;
    }
    // The signed app bundle is also the supported UI for a Homebrew-owned
    // daemon. Client/service packaging can differ without service drift; the
    // launchd/plist/loaded owners still decide whether mutation is safe.
    if matches!(
        (client_owner, service_owner),
        (InstallOwner::AppBundle, InstallOwner::HostedInstaller)
            | (InstallOwner::AppBundle, InstallOwner::Homebrew)
            | (InstallOwner::HostedInstaller, InstallOwner::AppBundle)
    ) {
        return false;
    }
    true
}

fn preferred_repair_owner(
    client_owner: InstallOwner,
    loaded_owner: InstallOwner,
    plist_owner: InstallOwner,
    daemon_owner: InstallOwner,
) -> InstallOwner {
    for owner in [loaded_owner, plist_owner, daemon_owner, client_owner] {
        if owner != InstallOwner::Unknown {
            return owner;
        }
    }
    InstallOwner::Unknown
}

fn owner_repair_command(owner: InstallOwner) -> Option<&'static str> {
    match owner {
        InstallOwner::Homebrew => Some("brew services restart ottto"),
        InstallOwner::HostedInstaller => Some("rerun the Ottto installer"),
        InstallOwner::AppBundle => Some("quit and relaunch the Ottto app"),
        InstallOwner::Dev => Some("run the explicit dev repair command"),
        InstallOwner::Unknown => None,
    }
}

fn owner_state_detail(
    owner_drift: bool,
    client_owner: InstallOwner,
    daemon_owner: InstallOwner,
) -> String {
    if owner_drift {
        return format!(
            "LaunchAgent owner drift detected between {} client and {} daemon.",
            install_owner_label(client_owner),
            install_owner_label(daemon_owner)
        );
    }
    format!(
        "LaunchAgent owner is {}.",
        install_owner_label(daemon_owner)
    )
}

fn commits_equivalent(local: &str, remote: &str) -> bool {
    if local == remote {
        return true;
    }
    let min_len = local.len().min(remote.len()).min(40);
    if min_len < 7 {
        return false;
    }
    local[..min_len].eq_ignore_ascii_case(&remote[..min_len])
}

fn local_release_channel() -> ReleaseChannel {
    std::env::var("OTTTO_RELEASE_CHANNEL")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| release_channel_from_str(&value))
        .unwrap_or_else(compiled_release_channel)
}

fn default_release_manifest_url(channel: &ReleaseChannel) -> String {
    format!(
        "https://install.ottto.net/ottto-local-platform/releases/{}/latest/release-manifest.json",
        release_channel_slug(channel)
    )
}

fn release_channel_slug(channel: &ReleaseChannel) -> &'static str {
    match channel {
        ReleaseChannel::Dev => "dev",
        ReleaseChannel::Preview => "preview",
        ReleaseChannel::StableCandidate => "stable-candidate",
        ReleaseChannel::Stable => "stable",
    }
}

fn app_download_url(manifest: &ReleaseManifest) -> Option<String> {
    manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == "macos_app"
                && artifact.platform == "macos"
                && (artifact.arch == std::env::consts::ARCH || artifact.arch == "universal")
        })
        .map(|artifact| artifact.url.clone())
}

fn version_tuple(value: &str) -> (u64, u64, u64) {
    let mut parts = value
        .split('-')
        .next()
        .unwrap_or(value)
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok());
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

fn cli_error(error: LocalApiError) -> CliError {
    let mut details = BTreeMap::new();
    let code = match &error {
        LocalApiError::Unauthorized => CliErrorCode::LocalAuthFailed,
        LocalApiError::LocalClientNotTrusted => CliErrorCode::LocalClientNotTrusted,
        LocalApiError::AccountResetRequired => CliErrorCode::AccountResetRequired,
        LocalApiError::AccountSwitchCandidate {
            current_user_email,
            new_user_email,
            new_organization_name,
            claim_code,
        } => {
            // Same wire code as AccountResetRequired so pre-switch clients keep
            // their existing reset flow; switch-aware clients read these
            // additive details to render a confirm dialog and call
            // `auth_switch_account` with the claim code.
            details.insert("switch_candidate".to_string(), RedactedValue::Bool(true));
            details.insert(
                "current_user_email".to_string(),
                RedactedValue::String(current_user_email.clone()),
            );
            details.insert(
                "new_user_email".to_string(),
                RedactedValue::String(new_user_email.clone()),
            );
            details.insert(
                "new_organization_name".to_string(),
                RedactedValue::String(new_organization_name.clone()),
            );
            details.insert(
                "claim_code".to_string(),
                RedactedValue::String(claim_code.clone()),
            );
            CliErrorCode::AccountResetRequired
        }
        LocalApiError::RepairLocked => CliErrorCode::RepairLocked,
        LocalApiError::StatePoisoned => CliErrorCode::Internal,
        LocalApiError::EmptyControlToken => CliErrorCode::InvalidRequest,
        LocalApiError::NoPendingAuthClaim | LocalApiError::AuthClaimMismatch => {
            CliErrorCode::InvalidRequest
        }
        LocalApiError::SetupRunConnectionMissing => CliErrorCode::NeedsUserAction,
        LocalApiError::SetupRunConnectionMismatch => CliErrorCode::InvalidRequest,
        LocalApiError::CloudSessionCleanupRequired => {
            details.insert(
                "reason_code".to_string(),
                RedactedValue::String("cloud_session_cleanup_required".to_string()),
            );
            CliErrorCode::NeedsUserAction
        }
        LocalApiError::IdentityMutationInProgress => {
            details.insert(
                "reason_code".to_string(),
                RedactedValue::String("identity_mutation_in_progress".to_string()),
            );
            CliErrorCode::NeedsUserAction
        }
        LocalApiError::InvalidRequest(_) | LocalApiError::RetiredCommand(_) => {
            CliErrorCode::InvalidRequest
        }
        LocalApiError::ManualFenceReviewRequired => CliErrorCode::ManualFenceReviewRequired,
        LocalApiError::LocalOperationFailed(_) => CliErrorCode::Internal,
        LocalApiError::NetworkUnavailable => CliErrorCode::NetworkUnavailable,
        LocalApiError::TimedOut(reason) => {
            details.insert("detail".to_string(), RedactedValue::String(reason.clone()));
            CliErrorCode::TimedOut
        }
        LocalApiError::Backend(backend) => {
            details.insert(
                "endpoint".to_string(),
                RedactedValue::String(backend.endpoint.clone()),
            );
            if let Some(status) = backend.status {
                details.insert("status".to_string(), RedactedValue::Number(status as i64));
            }
            if let Some(body_excerpt) = &backend.body_excerpt {
                details.insert(
                    "body_excerpt".to_string(),
                    RedactedValue::String(body_excerpt.clone()),
                );
            }
            if let Some(reason_code) = &backend.reason_code {
                details.insert(
                    "reason_code".to_string(),
                    RedactedValue::String(reason_code.clone()),
                );
            } else if backend_error_means_mac_disconnected(&error) {
                details.insert(
                    "reason_code".to_string(),
                    RedactedValue::String(MAC_DISCONNECTED_REASON_CODE.to_string()),
                );
            }
            match backend.kind {
                BackendErrorKind::Unreachable => CliErrorCode::BackendUnreachable,
                BackendErrorKind::Rejected => CliErrorCode::BackendRejected,
                BackendErrorKind::Unavailable => CliErrorCode::BackendUnavailable,
                BackendErrorKind::ResponseUnexpected => CliErrorCode::BackendResponseUnexpected,
            }
        }
    };

    let message = cli_error_message(&error);
    CliError {
        message,
        retryable: matches!(
            code,
            CliErrorCode::RepairLocked
                | CliErrorCode::Internal
                | CliErrorCode::TimedOut
                | CliErrorCode::BackendUnreachable
                | CliErrorCode::BackendUnavailable
        ),
        code,
        details,
    }
}

fn cli_error_message(error: &LocalApiError) -> String {
    match error {
        LocalApiError::SetupRunConnectionMissing => {
            "Setup needs browser approval. Open the Ottto app from Ottto, or run setup with a fresh claim code.".to_string()
        }
        LocalApiError::TimedOut(_) => {
            if let Some(message) = agent_read_timeout_message(error) {
                return message;
            }
            "Timed out waiting for setup to complete. Open the Ottto app from Ottto and retry.".to_string()
        }
        LocalApiError::Backend(backend) => {
            let diagnostics_upload = backend.endpoint.contains("/diagnostics/");
            let logout_disconnect = backend.endpoint.contains("/local-client/disconnect");
            let body = backend
                .body_excerpt
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if body.contains("revoked_cross_account_predecessor") {
                return MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE.to_string();
            }
            if body.contains("cross-account takeover requires the exact active predecessor") {
                return "This Mac still has a live registration for another Ottto account. Complete the takeover from that live installation with its exact saved device credential, or have the prior owner revoke it before the new owner approves Replace it."
                    .to_string();
            }
            if body.contains("requires an explicit relay device") {
                return "This Mac is already registered. Choose Reconnect it in the Ottto app to use the saved device credential, or choose Replace it on the browser claim page.".to_string();
            }
            if body.contains("requires an explicit prior credential") {
                return "This Mac is already registered but its prior device credential is unavailable. Choose Replace it on the browser claim page, then retry `ottto login` or `ottto setup`.".to_string();
            }
            if body.contains("more than one active authority") {
                return "This Mac has multiple active registrations. Choose Replace it on the browser claim page to revoke them and create one fresh device, then retry `ottto login` or `ottto setup`.".to_string();
            }
            match backend.reason_code.as_deref() {
                Some("timezone_query_unsupported") => {
                    return TIMEZONE_OVERRIDE_UNSUPPORTED.to_string();
                }
                Some("machine_filter_unsupported") => {
                    return "Ottto can't filter costs to one Mac yet. Remove --machine-id: the default answer is account-wide and its by_machine rows show each Mac.".to_string();
                }
                Some("no_committed_answer") => {
                    return "Ottto has no numbers for this window yet. They are unavailable, not zero; try again later.".to_string();
                }
                Some("results_not_served") => {
                    return "Ottto could not read these numbers from its current calculation. They are unavailable, not zero; try again later.".to_string();
                }
                // Typed Results refusals: a settled answer, not a setup failure.
                Some(_) if backend.status == Some(422) => {
                    return "Ottto can't answer this read yet.".to_string();
                }
                _ => {}
            }
            // Exact backend detail for a run Ottto no longer accepts. Other
            // text that merely mentions expiry (a short-lived companion token
            // the daemon refreshes, for example) is not a dead setup run.
            if backend.status == Some(401)
                && backend.endpoint.contains("/local-client/")
                && matches!(
                    backend_error_detail(backend).as_deref(),
                    Some(SETUP_RUN_EXPIRED_DETAIL | SETUP_RUN_CANCELLED_DETAIL)
                )
            {
                return "Setup run expired. Run `ottto login` to reconnect this Mac.".to_string();
            }
            if backend.status == Some(401) || backend.status == Some(403) {
                if diagnostics_upload {
                    return "Ottto rejected the diagnostics upload. Sign in again or use a fresh support claim.".to_string();
                }
                if logout_disconnect {
                    return "Ottto rejected the cloud logout for this Mac. Sign in from the Ottto app or use `ottto logout --local-only` only to clear local state.".to_string();
                }
                if backend_error_means_mac_disconnected(error) {
                    return MAC_DISCONNECTED_MESSAGE.to_string();
                }
                return "Ottto rejected the local setup request. Open the Ottto app from Ottto to attach an active setup run.".to_string();
            }
            match backend.kind {
                BackendErrorKind::Unreachable if logout_disconnect => {
                    "Ottto is unreachable, so logout did not clear local credentials. Retry when online or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Unreachable => "Ottto is unreachable from this Mac.".to_string(),
                BackendErrorKind::Unavailable if logout_disconnect => {
                    "Ottto is temporarily unavailable, so logout did not clear local credentials. Retry or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Unavailable => "Ottto is temporarily unavailable.".to_string(),
                BackendErrorKind::Rejected if diagnostics_upload => {
                    "Ottto rejected the diagnostics upload.".to_string()
                }
                BackendErrorKind::Rejected if logout_disconnect => {
                    "Ottto rejected the cloud logout for this Mac. Sign in from the Ottto app or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Rejected => "Ottto rejected the local setup request.".to_string(),
                BackendErrorKind::ResponseUnexpected if diagnostics_upload => {
                    "Ottto returned an unexpected diagnostics upload response.".to_string()
                }
                BackendErrorKind::ResponseUnexpected if logout_disconnect => {
                    "Ottto returned an unexpected logout response, so local credentials were not cleared.".to_string()
                }
                BackendErrorKind::ResponseUnexpected => {
                    "Ottto returned an unexpected setup response.".to_string()
                }
            }
        }
        _ => error.to_string(),
    }
}

/// The string `detail` of a JSON error body excerpt, if it has one.
fn backend_error_detail(backend: &BackendErrorDetails) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(backend.body_excerpt.as_deref()?).ok()?;
    value
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Plain guidance when Ottto refuses this Mac because its device was revoked
/// or its account was deleted. The generic "rejected the local setup request"
/// line told the user neither what happened nor what to do.
const MAC_DISCONNECTED_MESSAGE: &str =
    "This Mac was disconnected from its Ottto account. Sign in to connect it again.";

/// The new owner's sign-in found this Mac's revoked device from another Ottto
/// account (`revoked_cross_account_predecessor`). Replace it on the browser
/// claim page is still the step that binds it to the new account.
const MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE: &str = "This Mac was disconnected from its earlier Ottto account. To connect it to your account, choose Replace it on the sign-in page in your browser.";

/// Typed signal for the same case in the error details, so the app and the CLI
/// act on it without matching message text.
const MAC_DISCONNECTED_REASON_CODE: &str = "mac_disconnected";

/// Exact backend `detail` strings that mean Ottto no longer accepts this Mac's
/// device or account. A compatibility path until the backend types them.
const MAC_DISCONNECTED_DETAILS: [&str; 7] = [
    "Telemetry device is not active",
    "Telemetry device is revoked",
    "Telemetry device not found",
    "Telemetry device secret is invalid",
    "Telemetry device was revoked during registration",
    "Setup run owner not found",
    "Setup run organization not found",
];

/// Ottto refused this Mac (401/403) because its device was revoked or its
/// account no longer exists. Diagnostics uploads and cloud logout keep their
/// own guidance.
fn backend_error_means_mac_disconnected(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(backend) = error else {
        return false;
    };
    if !matches!(backend.status, Some(401 | 403))
        || backend.endpoint.contains("/diagnostics/")
        || backend.endpoint.contains("/local-client/disconnect")
    {
        return false;
    }
    backend_error_indicates_account_gone(error)
        || backend_error_detail(backend)
            .is_some_and(|detail| MAC_DISCONNECTED_DETAILS.contains(&detail.as_str()))
}

const SETUP_RUN_EXPIRED_DETAIL: &str = "Setup run expired";
const SETUP_RUN_CANCELLED_DETAIL: &str = "Setup run cancelled";

/// Why a device-secret refresh can never succeed for the current binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalRefreshRejection {
    /// Ottto ended the setup run (expired or cancelled); it is never revived.
    SetupRunEnded,
    /// Ottto no longer accepts this Mac's device credential.
    DeviceRejected,
}

/// An authoritative terminal answer from `/local-client/refresh`. The backend
/// does not type these yet, so this matches its exact JSON `detail` on that
/// endpoint only (a compatibility path, never a substring). Any other 401,
/// including an unrecognized detail, and every transport failure is not proof.
pub(crate) fn terminal_refresh_rejection(
    error: &LocalApiError,
) -> Option<TerminalRefreshRejection> {
    let LocalApiError::Backend(details) = error else {
        return None;
    };
    if details.status != Some(401)
        || !details.endpoint.contains("/api/v1/setup-runs/")
        || !details.endpoint.ends_with("/local-client/refresh")
    {
        return None;
    }
    match backend_error_detail(details).as_deref()? {
        SETUP_RUN_EXPIRED_DETAIL | SETUP_RUN_CANCELLED_DETAIL => {
            Some(TerminalRefreshRejection::SetupRunEnded)
        }
        "Telemetry device is not active"
        | "Telemetry device secret is invalid"
        | "Telemetry device not found" => Some(TerminalRefreshRejection::DeviceRejected),
        _ => None,
    }
}

fn bounded_display_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

struct ReattachRequiredState {
    message: StableMessage,
    can_reconnect: bool,
}

fn reattach_required_state(error: &LocalApiError) -> Option<ReattachRequiredState> {
    let LocalApiError::Backend(backend) = error else {
        return None;
    };
    let raw = backend.body_excerpt.as_deref().unwrap_or_default();
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let detail = parsed.as_ref().and_then(|value| value.get("detail"));
    let detail_object = detail.and_then(serde_json::Value::as_object);
    let backend_message = detail_object
        .and_then(|object| object.get("message"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| detail.and_then(serde_json::Value::as_str))
        .unwrap_or(raw);
    let lower = backend_message.to_ascii_lowercase();
    let reason = detail_object
        .and_then(|object| object.get("reason"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            matches!(
                *value,
                "existing_authority"
                    | "multiple_active_authorities"
                    | "revoked_cross_account_predecessor"
            )
        })
        .or_else(|| {
            lower
                .contains("more than one active authority")
                .then_some("multiple_active_authorities")
        })
        .or_else(|| {
            (lower.contains("requires an explicit relay device")
                || lower.contains("requires an explicit prior credential"))
            .then_some("existing_authority")
        })?;
    let device_name = detail_object
        .and_then(|object| object.get("device_name"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_display_text(value, 80))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "this Mac".to_string());
    let last_seen = detail_object
        .and_then(|object| object.get("last_seen_at"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_display_text(value, 40))
        .filter(|value| !value.is_empty());
    let last_seen_text = last_seen
        .map(|value| format!(" (last seen {value})"))
        .unwrap_or_default();
    let can_reconnect = detail_object
        .and_then(|object| object.get("can_reconnect"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let text = if can_reconnect {
        format!(
            "This Mac is already registered as {device_name}{last_seen_text}. Reconnect it with the saved credential, or approve Replace it in the browser."
        )
    } else {
        MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE.to_string()
    };
    Some(ReattachRequiredState {
        message: StableMessage {
            code: format!("reattach_required:{reason}"),
            text,
        },
        can_reconnect,
    })
}

fn agent_read_timeout_message(error: &LocalApiError) -> Option<String> {
    let LocalApiError::TimedOut(reason) = error else {
        return None;
    };
    if reason.contains("/local-client/agent-context") {
        return Some(
            "Timed out loading Ottto context. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/costs") {
        return Some(
            "Timed out loading Ottto costs. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/sessions") {
        return Some(
            "Timed out loading Ottto sessions. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/recommendations") {
        return Some("Timed out loading Ottto recommendations. Retry in a moment.".to_string());
    }
    if reason.contains("/local-client/provider-impact") {
        return Some("Timed out loading Ottto provider-impact events. Retry in a moment or narrow the query.".to_string());
    }
    None
}

#[derive(Default)]
struct SetupScanReconcile {
    binding: Option<(String, String)>,
    failures: u32,
    next_due: Option<Instant>,
}
static SETUP_SCAN: std::sync::LazyLock<Mutex<SetupScanReconcile>> =
    std::sync::LazyLock::new(|| Mutex::new(SetupScanReconcile::default()));

fn setup_run_status_is_active(status: &str) -> bool {
    matches!(
        status,
        "scanning" | "waiting_for_companion" | "running_action"
    )
}

/// Background reconcile retry after Ottto refused the scan result with a 400:
/// the payload is rebuilt the same way each attempt, so the refusal repeats.
/// Still a retry, not a park: binding changes and daemon restarts reset it.
const SETUP_RECONCILE_REFUSED_RETRY: Duration = Duration::from_secs(24 * 60 * 60);

/// The observed deterministic refusal: a 400 from the scan-result route. Other
/// statuses and routes keep their own handling or the jittered backoff.
fn setup_reconcile_refused(error: &LocalApiError) -> bool {
    matches!(
        error,
        LocalApiError::Backend(details)
            if details.status == Some(400)
                && setup_reconcile_route(&details.endpoint) == "scan-result"
    )
}

/// The endpoint's last path segment (`scan-result`), or `other` when that
/// segment is not a plain route name, so no id is logged.
fn setup_reconcile_route(endpoint: &str) -> &str {
    let path = endpoint.split('?').next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.len() <= 40
        && last.starts_with(|character: char| character.is_ascii_lowercase())
        && last
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
    {
        last
    } else {
        "other"
    }
}

/// ` endpoint=<route> status=<n> code=<reason>` for a backend error; empty
/// otherwise.
fn setup_reconcile_backend_fields(error: &LocalApiError) -> String {
    let LocalApiError::Backend(details) = error else {
        return String::new();
    };
    let mut fields = format!(" endpoint={}", setup_reconcile_route(&details.endpoint));
    if let Some(status) = details.status {
        fields.push_str(&format!(" status={status}"));
    }
    if let Some(code) = &details.reason_code {
        fields.push_str(&format!(" code={code}"));
    }
    fields
}

fn setup_reconcile_status_reason(status: Option<&str>) -> String {
    format!(
        "status:{}",
        bounded_display_text(status.unwrap_or("unknown"), 64)
    )
}

pub(crate) fn reconcile_setup_scan_in_background(daemon: &LocalDaemon) {
    let Ok(mut state) = SETUP_SCAN.try_lock() else {
        return;
    };
    let store = FileConnectionStore::default();
    let Ok(Some(binding)) = store.load() else {
        return;
    };
    let key = (binding.api_base_url.clone(), binding.setup_run_id.clone());
    if state.binding.as_ref() != Some(&key) {
        *state = SetupScanReconcile {
            binding: Some(key),
            ..Default::default()
        };
    }
    if state.next_due.is_some_and(|due| Instant::now() < due) {
        return;
    }
    let mut network_attempted = false;
    let mut actions_processed = 0;
    let result = (|| {
        let settled_run = store.setup_scan_settled_run_id().or_state_poisoned()?;
        if settled_run.as_deref() == Some(binding.setup_run_id.as_str()) {
            return Ok((true, String::new()));
        }
        let device = FileDeviceStore::default()
            .load()
            .or_state_poisoned()?
            .ok_or(LocalApiError::SetupRunConnectionMissing)?;
        network_attempted = true;
        let refreshed = refresh_setup_run_token_via_device_secret(&binding.api_base_url, &binding)?;
        let run = refreshed
            .run
            .ok_or(LocalApiError::SetupRunConnectionMissing)?;
        let mut credentials = SetupRunCredentials {
            connection: refreshed.connection,
            setup_run_token: refreshed.setup_run_token,
        };
        let machine = daemon.machine_for_trusted_client()?;
        match run.status.as_str() {
            "scanning" => {
                let result = scan_setup_run_with_action_count(
                    daemon,
                    &binding.api_base_url,
                    &mut credentials,
                    &machine,
                    Vec::new(),
                    false,
                    Some(&device.device_id),
                    &mut actions_processed,
                )?;
                let status = result["status"].as_str();
                Ok((
                    !status.is_some_and(setup_run_status_is_active),
                    setup_reconcile_status_reason(status),
                ))
            }
            "waiting_for_companion" | "running_action" => {
                let (actions, last_run_status, idle) = process_setup_actions_with_status(
                    daemon,
                    &binding.api_base_url,
                    &mut credentials,
                    &machine,
                    &mut actions_processed,
                )?;
                request_snapshot_sync_after_setup_actions(daemon, &actions);
                Ok((
                    idle && matches!(
                        last_run_status.as_deref(),
                        Some("waiting_for_user" | "completed")
                    ),
                    setup_reconcile_status_reason(last_run_status.as_deref()),
                ))
            }
            _ => Ok((true, setup_reconcile_status_reason(Some(&run.status)))),
        }
    })();
    let mut refused = false;
    let mut backend_fields = String::new();
    let (mut settled, mut reason) = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            refused = setup_reconcile_refused(&error);
            backend_fields = setup_reconcile_backend_fields(&error);
            (
                terminal_refresh_rejection(&error).is_some(),
                format!("error:{}", setup_action_execution_error_detail(&error).0),
            )
        }
    };
    if settled {
        let _binding_lock = lock_setup_run_binding();
        if let Err(error) = store.settle_setup_scan(&binding).or_state_poisoned() {
            settled = false;
            reason = format!("error:{}", setup_action_execution_error_detail(&error).0);
        }
    }
    let attempt = state.failures.saturating_add(1);
    let next_in = if settled {
        state.failures = 0;
        state.next_due = None;
        None
    } else {
        state.failures = attempt;
        let delay = if refused {
            SETUP_RECONCILE_REFUSED_RETRY
        } else {
            crate::snapshot_sync::full_jitter_backoff(state.failures)
        };
        state.next_due = Some(Instant::now() + delay);
        Some(delay.as_secs())
    };
    if network_attempted {
        let outcome = if settled { "settled" } else { "retry" };
        let next_in = next_in
            .map(|seconds| format!(" next_in={seconds}s"))
            .unwrap_or_default();
        eprintln!(
            "setup reconcile attempt={attempt} outcome={outcome} reason={reason}{backend_fields} actions={actions_processed}{next_in}"
        );
    }
}

fn setup_run(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    sources: Vec<SourceKind>,
    claim_code: Option<String>,
    setup_run_id: Option<String>,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let _attempt = SETUP_SCAN.lock().unwrap_or_else(|p| p.into_inner());
    let status = status_for(daemon, authorization)?;
    crate::snapshot_sync::reset_relay_authorization_backoff();
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let mut setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok();
    let claim_code_provided = claim_code
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    let requested_setup_run_id = setup_run_id.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    if status.account.state == LocalAccountState::Connected
        && status.account.user.is_some()
        && !claim_code_provided
        && requested_setup_run_id.is_none()
    {
        let mut setup_run_id = connection
            .as_ref()
            .map(|binding| binding.setup_run_id.clone());
        if let Some(binding) = connection.as_ref() {
            // An explicit sign-in on a Mac that looks connected confirms the
            // binding once with the device credential. Only an authoritative
            // terminal refresh answer ends it: the existing local-only reset
            // keeps the prior device proof, and `NeedsUserAction` sends the
            // caller to a fresh browser claim. The ended run is never revived;
            // any other failure keeps the binding and the no-op answer.
            match refresh_setup_run_token_via_device_secret(&binding.api_base_url, binding) {
                Ok(refreshed) => setup_run_id = Some(refreshed.connection.setup_run_id),
                Err(error) if terminal_refresh_rejection(&error).is_some() => {
                    // Only the binding Ottto just answered for is cleared:
                    // `auth_reset` rechecks it under the identity lifecycle
                    // lock, so a binding attached meanwhile is left alone.
                    auth_reset(daemon, authorization, true, false, Some(binding))?;
                    return Err(LocalApiError::SetupRunConnectionMissing);
                }
                Err(_) => {}
            }
        }
        return Ok(json!({
            "status": "completed",
            "already_connected": true,
            "setup_run_id": setup_run_id,
            "claim_code_provided": false,
            "source_count": 0,
            "detected_sources": [],
            "next_question": null,
            "next_action": null,
            "setup_claim_url": null,
            "actions": [],
            "message": "This Mac is already connected. No new setup claim was created.",
        }));
    }

    if let Some(code) = claim_code
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let attached = attach_setup_run_by_claim_code(&api_base_url, code, &status.machine)?;
        let binding = LocalConnectionBinding {
            setup_run_id: attached.setup_run_id.clone(),
            setup_run_token_expires_at: attached.expires_at.clone(),
            machine_id: attached.run.machine_id.clone(),
            claim_code: Some(code.to_string()),
            api_base_url: api_base_url.clone(),
        };
        let _binding_lock = lock_setup_run_binding();
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .save(&attached.setup_run_token)
            .or_state_poisoned()?;
        FileConnectionStore::default()
            .save(&binding)
            .or_state_poisoned()?;
        daemon.bind_setup_run_for_authorized_client(binding.clone())?;
        connection = Some(binding);
        setup_run_token = Some(attached.setup_run_token);
    }

    let connection = connection.ok_or(LocalApiError::SetupRunConnectionMissing)?;
    if let Some(expected_setup_run_id) = requested_setup_run_id.as_ref() {
        if expected_setup_run_id != &connection.setup_run_id {
            return Err(LocalApiError::SetupRunConnectionMismatch);
        }
    }
    let setup_run_token = setup_run_token.ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = SetupRunCredentials {
        setup_run_token,
        connection,
    };

    scan_setup_run_with_action_count(
        daemon,
        &api_base_url,
        &mut credentials,
        &status.machine,
        sources,
        claim_code_provided,
        None,
        &mut 0,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "preserves scan inputs while reporting partial action progress on errors"
)]
fn scan_setup_run_with_action_count(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
    sources: Vec<SourceKind>,
    claim_code_provided: bool,
    expected_device: Option<&str>,
    actions_processed: &mut usize,
) -> Result<serde_json::Value, LocalApiError> {
    let scan = build_local_scan(machine, sources);
    if let Some(expected) = expected_device {
        let device = FileDeviceStore::default().load().or_state_poisoned()?;
        if device.as_ref().map(|d| d.device_id.as_str()) != Some(expected) {
            return Err(LocalApiError::SetupRunConnectionMismatch);
        }
    }
    let mut detail = match publish_scan_result(api_base_url, credentials, &scan) {
        Ok(detail) => detail,
        Err(error) if is_terminal_setup_run_scan_error(&error) => {
            clear_setup_run_connection_if_current(
                daemon,
                &credentials.connection,
                &credentials.setup_run_token,
            )?;
            return Err(LocalApiError::SetupRunConnectionMissing);
        }
        Err(error) => return Err(error),
    };
    let (action_results, _, _) = process_setup_actions_with_status(
        daemon,
        api_base_url,
        credentials,
        machine,
        actions_processed,
    )?;
    if let Some(last) = action_results.last() {
        if let Some(refreshed) = &last.detail {
            detail = refreshed.clone();
        }
    }
    request_snapshot_sync_after_setup_actions(daemon, &action_results);

    // Build the wire result with the same builder the setup-answer and
    // setup-action paths use. Previously this path inlined a byte-identical
    // `json!`, which let a field drift between the two builders; routing through
    // `setup_result_from_detail` guarantees a field threaded for one entry point
    // (e.g. `setup_claim_url`, the verify browser-approval URL) reaches them all.
    setup_result_from_detail(
        &credentials.connection,
        detail,
        claim_code_provided,
        action_results,
    )
}

fn clear_setup_run_connection_if_current(
    daemon: &LocalDaemon,
    failed_connection: &LocalConnectionBinding,
    failed_setup_run_token: &str,
) -> Result<(), LocalApiError> {
    let _binding_lock = lock_setup_run_binding();
    let store = FileConnectionStore::default();
    let persisted = store.load().or_state_poisoned()?;
    if persisted
        .as_ref()
        .is_some_and(|binding| setup_run_binding_matches(binding, failed_connection))
    {
        store.reset().or_state_poisoned()?;
        let current_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load();
        if current_token
            .as_deref()
            .is_ok_and(|token| token == failed_setup_run_token)
        {
            let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
        }
    }
    daemon.clear_setup_run_for_authorized_client_if_matches(
        &failed_connection.setup_run_id,
        &failed_connection.api_base_url,
    )?;
    Ok(())
}

fn setup_run_binding_matches(
    current: &LocalConnectionBinding,
    expected: &LocalConnectionBinding,
) -> bool {
    current.setup_run_id == expected.setup_run_id && current.api_base_url == expected.api_base_url
}

/// Under the identity lifecycle lock: `expected`, when given, must still be
/// the persisted and the daemon's bound setup run. Otherwise a reattach or a
/// completed sign-in replaced it and nothing of the replacement is touched.
fn require_setup_run_still_bound(
    daemon: &LocalDaemon,
    expected: Option<&LocalConnectionBinding>,
) -> Result<(), LocalApiError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let persisted = FileConnectionStore::default().load().or_state_poisoned()?;
    let bound = daemon.connection_for_authorized_client()?;
    if [persisted, bound].iter().all(|binding| {
        binding
            .as_ref()
            .is_some_and(|binding| setup_run_binding_matches(binding, expected))
    }) {
        Ok(())
    } else {
        Err(LocalApiError::SetupRunConnectionMissing)
    }
}

fn is_terminal_setup_run_scan_error(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if !details.endpoint.contains("/api/v1/setup-runs/")
        || !details.endpoint.contains("/local-client/scan-result")
    {
        return false;
    }
    if matches!(details.status, Some(404) | Some(410)) {
        return true;
    }
    // A setup-run token that the backend rejects cannot become valid by
    // polling harder. Clear the stale binding after the first authoritative
    // 401/403 so an unattended CLI cannot hammer an old run forever.
    matches!(details.status, Some(401) | Some(403))
}

fn set_source_marker(
    write: fn(&Path, crate::snapshots::SnapshotSource) -> anyhow::Result<()>,
    source: &SourceKind,
) -> Result<(), LocalApiError> {
    write(
        &default_support_dir(),
        crate::snapshot_sync::snapshot_source_of_kind(source),
    )
    .or_state_poisoned()
}

fn setup_answer(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    answer_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    // Before any connection or POST: collection stops even if the run is gone.
    if answer_type.trim() == "disable_source" {
        set_source_marker(crate::snapshot_sync::disable_snapshot_source, &source)?;
        daemon.clear_tracking_confirmation(&source)?;
    }
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = setup_run_token_for_connection(&api_base_url, &connection)?;
    let answer_type = match answer_type.trim() {
        "skip_source" | "disable_source" => answer_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_answer only supports skip_source and disable_source".to_string(),
            ))
        }
    };
    let detail = save_setup_answer(&api_base_url, &mut credentials, &source, &answer_type)?;
    // `disable_source` already revoked with its pause marker.
    if source == SourceKind::ClaudeCode && answer_type == "skip_source" {
        crate::otlp_relay::legacy::revoke_now();
    }
    setup_result_from_detail(&credentials.connection, detail, false, Vec::new())
}

/// The Companion's Pause/Resume of one source on this Mac, saved to the
/// account through the relay. Nothing is deleted and nothing is re-sent.
fn source_collection(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    enabled: bool,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let snapshot_source = crate::snapshot_sync::snapshot_source_of_kind(&source);
    let reply = save_source_collection(&source, enabled, |body| {
        // The pause marker is already durable before any observation write.
        if !enabled {
            daemon
                .clear_tracking_confirmation(&source)
                .map_err(|_| anyhow::anyhow!("tracking state unavailable"))?;
        }
        let (device, secret) = crate::snapshot_client::load_snapshot_device_credentials()?;
        let client = crate::snapshot_client::SnapshotApiClient::new(
            crate::snapshot_sync::snapshot_api_base_url()?,
        );
        let token = client.issue_relay_token(&device, &secret, snapshot_source)?;
        client.upload_source_control(&token, body)
    })?;
    if enabled {
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(reply)
}

/// Pause stops collection before any network and stays paused if the save
/// fails. Resume writes nothing until the account accepts it, then applies
/// the reply exactly as a heartbeat's.
fn save_source_collection(
    source: &SourceKind,
    enabled: bool,
    post: impl FnOnce(&serde_json::Value) -> anyhow::Result<serde_json::Value>,
) -> Result<serde_json::Value, LocalApiError> {
    if !enabled {
        // Also revokes Claude's legacy relay.
        set_source_marker(crate::snapshot_sync::disable_snapshot_source, source)?;
    }
    let support_dir = default_support_dir();
    let server_saved = match post(&json!({"source": source, "enabled": enabled})) {
        Ok(reply) => {
            crate::snapshot_sync::apply_source_control(&support_dir, &reply);
            true
        }
        Err(error) if enabled => {
            return Err(LocalApiError::LocalOperationFailed(format!(
                "resume was not saved: {}",
                crate::snapshot_sync::safe_error(&error)
            )))
        }
        Err(error) => {
            eprintln!(
                "source pause not saved: {}",
                crate::snapshot_sync::safe_error(&error)
            );
            false
        }
    };
    let paused = crate::snapshot_sync::source_paused(
        &support_dir,
        crate::snapshot_sync::snapshot_source_of_kind(source),
    );
    Ok(json!({"source": source, "source_paused": paused, "server_saved": server_saved}))
}

fn setup_action(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    action_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let status = status_for(daemon, authorization)?;
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = setup_run_token_for_connection(&api_base_url, &connection)?;
    let action_type = match action_type.trim() {
        "install_source" | "verify_source" => action_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_action only supports install_source and verify_source".to_string(),
            ))
        }
    };
    let queued = queue_setup_action(&api_base_url, &mut credentials, &source, &action_type)?;
    if action_type == "install_source" {
        set_source_marker(crate::snapshot_sync::reconnect_snapshot_source, &source)?;
    }
    let action_results =
        process_setup_actions(daemon, &api_base_url, &mut credentials, &status.machine)?;
    request_snapshot_sync_after_setup_actions(daemon, &action_results);
    let detail = action_results
        .last()
        .and_then(|result| result.detail.clone())
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "queued setup action did not return a setup-run detail".to_string(),
            )
        })?;
    let mut result =
        setup_result_from_detail(&credentials.connection, detail, false, action_results)?;
    // Lets the client bind a completion to the action this request queued.
    result["queued_action_id"] = json!(queued.id);
    Ok(result)
}

#[derive(Debug, Deserialize)]
struct SetupRunAttachResponse {
    setup_run_id: String,
    setup_run_token: String,
    expires_at: String,
    run: SetupRunApiRun,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SetupRunDetailApiResponse {
    run: SetupRunApiRun,
    #[serde(default)]
    sources: Vec<SetupRunSourceApiResponse>,
    next_action: Option<SetupRunActionApiResponse>,
    next_question: Option<serde_json::Value>,
    // Web claim URL the app opens when a setup run waits on browser approval
    // (e.g. a verify_source that found no fresh telemetry transitions to
    // waiting_for_user). Surfaced to the Swift app so it can open the re-claim
    // tab instead of leaving the user stuck on "waiting for approval".
    #[serde(default)]
    setup_claim_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SetupRunApiRun {
    id: String,
    status: String,
    machine_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SetupRunSourceApiResponse {
    source: String,
    detected: bool,
    readiness_percent: u64,
    state: String,
    #[serde(default)]
    missing_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_import_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    live_telemetry_required: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SetupRunActionApiResponse {
    id: String,
    action_type: String,
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct SetupScanPayload {
    machine: BTreeMap<String, serde_json::Value>,
    companion: BTreeMap<String, serde_json::Value>,
    relay_runtime: BTreeMap<String, serde_json::Value>,
    service: BTreeMap<String, serde_json::Value>,
    sources: Vec<SetupScanSource>,
    missing_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SetupScanSource {
    source: &'static str,
    /// When this scan observed the source. The backend reads it before the
    /// status row's own `captured_at`, which may be an earlier cached reading.
    captured_at: String,
    detected: bool,
    installed: bool,
    telemetry_installed: bool,
    local_health: &'static str,
    missing_fields: Vec<String>,
    attribution_guess: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_status: Option<AgentStatusSnapshot>,
    /// Redacted preview of the on-disk Ottto-managed fence region, so the
    /// dashboard's "View managed config" modal shows what is really
    /// configured on this machine instead of a canned template.
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_import_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_telemetry_required: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SetupActionResult {
    action_id: String,
    action_type: String,
    source: Option<String>,
    status: String,
    detail: Option<SetupRunDetailApiResponse>,
    /// The result a verify_source action computed; it appears only in the
    /// response of the call that ran the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<SourceVerificationResult>,
}

fn request_snapshot_sync_after_setup_actions(
    daemon: &LocalDaemon,
    action_results: &[SetupActionResult],
) {
    let registered_device = action_results.iter().any(|result| {
        result.action_type == "install_source"
            && result.status == "succeeded"
            && result
                .source
                .as_deref()
                .and_then(source_from_slug)
                .is_some_and(|source| source_requires_device_registration(&source))
    });
    if registered_device {
        request_snapshot_sync_after_device_registration(daemon);
    }
}

fn setup_result_from_detail(
    connection: &LocalConnectionBinding,
    detail: SetupRunDetailApiResponse,
    claim_code_provided: bool,
    action_results: Vec<SetupActionResult>,
) -> Result<serde_json::Value, LocalApiError> {
    let source_count = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .count();
    let detected_sources = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .map(|source| {
            let mut summary = json!({
                "source": source.source,
                "state": source.state,
                "readiness_percent": source.readiness_percent,
                "missing_fields": source.missing_fields,
            });
            if let Some(ready) = source.local_import_ready {
                summary["local_import_ready"] = json!(ready);
            }
            if let Some(required) = source.live_telemetry_required {
                summary["live_telemetry_required"] = json!(required);
            }
            summary
        })
        .collect::<Vec<_>>();

    let local_claim: Option<StoredHistoryBrowserClaim> =
        match history_load(history_stores().browser.as_ref()) {
            Ok(claim) => claim,
            Err(_) if !local_history_recovery_expected()? => None,
            Err(error) => return Err(error),
        };
    let local_claim_url = local_claim
        .filter(|claim| {
            claim.setup_run_id.as_deref() == Some(connection.setup_run_id.as_str())
                && claim.api_base_url == connection.api_base_url
                && !auth_claim_is_expired(&claim.claim.expires_at)
        })
        .map(|claim| {
            append_nonce_to_claim_url(&claim.claim.claim_url, claim.nonce.expose_secret())
        });
    Ok(json!({
        "status": detail.run.status,
        "setup_run_id": connection.setup_run_id,
        "claim_code_provided": claim_code_provided,
        "source_count": source_count,
        "detected_sources": detected_sources,
        "next_question": detail.next_question,
        "next_action": detail.next_action,
        "setup_claim_url": local_claim_url.or(detail.setup_claim_url),
        "actions": action_results,
    }))
}

fn attach_setup_run_by_claim_code(
    api_base_url: &str,
    claim_code: &str,
    machine: &MachineIdentity,
) -> Result<SetupRunAttachResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/setup-claims/{claim_code}/attach"),
    );
    let body = setup_run_attach_body(machine);
    backend_post_json(&url, &body, &[])
}

fn setup_run_attach_body(machine: &MachineIdentity) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

#[derive(Debug, Deserialize)]
struct SetupRunRefreshResponse {
    run: Option<SetupRunApiRun>,
    setup_run_id: Option<String>,
    setup_run_token: String,
    expires_at: String,
}

#[derive(Debug, Clone)]
struct RefreshedSetupRunToken {
    run: Option<SetupRunApiRun>,
    setup_run_token: String,
    connection: LocalConnectionBinding,
}

#[derive(Debug, Clone)]
struct SetupRunCredentials {
    setup_run_token: String,
    connection: LocalConnectionBinding,
}

#[derive(Debug, Deserialize)]
struct SetupRunDisconnectResponse {
    setup_run_id: String,
    #[allow(dead_code, reason = "part of the server response shape; not read")]
    run_status: String,
    #[allow(dead_code, reason = "part of the server response shape; not read")]
    client_disconnected: bool,
    disconnected_at: String,
    /// True only when the server authenticated the release proof and revoked
    /// this Mac's device registration. Older servers omit the field.
    #[serde(default)]
    device_released: bool,
    #[serde(default)]
    revocation_receipt: Option<SecretString>,
}

/// This Mac's active relay-device id and secret, presented on a cloud
/// disconnect so the server can release the device registration. Read before
/// any local deletion. Secret; redacted from `Debug` and never logged.
struct DeviceReleaseProof {
    device_id: String,
    device_secret: String,
}

impl std::fmt::Debug for DeviceReleaseProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceReleaseProof")
            .field("device_id", &self.device_id)
            .field("device_secret", &"[redacted]")
            .finish()
    }
}

/// Load the active device id and secret together. The server rejects one
/// without the other, so a missing or unreadable half yields no proof.
fn load_device_release_proof() -> Option<DeviceReleaseProof> {
    let device = FileDeviceStore::default().load().ok().flatten()?;
    let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .ok()?;
    device_release_proof(device.device_id, device_secret)
}

fn device_release_proof(device_id: String, device_secret: String) -> Option<DeviceReleaseProof> {
    if device_id.trim().is_empty() || device_secret.is_empty() {
        return None;
    }
    Some(DeviceReleaseProof {
        device_id,
        device_secret,
    })
}

#[derive(Debug, Deserialize)]
struct DeviceSelfReleaseResponse {
    device_released: bool,
    #[serde(default)]
    revocation_receipt: Option<SecretString>,
}

/// Ask Ottto to release this Mac's registration with the device's own
/// secret, for a cloud logout whose setup run has already ended. Needs no
/// setup run. True only on a 200 that says `device_released: true`; any other
/// status (older servers answer 404 or 405), an unparsable body, or a
/// transport failure is not a release.
fn release_device_without_setup_run(api_base_url: &str, release: &DeviceReleaseProof) -> bool {
    // SECURITY: the request carries the long-lived device secret. Gate the
    // base through the trusted-base validator, only put an id made of plain
    // path characters into the URL, and never follow a redirect: ureq would
    // forward the custom secret header to the redirect target, so a 3xx is
    // an unconfirmed release.
    let Ok(api_base_url) = validated_api_base_url(Some(api_base_url)) else {
        return false;
    };
    if !release
        .device_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    let url = api_url_with_base(
        &api_base_url,
        &format!("/api/v1/telemetry/devices/{}/release", release.device_id),
    );
    let Ok(_history_lock) = lock_history_recovery() else {
        return false;
    };
    let stores = history_stores();
    if stage_local_release(&api_base_url, release, &stores, history_now()).is_err() {
        return false;
    }
    crate::retry_tls::credential_agent()
        .post(&url)
        .set("Accept", "application/json")
        .set("X-Ottto-Device-Secret", &release.device_secret)
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_bytes(&[])
        .ok()
        .filter(|response| response.status() == 200)
        .and_then(|response| response.into_json::<DeviceSelfReleaseResponse>().ok())
        .is_some_and(|response| {
            remember_revocation_receipt(
                response.device_released,
                response.revocation_receipt,
                &stores,
                history_now(),
            );
            response.device_released
        })
}

fn setup_run_disconnect_body(release: Option<&DeviceReleaseProof>) -> serde_json::Value {
    match release {
        Some(release) => json!({
            "reason": "logout",
            "release_device_id": release.device_id,
            "release_device_secret": release.device_secret,
        }),
        None => json!({ "reason": "logout" }),
    }
}

/// Mint a fresh `setup_run_token` for the current run using the daemon's
/// long-lived device secret. The token is persisted to Keychain and the
/// connection's expiry timestamp is updated. Returns the new token so the
/// caller can immediately retry whatever 401'd.
fn refresh_setup_run_token_via_device_secret(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
) -> Result<RefreshedSetupRunToken, LocalApiError> {
    // SECURITY: this path POSTs the long-lived relay device_secret to the
    // backend. `connection.api_base_url` is deserialized from on-disk
    // connection.json (see `LocalConnectionBinding`) and is not trusted — a
    // co-resident attacker who tampers that file could otherwise exfiltrate the
    // secret to their own host. Gate the base through the same trusted-base
    // validator every other secret-bearing egress in this file uses, BEFORE
    // touching the device secret. Fail closed: both callers map an `Err` to a
    // reconnect/backend error, so an untrusted base never releases the secret.
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    crate::snapshot_client::ensure_no_incomplete_device_credential_promotion()
        .map_err(|_| LocalApiError::IdentityMutationInProgress)?;
    let device = FileDeviceStore::default()
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .map_err(|_| LocalApiError::SetupRunConnectionMissing)?;

    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/refresh",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "device_id": device.device_id,
        "device_secret": device_secret,
    });
    let response: SetupRunRefreshResponse = backend_post_json(&url, &body, &[])?;
    let mut refreshed = connection.clone();
    if let Some(setup_run_id) = response
        .setup_run_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        refreshed.setup_run_id = setup_run_id.to_string();
    }
    refreshed.setup_run_token_expires_at = response.expires_at.clone();
    let committed = {
        let _binding_lock = lock_setup_run_binding();
        commit_refreshed_setup_run_binding_locked(
            connection,
            &refreshed,
            &response.setup_run_token,
            &FileConnectionStore::default(),
            &KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
        )?
    };
    Ok(RefreshedSetupRunToken {
        run: response.run,
        setup_run_token: response.setup_run_token,
        connection: committed,
    })
}

/// The connection half of a refresh commit; a seam so storage failures can be
/// exercised without touching the real support directory.
trait SetupRunConnectionStore {
    fn load_connection(&self) -> anyhow::Result<Option<LocalConnectionBinding>>;
    fn save_connection(&self, connection: &LocalConnectionBinding) -> anyhow::Result<()>;
}

impl SetupRunConnectionStore for FileConnectionStore {
    fn load_connection(&self) -> anyhow::Result<Option<LocalConnectionBinding>> {
        self.load()
    }

    fn save_connection(&self, connection: &LocalConnectionBinding) -> anyhow::Result<()> {
        self.save(connection)
    }
}

/// Persist a refreshed setup-run token and connection only if the persisted
/// binding is still the one this refresh belongs to, and return the binding
/// written. The caller holds the setup-run binding lock, which every writer
/// of these two stores (claim, switch, setup attach, terminal clear, logout
/// reset) also holds, so this compare-and-swap cannot interleave with a
/// reconnect or logout.
///
/// The persisted binding may name the refresh's own run, or the run the
/// backend just minted for (an earlier refresh rebinding to the latest run
/// persists that run while the in-memory binding keeps the old id). Only the
/// run id and token expiry change; the persisted record's other fields are
/// kept. Anything else means the binding was replaced or removed while the
/// refresh was in flight; the minted token is dropped and nothing is written.
/// If the connection write fails after the token write, the prior token is
/// put back (or the new one removed when none could be read), so the stores
/// keep the prior binding. The two stores are not written atomically: if that
/// rollback also fails, the new token stays beside the prior connection until
/// the next refresh.
fn commit_refreshed_setup_run_binding_locked(
    expected: &LocalConnectionBinding,
    refreshed: &LocalConnectionBinding,
    setup_run_token: &str,
    connections: &impl SetupRunConnectionStore,
    tokens: &impl ControlTokenStore,
) -> Result<LocalConnectionBinding, LocalApiError> {
    let persisted = connections
        .load_connection()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    if !setup_run_binding_matches(&persisted, expected)
        && !setup_run_binding_matches(&persisted, refreshed)
    {
        return Err(LocalApiError::SetupRunConnectionMismatch);
    }
    let committed = LocalConnectionBinding {
        setup_run_id: refreshed.setup_run_id.clone(),
        setup_run_token_expires_at: refreshed.setup_run_token_expires_at.clone(),
        ..persisted
    };
    let prior_token = tokens.load().ok();
    tokens.save(setup_run_token).or_state_poisoned()?;
    if connections.save_connection(&committed).is_err() {
        let _ = match prior_token {
            Some(token) => tokens.save(&token),
            None => tokens.delete(),
        };
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(committed)
}

pub(crate) fn refresh_setup_run_token_for_persisted_connection() -> Result<(), LocalApiError> {
    let connection = FileConnectionStore::default()
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    refresh_setup_run_token_via_device_secret(&connection.api_base_url, &connection).map(|_| ())
}

fn setup_run_token_for_connection(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
) -> Result<SetupRunCredentials, LocalApiError> {
    crate::snapshot_client::ensure_no_incomplete_device_credential_promotion()
        .map_err(|_| LocalApiError::IdentityMutationInProgress)?;
    match KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() {
        Ok(token) => Ok(SetupRunCredentials {
            setup_run_token: token,
            connection: connection.clone(),
        }),
        Err(_) => {
            refresh_setup_run_token_via_device_secret(api_base_url, connection).map(|refreshed| {
                SetupRunCredentials {
                    setup_run_token: refreshed.setup_run_token,
                    connection: refreshed.connection,
                }
            })
        }
    }
}

fn setup_run_request_with_refresh_mut<T>(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    request: impl Fn(&LocalConnectionBinding, &str) -> Result<T, LocalApiError>,
) -> Result<T, LocalApiError> {
    match request(&credentials.connection, &credentials.setup_run_token) {
        Ok(response) => Ok(response),
        Err(original) if is_setup_run_token_auth_error(&original) => {
            match refresh_setup_run_token_via_device_secret(api_base_url, &credentials.connection) {
                Ok(refreshed) => {
                    *credentials = SetupRunCredentials {
                        setup_run_token: refreshed.setup_run_token,
                        connection: refreshed.connection,
                    };
                    request(&credentials.connection, &credentials.setup_run_token)
                }
                Err(LocalApiError::SetupRunConnectionMissing) => Err(original),
                Err(other) => Err(other),
            }
        }
        Err(other) => Err(other),
    }
}

fn is_setup_run_token_auth_error(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status == Some(401) {
        return true;
    }
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let body = body.to_ascii_lowercase();
    body.contains("setup run companion token expired")
        || body.contains("setup run companion token is invalid")
}

/// Agent reads (context, costs, sessions, recommendations, provider impact)
/// refresh the setup-run token and retry once only on a backend 401. Unlike
/// `setup_run_request_with_refresh_mut`, a token-expiry body under another
/// status does not refresh. `read_url` builds the URL for whichever connection
/// is current, so the retry targets the refreshed run.
fn agent_read_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    read_url: impl Fn(&str, &LocalConnectionBinding) -> String,
) -> Result<serde_json::Value, LocalApiError> {
    let read = |connection: &LocalConnectionBinding,
                setup_run_token: &str|
     -> Result<serde_json::Value, LocalApiError> {
        let url = read_url(api_base_url, connection);
        backend_get_agent_read_json(&url, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
    };
    match read(connection, setup_run_token) {
        Ok(value) => Ok(value),
        Err(error) => {
            if matches!(&error, LocalApiError::Backend(details) if details.status == Some(401)) {
                let refreshed =
                    refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
                return read(&refreshed.connection, &refreshed.setup_run_token);
            }
            Err(error)
        }
    }
}

fn disconnect_setup_run_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    release: Option<&DeviceReleaseProof>,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    match disconnect_setup_run_local_client(api_base_url, connection, setup_run_token, release) {
        Ok(response) => Ok(response),
        Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
            let refreshed = refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
            disconnect_setup_run_local_client(
                api_base_url,
                &refreshed.connection,
                &refreshed.setup_run_token,
                release,
            )
        }
        Err(other) => Err(other),
    }
}

fn disconnect_setup_run_local_client(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    release: Option<&DeviceReleaseProof>,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    // SECURITY: a release proof carries the long-lived device secret. Gate the
    // base through the trusted-base validator here as well, so no caller can
    // send the secret to a base read from tampered on-disk state.
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/disconnect",
            connection.setup_run_id
        ),
    );
    let _history_lock = lock_history_recovery()?;
    let stores = history_stores();
    if let Some(release) = release {
        stage_local_release(&api_base_url, release, &stores, history_now())?;
    }
    let body = setup_run_disconnect_body(release);
    let mut response: SetupRunDisconnectResponse =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    remember_revocation_receipt(
        response.device_released,
        response.revocation_receipt.take(),
        &stores,
        history_now(),
    );
    Ok(response)
}

/// Call `wait_for_setup_run_verification_with_base` with one transparent
/// retry on 401: refresh the companion token via device-secret auth, then
/// re-issue the verify call with the new token. Other errors pass through.
fn wait_for_verification_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    wait_for_setup_run_verification_with_refresh_mut(
        api_base_url,
        credentials,
        source,
        smoke_after,
        None,
    )
}

fn wait_for_setup_run_verification_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    wait_for_setup_run_verification_with_refresh_mut_timeout(
        api_base_url,
        credentials,
        source,
        smoke_after,
        filters,
        SetupVerificationTimeouts {
            wait: VERIFICATION_WAIT_TIMEOUT,
            request: SETUP_VERIFICATION_HTTP_TIMEOUT,
        },
    )
}

fn wait_for_setup_run_verification_with_refresh_mut_timeout(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    timeouts: SetupVerificationTimeouts,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        wait_for_setup_run_verification_with_base_timeout(
            api_base_url,
            active,
            token,
            source,
            smoke_after,
            filters,
            timeouts,
        )
    })
}

fn emit_setup_run_fast_verification_marker_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    flow: &str,
) -> Result<String, LocalApiError> {
    let marker_id = format!("m3-{}-{}", source_slug(source), current_millis());
    let body = json!({
        "source": source_slug(source),
        "marker_id": marker_id,
        "details": {
            "flow": flow,
            "client": OTTTO_CLIENT_NAME,
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/verification-marker",
                active.setup_run_id
            ),
        );
        let _: serde_json::Value = backend_post_json_with_timeout(
            &url,
            &body,
            &[("X-Ottto-Setup-Run-Token", token)],
            SETUP_VERIFICATION_MARKER_HTTP_TIMEOUT,
        )?;
        Ok(marker_id.clone())
    })
}

fn publish_scan_result(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    scan: &SetupScanPayload,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/scan-result",
                active.setup_run_id
            ),
        );
        backend_post_json_with_timeout(
            &url,
            scan,
            &[("X-Ottto-Setup-Run-Token", token)],
            SETUP_SCAN_RESULT_HTTP_TIMEOUT,
        )
    })
}

fn save_setup_answer(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    answer_type: &str,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let body = json!({
        "source": source_slug(source),
        "answer_type": answer_type,
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/answers",
                active.setup_run_id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn queue_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    action_type: &str,
) -> Result<SetupRunActionApiResponse, LocalApiError> {
    let body = json!({
        "source": source_slug(source),
        "action_type": action_type,
        "requested_by": "companion_app",
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/actions",
                active.setup_run_id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn process_setup_actions(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
) -> Result<Vec<SetupActionResult>, LocalApiError> {
    process_setup_actions_with_status(daemon, api_base_url, credentials, machine, &mut 0)
        .map(|(results, _, _)| results)
}

fn process_setup_actions_with_status(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
    actions_processed: &mut usize,
) -> Result<(Vec<SetupActionResult>, Option<String>, bool), LocalApiError> {
    let mut results = Vec::new();
    let mut last_run_status = None;
    for _ in 0..8 {
        let next = get_next_setup_action(api_base_url, credentials)?;
        last_run_status = next.run_status;
        let Some(action) = next.action else {
            return Ok((results, last_run_status, true));
        };
        let source_slug = action.source.clone();
        let source = source_slug.as_deref().and_then(source_from_slug);
        if source.as_ref().is_some_and(setup_source_paused) {
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                "cancelled",
                "source_paused",
                json!({ "reason": "source_paused" }),
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status: "cancelled".to_string(),
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        if let Err(error) = record_setup_action_event(
            api_base_url,
            credentials,
            &action,
            SetupActionEvent {
                event_type: "action.started",
                status: "running",
                message: "Local daemon started setup action",
                metadata: None,
            },
        ) {
            let (status, message, result) =
                setup_action_execution_error_result(&action, source.as_ref(), &error);
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                &status,
                &message,
                result,
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status,
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        let action_outcome = match action.action_type.as_str() {
            "install_source" => {
                run_install_source_action(daemon, api_base_url, credentials, &action, machine)
                    .map(|(status, message, result)| (status, message, result, None))
            }
            "verify_source" => {
                if let Some(source) = source.clone() {
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::Setup,
                        || {
                            run_verify_source_action(
                                daemon,
                                api_base_url,
                                credentials,
                                &action,
                                source,
                            )
                        },
                    )
                } else {
                    Ok((
                        "failed".to_string(),
                        "Setup action source was missing".to_string(),
                        json!({
                            "verified": false,
                            "error_code": "source_missing",
                            "error_message": "Setup action source was missing",
                        }),
                        None,
                    ))
                }
            }
            _ => Ok((
                "failed".to_string(),
                format!("Unsupported setup action {}", action.action_type),
                json!({
                    "error_code": "unsupported_action",
                    "error_message": format!("Unsupported setup action {}", action.action_type),
                }),
                None,
            )),
        };
        let (status, message, result, verification) = match action_outcome {
            Ok(outcome) => outcome,
            Err(error) if registration_history_choice_required(&error) => {
                reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
                results.push(SetupActionResult {
                    action_id: action.id,
                    action_type: action.action_type,
                    source: source_slug,
                    status: "running".to_string(),
                    detail: None,
                    verification: None,
                });
                *actions_processed += 1;
                break;
            }
            Err(error) => {
                let (status, message, result) =
                    setup_action_execution_error_result(&action, source.as_ref(), &error);
                (status, message, result, None)
            }
        };
        let detail = complete_setup_action(
            api_base_url,
            credentials,
            &action,
            &status,
            &message,
            result,
        )?;
        results.push(SetupActionResult {
            action_id: action.id,
            action_type: action.action_type,
            source: source_slug,
            status,
            detail: Some(detail),
            verification,
        });
        *actions_processed += 1;
    }
    // A response containing an action cannot establish that the run is idle.
    Ok((results, last_run_status, false))
}

fn setup_action_execution_error_result(
    action: &SetupRunActionApiResponse,
    source: Option<&SourceKind>,
    error: &LocalApiError,
) -> (String, String, serde_json::Value) {
    let (error_code, error_message) = setup_action_execution_error_detail(error);
    let mut result = json!({
        "action_type": action.action_type.as_str(),
        "source": action.source.as_deref().or_else(|| source.map(source_slug)),
        "verified": false,
        "error_code": error_code,
        "error_message": error_message,
    });
    if source == Some(&SourceKind::Codex) {
        result["live_telemetry_required"] = json!(false);
        result["local_import_ready"] = json!(false);
    }
    ("failed".to_string(), error_message, result)
}

fn setup_action_execution_error_detail(error: &LocalApiError) -> (&'static str, String) {
    match error {
        LocalApiError::SetupRunConnectionMissing => (
            "setup_run_connection_missing",
            "This Mac needs an active Ottto setup flow. Start setup from the Ottto app, then retry.".to_string(),
        ),
        LocalApiError::SetupRunConnectionMismatch => (
            "setup_run_connection_mismatch",
            "This setup action belongs to a different Ottto setup run. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::TimedOut(_) => (
            "setup_action_timed_out",
            "Setup action timed out while waiting for Ottto. Check your network and retry setup.".to_string(),
        ),
        LocalApiError::NetworkUnavailable => (
            "network_unavailable",
            "Network is unavailable while running setup. Check your connection and retry setup.".to_string(),
        ),
        LocalApiError::Backend(details) => {
            if details.status == Some(401) || details.status == Some(403) {
                return (
                    "setup_action_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                );
            }
            if details.status == Some(404) {
                return (
                    "setup_run_missing",
                    "Ottto could not find this setup run. Start setup again from the Ottto app.".to_string(),
                );
            }
            match details.kind {
                BackendErrorKind::Unreachable => (
                    "backend_unreachable",
                    "Could not reach Ottto while running setup. Check your network and retry setup.".to_string(),
                ),
                BackendErrorKind::Unavailable => (
                    "backend_unavailable",
                    "Ottto was unavailable while running setup. Retry setup in a moment.".to_string(),
                ),
                BackendErrorKind::Rejected => (
                    "backend_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                ),
                BackendErrorKind::ResponseUnexpected => (
                    "backend_response_unexpected",
                    "Ottto returned an unexpected setup response. Retry setup in a moment.".to_string(),
                ),
            }
        }
        LocalApiError::LocalOperationFailed(_) => (
            "local_operation_failed",
            "A local setup step failed. Open Diagnostics or retry setup.".to_string(),
        ),
        LocalApiError::StatePoisoned => (
            "local_state_unavailable",
            "Local Ottto setup state is unavailable. Restart Ottto and retry setup.".to_string(),
        ),
        LocalApiError::RepairLocked => (
            "repair_locked",
            "Another Ottto repair is already running. Wait for it to finish, then retry setup.".to_string(),
        ),
        LocalApiError::ManualFenceReviewRequired => (
            "manual_fence_review_required",
            "Setup needs manual config review before it can continue.".to_string(),
        ),
        LocalApiError::CloudSessionCleanupRequired => (
            "cloud_session_cleanup_required",
            error.to_string(),
        ),
        LocalApiError::IdentityMutationInProgress => (
            "identity_mutation_in_progress",
            error.to_string(),
        ),
        LocalApiError::InvalidRequest(_) | LocalApiError::RetiredCommand(_) => (
            "invalid_setup_action",
            "Ottto could not run this setup action. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::Unauthorized
        | LocalApiError::LocalClientNotTrusted
        | LocalApiError::AccountResetRequired
        | LocalApiError::AccountSwitchCandidate { .. }
        | LocalApiError::EmptyControlToken
        | LocalApiError::NoPendingAuthClaim
        | LocalApiError::AuthClaimMismatch => (
            "setup_action_failed",
            "Ottto could not finish this setup action. Start setup from the Ottto app, then retry.".to_string(),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct SetupRunNextActionResponse {
    #[serde(default)]
    run_status: Option<String>,
    action: Option<SetupRunActionApiResponse>,
}

fn get_next_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
) -> Result<SetupRunNextActionResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/next-action",
                active.setup_run_id
            ),
        );
        heartbeat_setup_run(api_base_url, active, token, "polling_next_action")?;
        backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn heartbeat_setup_run(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    status: &str,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/heartbeat",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "status": status,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            // Report the live running version so the Apps surface can read it
            // from the heartbeat (the source of truth) instead of inferring it
            // from setup-scan / telemetry-device snapshots.
            "local_platform_version": compiled_release_version(),
        },
    });
    let _: serde_json::Value =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    Ok(())
}

fn record_setup_action_event(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    event: SetupActionEvent<'_>,
) -> Result<(), LocalApiError> {
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "source": action.source,
        "metadata": event.metadata,
    });
    let _: serde_json::Value =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/actions/{}/events",
                    active.setup_run_id, action.id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    Ok(())
}

struct SetupActionEvent<'a> {
    event_type: &'a str,
    status: &'a str,
    message: &'a str,
    metadata: Option<serde_json::Value>,
}

fn complete_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    status: &str,
    message: &str,
    result: serde_json::Value,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let body = json!({
        "status": status,
        "message": message,
        "result": result,
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/actions/{}/complete",
                active.setup_run_id, action.id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn run_install_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    machine: &MachineIdentity,
) -> Result<(String, String, serde_json::Value), LocalApiError> {
    let Some(source) = action.source.as_deref() else {
        return Ok((
            "failed".to_string(),
            "Install source action did not include a source".to_string(),
            json!({
            "error_code": "source_missing",
            "error_message": "Install source action did not include a source",
            }),
        ));
    };
    let body = json!({
        "action_id": action.id,
        "source": source,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "architecture": machine.arch,
        "client_name": OTTTO_CLIENT_NAME,
        "setup_origin": "companion_setup_run",
    });
    let install_session: InstallSessionApiResponse =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/install-sessions",
                    active.setup_run_id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    let Some(source_kind) = source_from_slug(source) else {
        return Ok((
            "failed".to_string(),
            format!("Unsupported local source: {source}"),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "error_code": "source_unsupported",
                "error_message": format!("Unsupported local source: {source}"),
            }),
        ));
    };
    if !source_requires_device_registration(&source_kind) {
        return Ok((
            "succeeded".to_string(),
            "Local source setup prepared".to_string(),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "local_changes": "prepared",
            }),
        ));
    }

    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.started",
            status: "running",
            message: &format!(
                "Registering local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: None,
        },
    )?;
    // Resolve any previously confirmed-but-not-promoted generation before
    // beginning another identity mutation. Uncertain pending state fails
    // closed; it is never overwritten by a modern-to-legacy fallback.
    recover_pending_device_credential_at_startup()?;
    if FileAccountStore::default()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account))
    {
        reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
        return Err(LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/api/v1/telemetry/devices/registration-preparations".to_string(),
            status: Some(400),
            body_excerpt: Some("Setup claim session is pending".to_string()),
            reason_code: Some("history_choice_required".to_string()),
        }));
    }
    // Preparation is server-side non-authoritative. Hold a panic-safe local
    // reservation across prepare, local durable staging, confirm, and exact
    // promotion while leaving the lifecycle mutex free during network I/O.
    let identity_reservation = reserve_identity_mutation()?;
    let (prepared, _prior, request_authority) =
        prepare_telemetry_device_registration(api_base_url, &install_session, machine)?;
    let pending = pending_device_credential_from_preparation(
        api_base_url,
        &prepared,
        true,
        None,
        request_authority,
    )?;
    stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let pending = mark_pending_device_credential_guards_passed(
        &pending,
        &FilePendingDeviceCredentialStore::default(),
    )?;
    let confirmed = confirm_device_credential_preparation(&pending, &prepared.candidate_secret)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending = mark_pending_device_credential_confirmed(
        &pending,
        &confirmed.confirmed_at,
        &pending_store,
    )?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        promote_pending_device_credential_with_stores(
            &pending,
            &prepared.candidate_secret,
            &pending_store,
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    let device = pending.device;
    let device_id = device.device_id.clone();
    drop(identity_reservation);
    // The local device binding + secret are now durable. Wake the snapshot
    // collector before any backend completion/event call that can transiently
    // fail after registration has already succeeded.
    request_snapshot_sync_after_device_registration(daemon);
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.completed",
            status: "succeeded",
            message: &format!(
                "Registered local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: Some(&device_id),
        },
    )?;
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "secure_store.saved",
            status: "succeeded",
            message: "Saved local relay device secret",
            metadata: Some(json!({"source": source, "store": "keychain"})),
            device_id: Some(&device_id),
        },
    )?;

    let codex_cleanup = if source_kind == SourceKind::Codex {
        Some(reconcile_codex_source_off()?)
    } else {
        None
    };
    if source_kind == SourceKind::Codex || !source_requires_config_patch(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} does not require local OTLP config patching",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "not_required",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} local session import prepared",
            source_display_name(&source_kind)
        );
        let mut result = install_source_registration_result(
            &install_session.install_session_id,
            &device_id,
            source,
            &message,
        );
        if let Some(cleanup) = codex_cleanup {
            result["live_telemetry_required"] = json!(false);
            result["local_import_ready"] = json!(
                snapshot_device_credentials_include_source("codex")
                    && codex_config_state_at(
                        &home_path(".codex/config.toml"),
                        "~/.codex/config.toml",
                        "",
                        false
                    )
                    .drift
                    .is_empty()
                    && !source_patch_disabled(&source_kind)
            );
            result["managed_telemetry_disabled"] = json!(!source_patch_disabled(&source_kind));
            result["config_updated"] = json!(cleanup.changed);
            result["requires_restart"] = json!(cleanup.changed);
            result["message"] = json!(if cleanup.changed {
                "Codex local import prepared; restart existing Codex processes to stop managed telemetry"
            } else {
                &message
            });
        }
        return Ok(("succeeded".to_string(), message, result));
    }

    if source_patch_disabled(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} telemetry config patching is disabled by environment",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "disabled_by_env",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} telemetry config patching skipped by environment",
            source_display_name(&source_kind)
        );
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            install_source_patch_disabled_result(
                &install_session.install_session_id,
                &device_id,
                source,
                &message,
            ),
        ));
    }

    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let relay_port = local_relay_port_for_daemon(daemon);
    let patch = match source_kind {
        SourceKind::Codex => reconcile_codex_source_off()?,
        SourceKind::ClaudeCode => {
            patch_claude_code_settings_with_relay_base(machine, &relay_base_url, false)?
        }
        SourceKind::Pi => unreachable!("Pi install actions do not patch OTLP config"),
    };
    let kept = patch.kept.map(claude_settings_kept_reason);
    let config_event_message = if let Some((_, text)) = kept {
        text.to_string()
    } else if patch.changed {
        format!(
            "Patched {} telemetry settings",
            source_display_name(&source_kind)
        )
    } else {
        format!(
            "{} telemetry settings already up to date",
            source_display_name(&source_kind)
        )
    };
    let mut metadata = json!({
        "source": source,
        "settings": match source_kind {
            SourceKind::Codex => "codex_config",
            SourceKind::ClaudeCode => "claude_settings",
            SourceKind::Pi => "none",
        },
        "changed": patch.changed,
        "created": patch.created,
        "backup_created": patch.backup_created,
        "backup_scope": "source_config",
        "restore_operation": "uninstall_restore",
    });
    if let Some((reason, _)) = kept {
        metadata["reason"] = json!(reason);
    }
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: if kept.is_some() {
                "config.patch.skipped"
            } else if patch.changed {
                "config.patched"
            } else {
                "config.unchanged"
            },
            status: "succeeded",
            message: &config_event_message,
            metadata: Some(metadata),
            device_id: Some(&device_id),
        },
    )?;

    let relay_running = loopback_listener_available(relay_port);
    if relay_running {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "relay.started",
                status: "succeeded",
                message: &format!(
                    "{} local OTLP relay is listening",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "port": relay_port,
                })),
                device_id: Some(&device_id),
            },
        )?;
    }

    let status = if relay_running { "succeeded" } else { "failed" }.to_string();
    let message = if let Some((_, text)) = kept {
        if relay_running {
            text.to_string()
        } else {
            format!("{text} The local OTLP relay is not listening.")
        }
    } else if relay_running {
        format!(
            "{} telemetry setup installed",
            source_display_name(&source_kind)
        )
    } else {
        let config_state = if patch.changed {
            "config was written"
        } else {
            "config is unchanged"
        };
        format!(
            "{} telemetry {config_state}, but the local OTLP relay is not listening",
            source_display_name(&source_kind)
        )
    };
    Ok((
        status,
        message.clone(),
        install_source_action_result(
            &install_session.install_session_id,
            &device_id,
            source,
            relay_running,
            relay_port,
            &message,
            patch.changed,
        ),
    ))
}

fn request_snapshot_sync_after_device_registration(daemon: &LocalDaemon) {
    if let Err(error) = crate::snapshot_sync::spawn_one_shot_local_snapshot_sync(daemon.clone()) {
        eprintln!(
            "local snapshot sync after setup unavailable: {}",
            crate::snapshot_sync::safe_error(&error)
        );
    }
}

fn source_requires_device_registration(source_kind: &SourceKind) -> bool {
    matches!(
        source_kind,
        SourceKind::Codex | SourceKind::ClaudeCode | SourceKind::Pi
    )
}

fn source_requires_config_patch(source_kind: &SourceKind) -> bool {
    matches!(source_kind, SourceKind::Codex | SourceKind::ClaudeCode)
}

fn source_patch_env_token(source_kind: &SourceKind) -> Option<&'static str> {
    match source_kind {
        SourceKind::Codex => Some("CODEX"),
        SourceKind::ClaudeCode => Some("CLAUDE_CODE"),
        SourceKind::Pi => None,
    }
}

fn setup_source_paused(source: &SourceKind) -> bool {
    source_patch_disabled(source)
        || crate::snapshot_sync::source_paused(
            &default_support_dir(),
            crate::snapshot_sync::snapshot_source_of_kind(source),
        )
}

fn source_patch_disabled(source_kind: &SourceKind) -> bool {
    let Some(token) = source_patch_env_token(source_kind) else {
        return false;
    };
    let key = format!("OTTTO_PATCH_{token}_DISABLED");
    std::env::var(&key)
        .ok()
        .is_some_and(|value| env_value_truthy(&value))
}

fn env_value_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn source_config_state_for_daemon(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<SourceConfigState, LocalApiError> {
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let patch_disabled = source_patch_disabled(source);
    Ok(match source {
        SourceKind::Codex => codex_config_state_at(
            &home_path(".codex/config.toml"),
            "~/.codex/config.toml",
            &relay_base_url,
            patch_disabled,
        ),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            let support_dir = default_support_dir();
            claude_code_settings_config_state_at(
                &home_path(".claude/settings.json"),
                "~/.claude/settings.json",
                &machine,
                &relay_base_url,
                &support_dir,
                patch_disabled,
            )
        }
        SourceKind::Pi => empty_source_config(source),
    })
}

fn empty_source_config(source: &SourceKind) -> SourceConfigState {
    SourceConfigState {
        discovered: false,
        path_hint: match source {
            SourceKind::Codex => Some("~/.codex/config.toml".to_string()),
            SourceKind::ClaudeCode => Some("~/.claude/settings.json".to_string()),
            SourceKind::Pi => None,
        },
        fingerprint: None,
        drift: Vec::new(),
    }
}

fn codex_config_state_at(
    path: &Path,
    path_hint: &str,
    _relay_base_url: &str,
    patch_disabled: bool,
) -> SourceConfigState {
    let bytes = fs::read(path);
    let (discovered, fingerprint, drift) = match bytes {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (false, None, Vec::new()),
        Err(_) => (
            false,
            None,
            vec![config_drift("codex.config_file", "readable", "unreadable")],
        ),
        Ok(bytes) => {
            let drift = match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|body| codex_source_off_body(body).ok().map(|next| (body, next)))
            {
                Some((body, next)) if body == next => Vec::new(),
                Some(_) => vec![config_drift(
                    "codex.ottto_exporters",
                    "disabled",
                    "configured",
                )],
                None => vec![config_drift(
                    "codex.config_toml",
                    "valid_unambiguous",
                    "needs_review",
                )],
            };
            (true, Some(config_fingerprint(&bytes)), drift)
        }
    };
    SourceConfigState {
        discovered,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift: if patch_disabled { Vec::new() } else { drift },
    }
}

fn claude_code_settings_config_state_at(
    path: &Path,
    path_hint: &str,
    machine: &MachineIdentity,
    relay_base_url: &str,
    support_dir: &Path,
    patch_disabled: bool,
) -> SourceConfigState {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return SourceConfigState {
                discovered: false,
                path_hint: Some(path_hint.to_string()),
                fingerprint: None,
                drift: if patch_disabled {
                    Vec::new()
                } else {
                    vec![config_drift(
                        "claude_code.settings_file",
                        "present",
                        "missing",
                    )]
                },
            };
        }
        Err(_) => {
            return SourceConfigState {
                discovered: false,
                path_hint: Some(path_hint.to_string()),
                fingerprint: None,
                drift: if patch_disabled {
                    Vec::new()
                } else {
                    vec![config_drift(
                        "claude_code.settings_file",
                        "readable",
                        "unreadable",
                    )]
                },
            };
        }
    };
    let fingerprint = Some(config_fingerprint(&bytes));
    if patch_disabled {
        return SourceConfigState {
            discovered: true,
            path_hint: Some(path_hint.to_string()),
            fingerprint,
            drift: Vec::new(),
        };
    }
    let mut drift = Vec::new();
    let settings = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value.is_object() => value,
        Ok(_) => {
            drift.push(config_drift(
                "claude_code.settings_json",
                "object",
                "non_object",
            ));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
        Err(_) => {
            drift.push(config_drift(
                "claude_code.settings_json",
                "valid",
                "invalid",
            ));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
    };
    let env = settings.get("env").and_then(|value| value.as_object());
    for (key, expected) in claude_code_relay_env_with_base(machine, relay_base_url) {
        let observed = env
            .and_then(|env| env.get(key))
            .and_then(|value| value.as_str());
        if observed != Some(expected.as_str()) {
            drift.push(config_drift(
                format!("env.{key}"),
                expected,
                observed.unwrap_or("missing"),
            ));
        }
    }
    let statusline_command = settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str());
    if let Some(command_drift) = claude_statusline_command_drift(statusline_command, support_dir) {
        drift.push(command_drift);
    } else if let Some(wrapper_drift) = claude_statusline_wrapper_drift(support_dir) {
        drift.push(wrapper_drift);
    }
    SourceConfigState {
        discovered: true,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift,
    }
}

fn config_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn config_drift(
    key: impl Into<String>,
    expected: impl Into<String>,
    observed: impl Into<String>,
) -> ConfigDrift {
    ConfigDrift {
        key: key.into(),
        expected: RedactedValue::String(expected.into()),
        observed: RedactedValue::String(observed.into()),
    }
}

fn patch_disabled_message(source: &SourceKind) -> StableMessage {
    StableMessage {
        code: "patch_disabled".to_string(),
        text: format!(
            "{} telemetry config patching is disabled by environment; Ottto will not inspect or repair local config.",
            source_display_name(source)
        ),
    }
}

fn install_source_registration_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "registered",
        "config_patched": false,
        "relay_required": false,
        "message": message,
    })
}

fn install_source_action_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    relay_running: bool,
    relay_port: u16,
    message: &str,
    config_patched: bool,
) -> serde_json::Value {
    let mut result = json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "installed",
        "config_patched": config_patched,
        "relay_running": relay_running,
        "relay_port": relay_port,
        "relay_source": source,
    });
    if !relay_running {
        result["error_code"] = json!("relay_unavailable");
        result["error_message"] = json!(message);
    }
    result
}

fn install_source_patch_disabled_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "patch_disabled",
        "config_patched": false,
        "relay_required": true,
        "message": message,
    })
}

#[derive(Debug, Deserialize)]
struct InstallSessionApiResponse {
    install_session_id: String,
    install_session_token: String,
}

#[derive(Clone, Deserialize)]
struct DeviceCredentialPreparationApiResponse {
    preparation_id: String,
    capability: String,
    expires_at: String,
    credential_generation: u64,
    device: TelemetryDeviceApiResponse,
    candidate_secret: String,
    #[serde(default)]
    identity_continuity_capability: Option<String>,
    credential_rotation_planned: bool,
    #[serde(default)]
    prior_device_id: Option<String>,
}

impl std::fmt::Debug for DeviceCredentialPreparationApiResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCredentialPreparationApiResponse")
            .field("preparation_id", &"[redacted]")
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at)
            .field("credential_generation", &self.credential_generation)
            .field("device", &"[redacted]")
            .field("candidate_secret", &"[redacted]")
            .field(
                "identity_continuity_capability",
                &self.identity_continuity_capability,
            )
            .field(
                "credential_rotation_planned",
                &self.credential_rotation_planned,
            )
            .field("prior_device_id", &self.prior_device_id)
            .finish()
    }
}

#[derive(Deserialize)]
struct DeviceCredentialConfirmationApiResponse {
    preparation_id: String,
    status: String,
    confirmed_at: String,
    credential_generation: u64,
    device: TelemetryDeviceApiResponse,
    #[serde(default)]
    identity_continuity_capability: Option<String>,
    credential_rotation_performed: bool,
    #[serde(default)]
    rotated_prior_device_id: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCredentialPreparationStatusApiResponse {
    preparation_id: String,
    status: String,
    expires_at: String,
    credential_generation: u64,
    device: TelemetryDeviceApiResponse,
    #[serde(default)]
    confirmed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TelemetryDeviceApiResponse {
    id: String,
    machine_id: Option<String>,
    #[serde(default)]
    sources: Vec<String>,
}

struct InstallSessionEvent<'a> {
    event_type: &'a str,
    status: &'a str,
    message: &'a str,
    metadata: Option<serde_json::Value>,
    device_id: Option<&'a str>,
}

fn prepare_telemetry_device_registration(
    api_base_url: &str,
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
) -> Result<
    (
        DeviceCredentialPreparationApiResponse,
        Option<PriorDeviceCredential>,
        PendingDeviceCredentialRequestAuthority,
    ),
    LocalApiError,
> {
    let url = api_url_with_base(
        api_base_url,
        "/api/v1/telemetry/devices/registration-preparations",
    );
    let prior = prior_device_credential_for_registration()?;
    let request_authority = device_credential_request_authority(
        "register",
        &install_session.install_session_id,
        machine,
        prior.as_ref(),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    );
    let mut body =
        telemetry_device_register_body_with_prior(install_session, machine, prior.as_ref());
    body["credential_preparation_capability"] = json!(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY);
    body["credential_preparation_idempotency_key"] = json!(request_authority
        .credential_preparation_idempotency_key
        .clone());
    let prepared =
        backend_post_json(&url, &body, &[]).map_err(registration_history_choice_error)?;
    validate_device_credential_preparation(&url, &prepared, prior.as_ref())?;
    Ok((prepared, prior, request_authority))
}

fn confirm_device_credential_preparation(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<DeviceCredentialConfirmationApiResponse, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    if !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
        || pending.confirmed_at.is_some()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    // The pending file is local state, not authority. Revalidate its base
    // before releasing the candidate secret in a request header.
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/device-credential-preparations/{}/confirm",
            pending.preparation_id
        ),
    );
    let body = json!({
        "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
        "credential_generation": pending.credential_generation,
    });
    let confirmed = backend_post_json(
        &url,
        &body,
        &[(
            DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER,
            candidate_secret,
        )],
    )
    .map_err(registration_history_choice_error)?;
    validate_device_credential_confirmation(&url, pending, &confirmed)?;
    Ok(confirmed)
}

fn inspect_device_credential_preparation(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<DeviceCredentialPreparationStatusApiResponse, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/device-credential-preparations/{}",
            pending.preparation_id
        ),
    );
    let status = backend_get_json(
        &url,
        &[(
            DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER,
            candidate_secret,
        )],
    )?;
    validate_device_credential_status(&url, pending, &status)?;
    Ok(status)
}

fn device_credential_preparation_idempotency_key(
    flow: &str,
    operation_id: &str,
    installation_id: &str,
) -> String {
    let mut digest = Sha256::new();
    for part in [
        DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
        flow,
        operation_id,
        installation_id,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn device_credential_request_authority(
    flow: &str,
    operation_id: &str,
    machine: &MachineIdentity,
    prior: Option<&PriorDeviceCredential>,
    identity_continuity_capability: Option<&str>,
) -> PendingDeviceCredentialRequestAuthority {
    PendingDeviceCredentialRequestAuthority {
        flow: flow.to_string(),
        credential_preparation_idempotency_key: device_credential_preparation_idempotency_key(
            flow,
            operation_id,
            &machine.installation_id,
        ),
        machine_id: machine.machine_id.clone(),
        installation_id: machine.installation_id.clone(),
        hardware_uuid: machine.hardware_uuid.clone(),
        account_scope: machine.account_scope.clone(),
        identity_continuity_capability: identity_continuity_capability.map(str::to_string),
        prior_device_id: prior.map(|value| value.device_id.clone()),
        prior_device_sources: prior.map(|value| value.device_sources.clone()),
        prior_secret_commitment_sha256: prior.map(|value| secret_sha256(&value.device_secret)),
        canonical_snapshot_namespace: None,
        incoming_snapshot_namespace: None,
    }
}

fn pending_credential_owner(
    pending: &PendingDeviceCredentialPreparation,
) -> Option<LocalCredentialOwner> {
    let claim = pending.claim_commit.as_ref()?;
    Some(LocalCredentialOwner {
        user_id: claim.target_user_id.clone(),
        organization_id: claim.account.organization.as_ref()?.id.clone(),
        api_base_url: pending.api_base_url.clone(),
    })
}

/// Exact claim identity; history never supplies authentication.
fn pending_owner_snapshot_key(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<OwnerSnapshotKey, LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let authority = pending
        .request_authority
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let owner = pending_credential_owner(pending).ok_or(LocalApiError::StatePoisoned)?;
    if authority.flow != "setup_claim"
        || claim.account.user.as_ref().map(|u| &u.id) != Some(&owner.user_id)
        || owner.api_base_url != validated_api_base_url(Some(&claim.connection.api_base_url))?
        || pending.device.machine_id.as_deref() != Some(authority.machine_id.as_str())
        || claim.connection.machine_id.as_deref() != Some(authority.machine_id.as_str())
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(OwnerSnapshotKey {
        owner,
        machine_id: authority.machine_id.clone(),
        installation_id: authority.installation_id.clone(),
        account_scope: authority
            .account_scope
            .clone()
            .filter(|v| !v.is_empty())
            .ok_or(LocalApiError::StatePoisoned)?,
    })
}

#[cfg(test)]
thread_local! {
    static OWNER_SNAPSHOT_MACHINE_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// One physical-observation boundary for selection, staging, promotion and logout.
fn owner_snapshot_live_machine(
    key: &OwnerSnapshotKey,
    hardware: Option<&str>,
) -> Result<bool, LocalApiError> {
    #[cfg(test)]
    if let Some(allowed) = OWNER_SNAPSHOT_MACHINE_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(allowed && tests::owner_return_test_machine(key)?);
    }
    let Some(machine) = FileMachineStore::default().load().or_state_poisoned()? else {
        return Ok(false);
    };
    Ok(machine.machine_id == key.machine_id
        && machine.installation_id == key.installation_id
        && crate::local_account_scope(&machine.machine_id).as_deref()
            == Some(key.account_scope.as_str())
        && crate::grant_rebind::verified_live_hardware().is_ok()
        && crate::grant_rebind::verify_hardware(
            hardware,
            crate::grant_rebind::live_hardware_id().as_deref(),
        )
        .is_ok())
}

/// Preserve main's same-owner rotation policy before consulting return history.
fn select_rotation_snapshot_namespace(
    pending: &mut PendingDeviceCredentialPreparation,
    prior: Option<&PriorDeviceCredential>,
) -> bool {
    let (Some(prior), Some(claim), Some(authority)) = (
        prior,
        pending.claim_commit.as_ref(),
        pending.request_authority.as_mut(),
    ) else {
        return false;
    };
    let Some(owner) = prior.owner.as_ref() else {
        return false;
    };
    if authority.flow == "setup_claim"
        && authority.prior_device_id.as_deref() == Some(prior.device_id.as_str())
        && pending.device.machine_id.as_deref() == Some(authority.machine_id.as_str())
        && claim.account.user.as_ref().map(|user| &user.id) == Some(&owner.user_id)
        && claim.account.organization.as_ref().map(|org| &org.id) == Some(&owner.organization_id)
        && claim.connection.api_base_url.trim_end_matches('/')
            == owner.api_base_url.trim_end_matches('/')
    {
        authority.canonical_snapshot_namespace = Some(prior.snapshot_namespace.clone());
        return true;
    }
    false
}

fn select_owner_snapshot_namespace(
    pending: &mut PendingDeviceCredentialPreparation,
    candidate: &str,
    prior: Option<&PriorDeviceCredential>,
    store: &FileOwnerSnapshotNamespaceStore,
    support: &Path,
) -> Result<(), LocalApiError> {
    if let Some(existing) =
        FilePendingDeviceCredentialStore::new(support.join("pending-device-credential.json"))
            .load()
            .or_state_poisoned()?
        && existing.preparation_id == pending.preparation_id
    {
        pending.schema_version = existing.schema_version;
        pending.request_authority = existing.request_authority;
        return Ok(()); // Immutable journal equality is checked at staging.
    }
    // Rotation keeps the released v2 path, including when live hardware,
    // installation scope, history or source custody is unavailable.
    if select_rotation_snapshot_namespace(pending, prior) {
        return Ok(());
    }
    let key = match pending_owner_snapshot_key(pending) {
        Ok(key) => key,
        Err(_) => return Ok(()),
    };
    let hardware = pending
        .request_authority
        .as_ref()
        .and_then(|a| a.hardware_uuid.as_deref());
    if !owner_snapshot_live_machine(&key, hardware)? {
        return Ok(());
    }
    let history = store.load().or_state_poisoned()?;
    let recorded = history.iter().find(|row| row.key == key);
    let selected = match recorded {
        Some(row)
            if crate::snapshot_sync::snapshot_namespace_has_store(support, &row.namespace)
                .or_state_poisoned()? =>
        {
            Some(row.namespace.clone())
        }
        _ => None,
    };
    let namespace = selected.clone().unwrap_or_else(|| {
        crate::snapshot_sync::snapshot_destination_namespace(&pending.device, candidate, None)
    });
    let authority = pending
        .request_authority
        .as_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    authority.canonical_snapshot_namespace = selected;
    authority.incoming_snapshot_namespace = Some(OwnerSnapshotNamespace { key, namespace });
    pending.schema_version = OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION;
    Ok(())
}

/// Called at the durable staging and promotion boundaries.
fn validate_owner_snapshot_selection(
    pending: &PendingDeviceCredentialPreparation,
    candidate: &str,
    store: &FileOwnerSnapshotNamespaceStore,
) -> Result<(), LocalApiError> {
    validate_pending_prior_credential_binding(pending)?;
    if pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
        return Ok(());
    }
    let authority = pending
        .request_authority
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let incoming = authority
        .incoming_snapshot_namespace
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    incoming.validate().or_state_poisoned()?;
    if incoming.key != pending_owner_snapshot_key(pending)?
        || !owner_snapshot_live_machine(&incoming.key, authority.hardware_uuid.as_deref())?
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let history = store.load().or_state_poisoned()?;
    if let Some(namespace) = authority.canonical_snapshot_namespace.as_ref() {
        if incoming.namespace != *namespace
            || !history
                .iter()
                .any(|row| row.key == incoming.key && row.namespace == *namespace)
        {
            return Err(LocalApiError::StatePoisoned);
        }
    } else if incoming.namespace
        != crate::snapshot_sync::snapshot_destination_namespace(&pending.device, candidate, None)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn publish_owner_snapshot_history(
    pending: &PendingDeviceCredentialPreparation,
    store: &FileOwnerSnapshotNamespaceStore,
) -> Result<(), LocalApiError> {
    if pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
        return Ok(());
    }
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let incoming = pending
        .request_authority
        .as_ref()
        .and_then(|a| a.incoming_snapshot_namespace.as_ref())
        .ok_or(LocalApiError::StatePoisoned)?;
    store
        .upsert(std::slice::from_ref(incoming))
        .or_state_poisoned()
}

/// Mid-claim logout keeps existing history and never seeds from mixed halves.
fn owner_snapshot_logout_can_retain_active(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<bool, LocalApiError> {
    if !supported_pending_credential_schema(pending.schema_version) {
        return Err(LocalApiError::StatePoisoned);
    }
    validate_pending_prior_credential_binding(pending)?;
    Ok(pending.confirmed_at.is_none() && !pending.preconfirm_guards_passed)
}

fn seed_owner_snapshot_history_for_logout() -> Result<bool, LocalApiError> {
    let store = FileOwnerSnapshotNamespaceStore::default();
    if let Some(pending) = FilePendingDeviceCredentialStore::default()
        .load()
        .or_state_poisoned()?
        && !owner_snapshot_logout_can_retain_active(&pending)?
    {
        return Ok(false);
    }
    let Some(machine) = FileMachineStore::default().load().or_state_poisoned()? else {
        return Ok(true);
    };
    let Some(scope) = crate::local_account_scope(&machine.machine_id) else {
        return Ok(true);
    };
    // Missing active secret is not a reason to make local logout unavailable.
    match KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).load() {
        Err(TokenStoreError::Missing) => return Ok(true),
        Err(_) => return Err(LocalApiError::StatePoisoned),
        Ok(_) => {}
    }
    if let Some(prior) = prior_device_credential_for_registration()?
        && let Some(mut owner) = prior.owner
    {
        owner.api_base_url = validated_api_base_url(Some(&owner.api_base_url))?;
        let key = OwnerSnapshotKey {
            owner,
            machine_id: machine.machine_id,
            installation_id: machine.installation_id,
            account_scope: scope,
        };
        if prior.machine_id.as_deref() == Some(key.machine_id.as_str())
            && owner_snapshot_live_machine(&key, machine.hardware_uuid.as_deref())?
        {
            if store
                .upsert(&[OwnerSnapshotNamespace {
                    key,
                    namespace: prior.snapshot_namespace,
                }])
                .is_err()
            {
                crate::local_resource_diagnostics::traversal_point(
                    "owner_history_seed_skipped",
                    "control",
                    &json!({"skipped_seeds": 1}),
                );
            }
        }
    }
    Ok(true)
}

fn same_prior_device_authority(
    expected: Option<&PriorDeviceCredential>,
    actual: Option<&PriorDeviceCredential>,
) -> bool {
    match (expected, actual) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            let expected_secret_commitment = secret_sha256(&expected.device_secret);
            let actual_secret_commitment = secret_sha256(&actual.device_secret);
            expected.machine_id == actual.machine_id
                && expected.device_id == actual.device_id
                && expected.device_sources == actual.device_sources
                && expected.owner == actual.owner
                && expected.snapshot_namespace == actual.snapshot_namespace
                && constant_work_eq(
                    expected_secret_commitment.as_bytes(),
                    actual_secret_commitment.as_bytes(),
                )
        }
        _ => false,
    }
}

/// The operation id is server-issued and survives a daemon crash. Retrying the
/// same install session or claim therefore reuses one idempotency key. An
/// expired attempt obtains a new boundary only by obtaining a new server
/// install session or setup claim; the daemon never spins on a locally minted
/// replacement key after a definitive 410.
fn validate_device_credential_preparation(
    url: &str,
    prepared: &DeviceCredentialPreparationApiResponse,
    prior: Option<&PriorDeviceCredential>,
) -> Result<(), LocalApiError> {
    if prepared.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || prepared.preparation_id.trim().is_empty()
        || prepared.expires_at.trim().is_empty()
        || prepared.credential_generation == 0
        || prepared.device.id.trim().is_empty()
        || prepared.device.sources.is_empty()
        || prepared.candidate_secret.trim().is_empty()
    {
        return Err(backend_response_unexpected(
            url,
            "telemetry registration returned an incomplete credential preparation".to_string(),
        ));
    }
    if prepared
        .identity_continuity_capability
        .as_deref()
        .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
    {
        return Err(backend_response_unexpected(
            url,
            "telemetry registration returned an unsupported identity continuity capability"
                .to_string(),
        ));
    }
    match prior {
        Some(prior)
            if !prepared.credential_rotation_planned
                || prepared.identity_continuity_capability.as_deref()
                    != Some(IDENTITY_CONTINUITY_CAPABILITY)
                || prepared.prior_device_id.as_deref() != Some(prior.device_id.as_str()) =>
        {
            Err(backend_response_unexpected(
                url,
                "telemetry registration returned inconsistent credential rotation preparation"
                    .to_string(),
            ))
        }
        None if prepared.credential_rotation_planned || prepared.prior_device_id.is_some() => {
            Err(backend_response_unexpected(
                url,
                "telemetry registration planned a prior-device rotation without prior authority"
                    .to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn validate_device_credential_confirmation(
    url: &str,
    pending: &PendingDeviceCredentialPreparation,
    confirmed: &DeviceCredentialConfirmationApiResponse,
) -> Result<(), LocalApiError> {
    if confirmed.preparation_id != pending.preparation_id
        || confirmed.status != "confirmed"
        || confirmed.confirmed_at.trim().is_empty()
        || confirmed.credential_generation != pending.credential_generation
        || confirmed.device.id != pending.device.device_id
        || confirmed.device.machine_id != pending.device.machine_id
        || confirmed.device.sources != pending.device.sources
    {
        return Err(backend_response_unexpected(
            url,
            "credential confirmation did not match the staged preparation".to_string(),
        ));
    }
    if confirmed
        .identity_continuity_capability
        .as_deref()
        .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
        || confirmed.credential_rotation_performed != confirmed.rotated_prior_device_id.is_some()
    {
        return Err(backend_response_unexpected(
            url,
            "credential confirmation returned inconsistent rotation proof".to_string(),
        ));
    }
    if let Some(prior_device_id) = pending
        .request_authority
        .as_ref()
        .and_then(|authority| authority.prior_device_id.as_deref())
    {
        if confirmed.identity_continuity_capability.as_deref()
            != Some(IDENTITY_CONTINUITY_CAPABILITY)
            || !confirmed.credential_rotation_performed
            || confirmed.rotated_prior_device_id.as_deref() != Some(prior_device_id)
        {
            return Err(backend_response_unexpected(
                url,
                "credential confirmation did not match the journaled prior authority".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_device_credential_status(
    url: &str,
    pending: &PendingDeviceCredentialPreparation,
    status: &DeviceCredentialPreparationStatusApiResponse,
) -> Result<(), LocalApiError> {
    if status.preparation_id != pending.preparation_id
        || status.expires_at != pending.expires_at
        || status.credential_generation != pending.credential_generation
        || status.device.id != pending.device.device_id
        || status.device.machine_id != pending.device.machine_id
        || status.device.sources != pending.device.sources
        || !matches!(
            status.status.as_str(),
            "pending" | "confirmed" | "expired" | "superseded"
        )
        || (status.status == "confirmed") != status.confirmed_at.is_some()
    {
        return Err(backend_response_unexpected(
            url,
            "credential preparation status did not match the staged generation".to_string(),
        ));
    }
    Ok(())
}

const IDENTITY_CONTINUITY_CAPABILITY: &str = "prior_device_credential_v1";
// Advertise only with the uploader that reprojects health and heartbeat using
// the paired machine id. This is compatibility information, not authority.
const MACHINE_IDENTITY_CAPABILITY: &str = "paired_machine_local_health_v1";

struct PriorDeviceCredential {
    machine_id: Option<String>,
    device_id: String,
    device_sources: Vec<String>,
    device_secret: String,
    /// Account the credential was installed for, if known.
    owner: Option<LocalCredentialOwner>,
    /// The namespace its local snapshot history lives under.
    snapshot_namespace: String,
}

fn prior_device_credential_for_registration() -> Result<Option<PriorDeviceCredential>, LocalApiError>
{
    let active_store = FileDeviceStore::default();
    if active_store.load().or_state_poisoned()?.is_some() {
        return prior_device_credential_with_stores(
            &active_store,
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            connected_account_owner(),
        );
    }
    // A retained prior carries the owner recorded before logout reset the account.
    prior_device_credential_with_stores(
        &FileDeviceStore::new(default_prior_device_path()),
        &KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT),
        None,
    )
}

/// Owner of a legacy active binding written before credentials recorded one:
/// the bound account, only while it is connected.
fn connected_account_owner() -> Option<LocalCredentialOwner> {
    let account = FileAccountStore::default().load().ok()?;
    let connection = FileConnectionStore::default().load().ok()??;
    if account.state != LocalAccountState::Connected {
        return None;
    }
    Some(LocalCredentialOwner {
        user_id: account.user?.id,
        organization_id: account.organization?.id,
        api_base_url: connection.api_base_url,
    })
}

fn retain_prior_device_credential_for_logout() -> Result<(), LocalApiError> {
    retain_prior_device_credential_with_stores(
        &FileDeviceStore::default(),
        &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        &FileDeviceStore::new(default_prior_device_path()),
        &KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT),
        connected_account_owner(),
    )
}

fn retain_prior_device_credential_with_stores(
    active_device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
    prior_device_store: &FileDeviceStore,
    prior_secret_store: &impl ControlTokenStore,
    legacy_owner: Option<LocalCredentialOwner>,
) -> Result<(), LocalApiError> {
    let Some(mut envelope) = active_device_store.load_envelope().or_state_poisoned()? else {
        return Ok(());
    };
    let secret = match active_secret_store.load() {
        Ok(secret) => secret,
        Err(TokenStoreError::Missing) => {
            // The active binding was already incomplete before logout. Do not
            // fail logout or reuse an unrelated older proof; the next claim
            // will surface the typed replacement path.
            prior_device_store.reset().or_state_poisoned()?;
            // The public device-id half is the authority selector. Removing it
            // makes any orphaned secret unusable; secret deletion is best
            // effort because a locked Keychain must not block local logout.
            let _ = prior_secret_store.delete();
            return Ok(());
        }
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    if envelope.device.device_id.trim().is_empty() || secret.trim().is_empty() {
        return Err(LocalApiError::StatePoisoned);
    }
    prior_secret_store.save(&secret).or_state_poisoned()?;
    envelope.continuity.owner = envelope.continuity.owner.take().or(legacy_owner);
    prior_device_store
        .save_envelope(&envelope)
        .or_state_poisoned()
}

fn clear_prior_device_credential() -> Result<(), LocalApiError> {
    clear_prior_device_selector()?;
    KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
        .delete()
        .or_state_poisoned()
}

fn clear_prior_device_selector() -> Result<(), LocalApiError> {
    FileDeviceStore::new(default_prior_device_path())
        .reset()
        .map(|_| ())
        .or_state_poisoned()
}

fn prior_device_credential_with_stores(
    device_store: &FileDeviceStore,
    secret_store: &impl ControlTokenStore,
    legacy_owner: Option<LocalCredentialOwner>,
) -> Result<Option<PriorDeviceCredential>, LocalApiError> {
    let Some(LocalDeviceEnvelope { device, continuity }) =
        device_store.load_envelope().or_state_poisoned()?
    else {
        return Ok(None);
    };
    let device_secret = secret_store.load().or_state_poisoned()?;
    if device.device_id.trim().is_empty() || device_secret.trim().is_empty() {
        return Err(LocalApiError::StatePoisoned);
    }
    let snapshot_namespace = crate::snapshot_sync::snapshot_destination_namespace(
        &device,
        &device_secret,
        continuity.snapshot_namespace.as_ref(),
    );
    Ok(Some(PriorDeviceCredential {
        machine_id: device.machine_id,
        device_id: device.device_id,
        device_sources: device.sources,
        device_secret,
        owner: continuity.owner.or(legacy_owner),
        snapshot_namespace,
    }))
}

#[cfg(test)]
fn telemetry_device_register_body(
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
) -> serde_json::Value {
    telemetry_device_register_body_with_prior(install_session, machine, None)
}

fn telemetry_device_register_body_with_prior(
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
    prior: Option<&PriorDeviceCredential>,
) -> serde_json::Value {
    let mut body = json!({
        "install_session_id": install_session.install_session_id,
        "install_session_token": install_session.install_session_token,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "client_name": OTTTO_CLIENT_NAME,
        "client_version": machine.local_platform_version,
        "machine_id": machine.machine_id,
        "machine_identity_capability": MACHINE_IDENTITY_CAPABILITY,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
    });
    if let Some(prior) = prior {
        body["prior_device_id"] = json!(prior.device_id);
        body["prior_device_secret"] = json!(prior.device_secret);
    }
    body
}

fn record_install_session_event(
    api_base_url: &str,
    install_session_id: &str,
    install_session_token: &str,
    event: InstallSessionEvent<'_>,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/telemetry/devices/install-sessions/{install_session_id}/events"),
    );
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "metadata": event.metadata,
        "device_id": event.device_id,
    });
    let _: serde_json::Value = backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Install-Session-Token", install_session_token)],
    )?;
    Ok(())
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ConfigPatchResult {
    changed: bool,
    created: bool,
    backup_created: bool,
    /// Claude settings left untouched because the user opted out or exports
    /// telemetry elsewhere.
    kept: Option<crate::agent_configs::claude_managed_settings::Outcome>,
}

fn local_relay_base_url_for_daemon(daemon: &LocalDaemon) -> String {
    crate::otlp_relay::local_relay_base_url_for_port(local_relay_port_for_daemon(daemon))
}

/// The port settings writers record. Only a relay bound and serving right now
/// (Connected) supplies its live port. While unbound or mid-rebind the
/// endpoint settings already approve stays, so a transient never moves it.
fn local_relay_port_for_daemon(daemon: &LocalDaemon) -> u16 {
    daemon
        .status_for_trusted_client()
        .ok()
        .filter(|status| status.relay.state == ottto_protocol::RelayRuntimeState::Connected)
        .and_then(|status| status.relay.endpoint)
        .as_deref()
        .and_then(crate::otlp_relay::local_relay_port_from_endpoint)
        .or_else(|| {
            approved_managed_claude_relay_endpoint()
                .ok()
                .flatten()
                .as_deref()
                .and_then(crate::otlp_relay::local_relay_port_from_endpoint)
        })
        .unwrap_or(crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT)
}

/// Upgrade reconciliation is local and never reads credentials or contacts a provider.
pub fn reconcile_codex_source_off_at_startup() -> Result<bool, LocalApiError> {
    reconcile_codex_source_off().map(|result| result.changed)
}

fn reconcile_codex_source_off() -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(&SourceKind::Codex) {
        return Ok(ConfigPatchResult::default());
    }
    reconcile_codex_source_off_at(&home_path(".codex/config.toml"), &default_support_dir())
}

static CODEX_CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());
static CODEX_CONFIG_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn reconcile_codex_source_off_at(
    path: &Path,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    let _write_guard = CODEX_CONFIG_WRITE_LOCK.lock().or_state_poisoned()?;
    let existing = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ConfigPatchResult::default())
        }
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    let next = codex_source_off_body(&existing)?;
    if next == existing {
        return Ok(ConfigPatchResult::default());
    }
    let backup_created = backup_existing_config(SourceKind::Codex, path, backup_root)?.is_some();
    if fs::read_to_string(path).or_state_poisoned()? != existing {
        return Err(LocalApiError::InvalidRequest(
            "Codex config changed during telemetry cleanup; retry after the edit finishes"
                .to_string(),
        ));
    }
    write_codex_source_off_body(path, &existing, &next)?;
    Ok(ConfigPatchResult {
        changed: true,
        created: false,
        backup_created,
        kept: None,
    })
}

fn write_codex_source_off_body(
    path: &Path,
    expected: &str,
    next: &str,
) -> Result<(), LocalApiError> {
    use std::io::Write;
    let sequence = CODEX_CONFIG_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp.codex-off.{}.{sequence}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| {
        let mut file = options.open(&temp).or_state_poisoned()?;
        let permissions = fs::metadata(path).or_state_poisoned()?.permissions();
        fs::set_permissions(&temp, permissions).or_state_poisoned()?;
        file.write_all(next.as_bytes()).or_state_poisoned()?;
        file.sync_all().or_state_poisoned()?;
        if fs::read_to_string(path).or_state_poisoned()? != expected {
            return Err(LocalApiError::InvalidRequest(
                "Codex config changed during cleanup; retry after the edit finishes".into(),
            ));
        }
        fs::rename(&temp, path).or_state_poisoned()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Only an Ottto header AND a loopback signal destination establish ownership.
/// External exporters and unrelated table fields survive, including inside a fence.
fn codex_source_off_body(existing: &str) -> Result<String, LocalApiError> {
    let fence = codex_toml::source_off_fence(existing, codex_exporter_relay_port)
        .map_err(|_| LocalApiError::ManualFenceReviewRequired)?;
    if let codex_toml::SourceOffFence::Recovered(next) = &fence {
        return Ok(next.clone());
    }
    let mut document = existing.parse::<DocumentMut>().or_state_poisoned()?;
    let Some(otel) = document.get_mut("otel").and_then(Item::as_table_like_mut) else {
        return Ok(existing.to_string());
    };
    let changed = remove_owned_codex_exporters(otel);
    if !changed {
        return Ok(existing.to_string());
    }
    // A legacy fence containing only the generated telemetry fields can go away
    // entirely. Mixed/user-edited fences keep their remaining contents.
    if let codex_toml::SourceOffFence::Complete { start, end } = fence {
        let fenced_body = &existing[start.end..end.start];
        if let Ok(mut fenced) = fenced_body.parse::<DocumentMut>() {
            if let Some(table) = fenced.get_mut("otel").and_then(Item::as_table_like_mut) {
                remove_owned_codex_exporters(table);
                let generated_only = table.iter().all(|(key, value)| match key {
                    "environment" => value.as_str() == Some("prod"),
                    "log_user_prompt" => value.as_bool() == Some(false),
                    _ => false,
                }) && fenced.iter().count() == 1;
                let full_table_generated_only =
                    document["otel"].as_table_like().is_some_and(|table| {
                        table.iter().all(|(key, value)| match key {
                            "environment" => value.as_str() == Some("prod"),
                            "log_user_prompt" => value.as_bool() == Some(false),
                            _ => false,
                        })
                    });
                if generated_only && full_table_generated_only {
                    let mut next = existing.to_string();
                    next.replace_range(start.start..end.end, "");
                    let mut remaining = next.parse::<DocumentMut>().or_state_poisoned()?;
                    if let Some(otel) = remaining.get_mut("otel").and_then(Item::as_table_like_mut)
                    {
                        if remove_owned_codex_exporters(otel) {
                            return Ok(remaining.to_string());
                        }
                    }
                    return Ok(next);
                }
            }
        }
    }
    Ok(document.to_string())
}

fn remove_owned_codex_exporters(otel: &mut dyn toml_edit::TableLike) -> bool {
    let mut changed = false;
    for (key, signal) in [
        ("exporter", "logs"),
        ("trace_exporter", "traces"),
        ("metrics_exporter", "metrics"),
    ] {
        if codex_exporter_relay_port(otel, key, signal).is_some() {
            let exporter = otel
                .get_mut(key)
                .and_then(Item::as_table_like_mut)
                .expect("owned exporter table");
            exporter.remove("otlp-http");
            if exporter.is_empty() {
                otel.remove(key);
            }
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
fn patch_codex_config_at(
    path: &Path,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    patch_codex_config_at_with_relay_base(
        path,
        backup_root,
        &crate::otlp_relay::default_local_relay_base_url(),
    )
}

// Historical enabled configuration is a fixture, never a production policy.
#[cfg(test)]
fn patch_codex_config_at_with_relay_base(
    path: &Path,
    backup_root: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let body = render_codex_relay_toml_block_for_base(relay_base_url);
    let backup_created = backup_existing_config(SourceKind::Codex, path, backup_root)?.is_some();
    let write = codex_toml::upsert_fence(path, &body).map_err(agent_config_error)?;
    Ok(ConfigPatchResult {
        changed: write.changed,
        created: write.created,
        backup_created,
        kept: None,
    })
}

#[cfg(test)]
fn render_codex_relay_toml_block_for_base(relay_base_url: &str) -> String {
    let relay_header = crate::otlp_relay::LOCAL_RELAY_HEADER;
    let relay_source = crate::otlp_relay::CODEX_RELAY_SOURCE;
    let relay_base_url = relay_base_url.trim_end_matches('/');
    [
        "otel.environment = \"prod\"".to_string(),
        "otel.log_user_prompt = false".to_string(),
        format!(
            "otel.exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/logs\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
        format!(
            "otel.trace_exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/traces\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
        format!(
            "otel.metrics_exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/metrics\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
    ]
    .join("\n")
}

/// `clear_opt_out` only for the explicit source Enable; every other caller
/// leaves an opt-out or external exporter in place and reports it.
fn patch_claude_code_settings_with_relay_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
    clear_opt_out: bool,
) -> Result<ConfigPatchResult, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    let backup_root = default_support_dir();
    let mut patch = patch_claude_code_settings_at_with_relay_base(
        &home_path(".claude/settings.json"),
        machine,
        &backup_root,
        relay_base_url,
        clear_opt_out,
    )?;
    patch.changed |= repair_registered_managed_claude_relay_settings_locked()?;
    Ok(patch)
}

fn repair_claude_statusline_for_refresh_at(
    path: &Path,
    machine: &MachineIdentity,
    support_dir: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    if !claude_statusline_refresh_repair_needed(path, support_dir) {
        return Ok(ConfigPatchResult::default());
    }
    patch_claude_code_settings_at_with_relay_base(path, machine, support_dir, relay_base_url, false)
}

fn claude_statusline_refresh_repair_needed(path: &Path, support_dir: &Path) -> bool {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let settings = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value.is_object() => value,
        _ => return false,
    };
    let has_telemetry_settings = settings
        .get("env")
        .and_then(|env| env.as_object())
        .is_some_and(|env| {
            env.keys().any(|key| {
                key.starts_with("OTEL_")
                    || matches!(
                        key.as_str(),
                        "CLAUDE_CODE_ENABLE_TELEMETRY"
                            | "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"
                            | "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS"
                    )
            })
        });
    if has_telemetry_settings
        && std::str::from_utf8(&bytes)
            .ok()
            .and_then(crate::agent_configs::claude_managed_settings::approved_relay_port)
            .is_none()
    {
        return false;
    }
    if [
        "CLAUDE_CODE_ENABLE_TELEMETRY",
        "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    ]
    .iter()
    .any(|key| {
        settings
            .get("env")
            .and_then(|env| env.get(*key))
            .is_some_and(|enabled| enabled != "1")
    }) {
        return false;
    }
    let statusline = settings
        .get("statusLine")
        .and_then(|value| value.as_object());
    if statusline
        .and_then(|statusline| statusline.get("type"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value != "command")
    {
        return false;
    }
    let command = statusline
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match command {
        None => true,
        Some(command) if is_ottto_statusline_command(command) => {
            command != expected_claude_statusline_command(support_dir).as_str()
                || claude_statusline_wrapper_drift(support_dir).is_some()
        }
        Some(_) => false,
    }
}

fn patch_claude_code_env_with_relay_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let backup_root = default_support_dir();
    patch_claude_code_env_at(
        &home_path(".ottto/claude-telemetry.env"),
        &home_path(".zshrc"),
        machine,
        &backup_root,
        relay_base_url,
    )
}

fn patch_claude_code_env_at(
    env_path: &Path,
    shell_rc_path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let entries = claude_code_relay_env_with_base(machine, relay_base_url);
    let entry_refs = entries
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();
    let env_body = claude_env::render_export_block(&entry_refs);
    let env_would_change =
        claude_env::upsert_would_change(env_path, &env_body).map_err(agent_config_error)?;
    let shell_body =
        r#"[ -f "$HOME/.ottto/claude-telemetry.env" ] && . "$HOME/.ottto/claude-telemetry.env""#;
    let shell_would_change =
        claude_env::upsert_would_change(shell_rc_path, shell_body).map_err(agent_config_error)?;
    if !env_would_change && !shell_would_change {
        return Ok(ConfigPatchResult::default());
    }
    let env_backup_created = if env_would_change {
        backup_existing_config(SourceKind::ClaudeCode, env_path, backup_root)?.is_some()
    } else {
        false
    };
    let shell_backup_created = if shell_would_change {
        backup_existing_config(SourceKind::ClaudeCode, shell_rc_path, backup_root)?.is_some()
    } else {
        false
    };
    let env_write = claude_env::upsert_fence(env_path, &env_body).map_err(agent_config_error)?;
    #[cfg(unix)]
    {
        if env_write.changed || env_write.created {
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(env_path, permissions).or_state_poisoned()?;
        }
    }

    let shell_write =
        claude_env::upsert_fence(shell_rc_path, shell_body).map_err(agent_config_error)?;

    Ok(ConfigPatchResult {
        changed: env_write.changed || shell_write.changed,
        created: env_write.created || shell_write.created,
        backup_created: env_backup_created || shell_backup_created,
        kept: None,
    })
}

fn remove_claude_code_env() -> Result<ConfigPatchResult, LocalApiError> {
    remove_claude_code_env_at(
        &home_path(".ottto/claude-telemetry.env"),
        &home_path(".zshrc"),
    )
}

fn remove_claude_code_env_at(
    env_path: &Path,
    shell_rc_path: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    let env_write = claude_env::remove_fence(env_path).map_err(agent_config_error)?;
    let shell_write = claude_env::remove_fence(shell_rc_path).map_err(agent_config_error)?;
    let removed_empty_env = if env_path.exists()
        && fs::read_to_string(env_path)
            .map(|body| body.trim().is_empty())
            .unwrap_or(false)
    {
        let _ = fs::remove_file(env_path);
        true
    } else {
        false
    };
    Ok(ConfigPatchResult {
        changed: env_write.changed || shell_write.changed || removed_empty_env,
        created: false,
        backup_created: false,
        kept: None,
    })
}

fn agent_config_error(error: AgentConfigError) -> LocalApiError {
    match error {
        AgentConfigError::AmbiguousFence { .. } => LocalApiError::ManualFenceReviewRequired,
        _ => LocalApiError::LocalOperationFailed(error.to_string()),
    }
}

#[cfg(test)]
fn patch_claude_code_settings_at(
    path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    patch_claude_code_settings_at_with_relay_base(
        path,
        machine,
        backup_root,
        &crate::otlp_relay::default_local_relay_base_url(),
        false,
    )
}

fn patch_claude_code_settings_at_with_relay_base(
    path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
    relay_base_url: &str,
    clear_opt_out: bool,
) -> Result<ConfigPatchResult, LocalApiError> {
    use crate::agent_configs::claude_managed_settings::{reconcile_default, Outcome};
    let created = !path.exists();
    let root = path.parent().ok_or(LocalApiError::StatePoisoned)?;
    let (mut wrapper_changed, mut backup_created) = (false, false);
    let (written, kept) = reconcile_default(
        root,
        &claude_code_relay_env_with_base(machine, relay_base_url),
        clear_opt_out,
        |settings| {
            wrapper_changed = point_claude_statusline_at_wrapper(settings, backup_root)
                .map_err(io::Error::other)?;
            Ok(())
        },
        || {
            backup_created = backup_existing_config(SourceKind::ClaudeCode, path, backup_root)
                .map_err(io::Error::other)?
                .is_some();
            Ok(())
        },
    )
    .map_err(|error| {
        LocalApiError::LocalOperationFailed(format!(
            "Claude Code settings could not be safely updated: {error}"
        ))
    })?;
    let written = written == Outcome::Changed;
    Ok(ConfigPatchResult {
        changed: written || wrapper_changed,
        created: created && written,
        backup_created,
        kept,
    })
}

/// Route the settings status line through Ottto's wrapper, delegating to the
/// user's own command, and refresh the wrapper. Returns whether it changed.
fn point_claude_statusline_at_wrapper(
    settings: &mut serde_json::Value,
    backup_root: &Path,
) -> Result<bool, LocalApiError> {
    let delegated_statusline = match existing_claude_statusline_command(settings) {
        Some(command) => Some(command),
        None => existing_claude_statusline_wrapper_delegated_command(backup_root)?,
    };
    let object = settings
        .as_object_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    let statusline_script = claude_statusline_wrapper_path(backup_root);
    let statusline_value = object.entry("statusLine").or_insert_with(|| json!({}));
    if !statusline_value.is_object() {
        *statusline_value = json!({});
    }
    let statusline = statusline_value
        .as_object_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    statusline.insert(
        "type".to_string(),
        serde_json::Value::String("command".to_string()),
    );
    statusline.insert(
        "command".to_string(),
        serde_json::Value::String(shell_quote_path(&statusline_script)),
    );
    let (_statusline_script, wrapper_changed) =
        write_claude_statusline_wrapper(backup_root, delegated_statusline.as_deref())?;
    Ok(wrapper_changed)
}

/// Stable reason code and user text for Claude settings Ottto left untouched.
fn claude_settings_kept_reason(
    kept: crate::agent_configs::claude_managed_settings::Outcome,
) -> (&'static str, &'static str) {
    use crate::agent_configs::claude_managed_settings::Outcome;
    match kept {
        Outcome::OptedOut => (
            "opted_out",
            "Claude Code settings turn telemetry off, so Ottto left their telemetry settings unchanged.",
        ),
        Outcome::Linked => (
            "linked_settings",
            "Claude Code settings.json is a link or not a regular file, so Ottto left it unchanged.",
        ),
        _ => (
            "external_telemetry",
            "Claude Code settings send telemetry to another collector, so Ottto left their telemetry settings unchanged.",
        ),
    }
}

fn existing_claude_statusline_command(settings: &serde_json::Value) -> Option<String> {
    let command = settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .filter(|statusline| {
            statusline
                .get("type")
                .and_then(|value| value.as_str())
                .map_or(true, |value| value == "command")
        })
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if is_ottto_statusline_command(command) {
        return None;
    }
    Some(command.to_string())
}

fn is_ottto_statusline_command(command: &str) -> bool {
    command.contains("claude-code-statusline")
}

fn claude_statusline_wrapper_path(support_dir: &Path) -> PathBuf {
    support_dir.join("claude-code-statusline.sh")
}

fn expected_claude_statusline_command(support_dir: &Path) -> String {
    shell_quote_path(&claude_statusline_wrapper_path(support_dir))
}

fn claude_statusline_command_drift(
    command: Option<&str>,
    support_dir: &Path,
) -> Option<ConfigDrift> {
    let expected = expected_claude_statusline_command(support_dir);
    let observed = command.map(str::trim).filter(|value| !value.is_empty());
    match observed {
        Some(command) if command == expected => None,
        Some(command) if is_ottto_statusline_command(command) => {
            Some(config_drift("statusLine.command", expected, command))
        }
        Some(command) => Some(config_drift(
            "statusLine.command",
            "ottto claude-code-statusline wrapper",
            command,
        )),
        None => Some(config_drift(
            "statusLine.command",
            "ottto claude-code-statusline wrapper",
            "missing",
        )),
    }
}

fn claude_statusline_wrapper_drift(support_dir: &Path) -> Option<ConfigDrift> {
    let path = claude_statusline_wrapper_path(support_dir);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "missing",
            ));
        }
        Err(_) => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "unreadable",
            ));
        }
    };
    if !metadata.is_file() {
        return Some(config_drift(
            "statusLine.wrapper",
            "executable current ottto statusLine wrapper",
            "not_file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Some(config_drift(
            "statusLine.wrapper",
            "executable current ottto statusLine wrapper",
            "not_executable",
        ));
    }
    let body = match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(_) => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "unreadable",
            ));
        }
    };
    let delegated_command = body
        .lines()
        .find_map(|line| line.strip_prefix("ORIGINAL_STATUSLINE="))
        .and_then(parse_shell_single_quoted_assignment)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let expected =
        render_claude_statusline_wrapper(&preferred_ottto_cli_path(), delegated_command.as_deref());
    if body != expected {
        return Some(config_drift(
            "statusLine.wrapper",
            "current ottto statusLine wrapper",
            "stale",
        ));
    }
    None
}

fn claude_statusline_wrapper_ready(support_dir: &Path) -> bool {
    claude_statusline_wrapper_drift(support_dir).is_none()
}

fn existing_claude_statusline_wrapper_delegated_command(
    support_dir: &Path,
) -> Result<Option<String>, LocalApiError> {
    let path = claude_statusline_wrapper_path(support_dir);
    let body = match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    Ok(body
        .lines()
        .find_map(|line| line.strip_prefix("ORIGINAL_STATUSLINE="))
        .and_then(parse_shell_single_quoted_assignment)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn parse_shell_single_quoted_assignment(value: &str) -> Option<String> {
    let inner = value.trim().strip_prefix('\'')?.strip_suffix('\'')?;
    Some(inner.replace("'\"'\"'", "'"))
}

fn write_claude_statusline_wrapper(
    support_dir: &Path,
    delegated_command: Option<&str>,
) -> Result<(PathBuf, bool), LocalApiError> {
    fs::create_dir_all(support_dir).or_state_poisoned()?;
    let path = claude_statusline_wrapper_path(support_dir);
    let cli_path = preferred_ottto_cli_path();
    let script = render_claude_statusline_wrapper(&cli_path, delegated_command);
    match fs::read_to_string(&path) {
        Ok(existing) if existing == script => return Ok((path, false)),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LocalApiError::StatePoisoned),
    }
    let tmp_path = path.with_extension(format!("sh.tmp.{}", std::process::id()));
    fs::write(&tmp_path, script).or_state_poisoned()?;
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(&tmp_path, permissions).or_state_poisoned()?;
    }
    fs::rename(&tmp_path, &path).or_state_poisoned()?;
    Ok((path, true))
}

fn preferred_ottto_cli_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("ottto"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".ottto/bin/ottto"));
    }
    if let Some(path) = crate::command_env::executable_path("ottto") {
        candidates.push(path);
    }
    candidates
        .into_iter()
        .find(|path| path.exists() && path.is_file())
}

fn render_claude_statusline_wrapper(
    cli_path: &Option<PathBuf>,
    delegated_command: Option<&str>,
) -> String {
    let cli_assignment = cli_path
        .as_ref()
        .map(|path| shell_single_quote(&path.display().to_string()))
        .unwrap_or_else(|| "''".to_string());
    let delegated_assignment = delegated_command
        .map(shell_single_quote)
        .unwrap_or_else(|| "''".to_string());
    format!(
        r#"#!/bin/sh
input="$(cat)"
OTTTO_CLI={cli_assignment}
ORIGINAL_STATUSLINE={delegated_assignment}

if [ -n "$OTTTO_CLI" ] && [ -x "$OTTTO_CLI" ]; then
  printf '%s' "$input" | "$OTTTO_CLI" claude-code-statusline >/dev/null 2>&1 || true
else
  printf '%s' "$input" | ottto claude-code-statusline >/dev/null 2>&1 || true
fi

if [ -n "$ORIGINAL_STATUSLINE" ]; then
  printf '%s' "$input" | sh -c "$ORIGINAL_STATUSLINE"
fi
"#
    )
}

fn shell_quote_path(path: &Path) -> String {
    shell_single_quote(&path.display().to_string())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigBackupResult {
    backup_id: String,
}

fn backup_existing_config(
    source: SourceKind,
    path: &Path,
    backup_root: &Path,
) -> Result<Option<ConfigBackupResult>, LocalApiError> {
    if !path.exists() {
        return Ok(None);
    }
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_millis();
    let backup_id = format!("{}_config_{millis}", source_slug(&source));
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("backup");
    let backup_dir = backup_root
        .join("config-backups")
        .join(source_slug(&source));
    fs::create_dir_all(&backup_dir).or_state_poisoned()?;
    fs::copy(path, backup_dir.join(format!("{backup_id}.{extension}"))).or_state_poisoned()?;
    prune_config_backups(&backup_dir, config_backup_retention_limit())?;
    Ok(Some(ConfigBackupResult { backup_id }))
}

fn config_backup_retention_limit() -> usize {
    std::env::var(OTTTO_CONFIG_BACKUP_RETENTION_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(MAX_CONFIG_BACKUPS_PER_SOURCE)
}

fn prune_config_backups(backup_dir: &Path, keep: usize) -> Result<(), LocalApiError> {
    let mut entries = fs::read_dir(backup_dir)
        .or_state_poisoned()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some(ConfigBackupEntry {
                rank_millis: config_backup_rank_millis(&path, &metadata),
                path,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .rank_millis
            .cmp(&left.rank_millis)
            .then_with(|| right.path.cmp(&left.path))
    });
    for entry in entries.into_iter().skip(keep) {
        if let Err(error) = fs::remove_file(&entry.path) {
            eprintln!(
                "Failed to prune old config backup {}: {error}",
                entry.path.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ConfigBackupEntry {
    rank_millis: Option<u128>,
    path: PathBuf,
}

fn config_backup_rank_millis(path: &Path, metadata: &fs::Metadata) -> Option<u128> {
    let file_name = path.file_name()?.to_str()?;
    if let Some((_prefix, suffix)) = file_name.split_once("_config_") {
        let timestamp = suffix.split('.').next().unwrap_or("");
        return timestamp.parse::<u128>().ok();
    }
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
}

fn claude_code_relay_env_with_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
) -> Vec<(&'static str, String)> {
    claude_code_relay_env_for_machine_id(&machine.machine_id, relay_base_url)
}

fn claude_code_relay_env_for_machine_id(
    machine_id: &str,
    relay_base_url: &str,
) -> Vec<(&'static str, String)> {
    let relay_base = relay_base_url.trim_end_matches('/');
    vec![
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".to_string()),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1".to_string()),
        ("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS", "10000".to_string()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_string()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_string()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_string()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_string()),
        // The local reducer consumes Claude's exact per-request api_request logs.
        // Keep metrics/traces protobuf while making only the logs signal safely
        // inspectable without persisting raw OTLP payloads.
        ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/json".to_string()),
        (
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            format!("{relay_base}/v1/metrics"),
        ),
        (
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            format!("{relay_base}/v1/logs"),
        ),
        (
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            format!("{relay_base}/v1/traces"),
        ),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Ottto-Local-Relay=claude_code".to_string(),
        ),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            format!(
                "service.name=claude-code,ottto.source=claude_code,ottto.machine_id={machine_id}"
            ),
        ),
    ]
}

/// Status, message and backend result of a setup action, plus the
/// verification result a verify_source action computed.
type SetupVerifyActionOutcome = (
    String,
    String,
    serde_json::Value,
    Option<SourceVerificationResult>,
);

fn run_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    source: SourceKind,
) -> Result<SetupVerifyActionOutcome, LocalApiError> {
    if source == SourceKind::Codex {
        reconcile_codex_source_off()?;
        let result = verify_source(
            daemon,
            &RequestAuthorization::TrustedCompanionApp,
            source,
            false,
        )?;
        let ready = result.message.code == "codex_local_import" && result.config.drift.is_empty();
        return Ok((
            if ready { "succeeded" } else { "failed" }.to_string(),
            result.message.text.clone(),
            json!({
                "status": verification_status_slug(&result.status), "verified": false, "records_seen": 0,
                "last_record_id": null, "last_received_at": null, "smoke_after": null,
                "local_import_ready": ready, "live_telemetry_required": false,
                "message_code": result.message.code,
                "error_code": if ready { serde_json::Value::Null } else { json!(result.message.code) },
                "error_message": if ready { serde_json::Value::Null } else { json!(result.message.text) }
            }),
            Some(result),
        ));
    }

    if !source_binary_present(&source) {
        let mut result =
            not_installed_verification_result(source.clone(), empty_source_config(&source));
        daemon.record_verification_result(&result)?;
        attach_verification_check(&mut result);
        let message = result.message.text.clone();
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            json!({
                "status": verification_status_slug(&result.status),
                "verified": false,
                "records_seen": 0,
                "last_record_id": serde_json::Value::Null,
                "last_received_at": serde_json::Value::Null,
                "smoke_after": serde_json::Value::Null,
                "error_code": SOURCE_NOT_INSTALLED_CODE,
                "error_message": message,
            }),
            Some(result),
        ));
    }
    // Pi verifies its routes after the shared not-installed gate, so a Mac
    // without Pi never creates Pi directories or runs a doomed smoke.
    if source == SourceKind::Pi {
        return run_pi_verify_source_action(daemon, api_base_url, credentials, action);
    }
    let smoke_after = current_rfc3339();
    let smoke = run_verification_smoke_prompt(daemon, &source)?;
    record_setup_action_event(
        api_base_url,
        credentials,
        action,
        SetupActionEvent {
            event_type: "smoke.completed",
            status: if smoke.succeeded {
                "succeeded"
            } else {
                "warning"
            },
            message: &smoke.message,
            metadata: Some(json!({
                "source": source_slug(&source),
                "command_found": smoke.command_found,
                "exit_status": smoke.exit_status,
                "duration_ms": smoke.duration_ms,
                "diagnostic": smoke.diagnostic.clone(),
            })),
        },
    )?;
    if !smoke.succeeded {
        let mut result =
            smoke_failure_verification_result(source.clone(), &smoke, Some(smoke_after));
        daemon.record_verification_result(&result)?;
        attach_verification_check(&mut result);
        let message = result.message.text.clone();
        let action_status = match result.status {
            SourceVerificationStatus::Verified | SourceVerificationStatus::Warning => "succeeded",
            _ => "failed",
        };
        return Ok((
            action_status.to_string(),
            message.clone(),
            json!({
                "status": verification_status_slug(&result.status),
                "verified": false,
                "records_seen": 0,
                "last_record_id": serde_json::Value::Null,
                "last_received_at": serde_json::Value::Null,
                "smoke_after": result.smoke_after,
                "smoke": smoke_result_metadata(&smoke),
                "error_code": smoke.error_code.as_deref().unwrap_or("smoke_command_failed"),
                "error_message": message,
            }),
            Some(result),
        ));
    }
    let _ = emit_setup_run_fast_verification_marker_with_refresh_mut(
        api_base_url,
        credentials,
        &source,
        "setup_action_verify",
    );
    let verification =
        wait_for_verification_with_refresh_mut(api_base_url, credentials, &source, &smoke_after)?;
    let failure_code = verification_failure_code(&source, &smoke, &verification);
    let verification_message = if verification.verified {
        format!("{} verification passed.", source_display_name(&source))
    } else {
        verification_failure_message(
            &source,
            &smoke,
            &failure_code,
            verification.clear_condition.as_deref(),
        )
    };
    let mut result = verification_result(
        source.clone(),
        if verification.verified {
            SourceVerificationStatus::Verified
        } else {
            SourceVerificationStatus::NoFreshTelemetry
        },
        verification.verified,
        verification.records_seen,
        verification.last_record_id.clone(),
        verification.last_received_at.clone(),
        Some(verification.smoke_after.clone()),
        if verification.verified {
            "verified"
        } else {
            &failure_code
        },
        &verification_message,
    );
    daemon.record_verification_result(&result)?;
    attach_verification_check(&mut result);
    let status = if verification.verified {
        "succeeded"
    } else {
        "failed"
    };
    let message = result.message.text.clone();
    Ok((
        status.to_string(),
        message,
        json!({
            "verified": verification.verified,
            "records_seen": verification.records_seen,
            "last_record_id": verification.last_record_id,
            "last_received_at": verification.last_received_at,
            "smoke_after": verification.smoke_after,
            "smoke": smoke_result_metadata(&smoke),
            "error_code": if verification.verified { serde_json::Value::Null } else { json!(failure_code) },
            "error_message": if verification.verified { serde_json::Value::Null } else { json!(result.message.text) },
        }),
        Some(result),
    ))
}

fn run_pi_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
) -> Result<SetupVerifyActionOutcome, LocalApiError> {
    let mut result = run_pi_route_verification_with_credentials(api_base_url, credentials, None)?;
    record_setup_action_event(
        api_base_url,
        credentials,
        action,
        SetupActionEvent {
            event_type: "smoke.completed",
            status: if result.status == SourceVerificationStatus::Verified {
                "succeeded"
            } else if result.status == SourceVerificationStatus::Warning {
                "warning"
            } else {
                "failed"
            },
            message: &result.message.text,
            metadata: Some(pi_route_summary_metadata(&result)),
        },
    )?;
    daemon.record_verification_result(&result)?;
    let message = result.message.text.clone();
    let routes_total = result.route_results.len();
    let routes_verified = result
        .route_results
        .iter()
        .filter(|route| route.verified)
        .count();
    let routes_failed = routes_total.saturating_sub(routes_verified);
    // A Warning (partial-verified, or all routes awaiting a provider re-sign-in)
    // is a non-fatal completion: the run should advance and the source settle to
    // "warning"/needs-attention, not a hard "failed" that blocks. Only a real
    // smoke Failed maps the action to "failed".
    let action_status = match result.status {
        SourceVerificationStatus::Verified | SourceVerificationStatus::Warning => "succeeded",
        _ => "failed",
    };
    let backend_result = json!({
        "status": verification_status_slug(&result.status),
        "verified": result.verified,
        "records_seen": result.records_seen,
        "last_record_id": result.last_record_id,
        "last_received_at": result.last_received_at,
        "smoke_after": result.smoke_after,
        "route_results": result.route_results,
        "routes_total": routes_total,
        "routes_verified": routes_verified,
        "routes_failed": routes_failed,
        "error_code": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(result.message.code) },
        "error_message": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(message) },
    });
    // Classify after building the backend payload so its bytes are unchanged.
    attach_verification_check(&mut result);
    Ok((
        action_status.to_string(),
        message,
        backend_result,
        Some(result),
    ))
}

struct SmokeResult {
    command_found: bool,
    succeeded: bool,
    exit_status: Option<i32>,
    duration_ms: u128,
    message: String,
    diagnostic: Option<String>,
    error_code: Option<String>,
    local_session_observed: Option<bool>,
}

/// Code for a Verify smoke the quiet window held back: starting Claude Code
/// now could refresh, and so sign out, the saved login.
pub(crate) const CLAUDE_LOGIN_REFRESH_PENDING_CODE: &str = "claude_login_refresh_pending";
pub(crate) const CLAUDE_SMOKE_TIMEOUT_MESSAGE: &str =
    "The Claude Code test run timed out before Ottto could check it.";

fn run_verification_smoke_prompt(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<SmokeResult, LocalApiError> {
    if *source == SourceKind::ClaudeCode {
        let connected = daemon
            .state()?
            .sources
            .iter()
            .find(|health| health.source == *source)
            .and_then(|health| health.agent_status.as_ref())
            .is_some_and(crate::agent_status::claude_default_check_skipped);
        if connected {
            return Ok(SmokeResult {
                command_found: true,
                succeeded: false,
                exit_status: None,
                duration_ms: 0,
                message: "Claude is connected through an account added in Ottto. The live check is skipped because Claude Code isn't signed in on this Mac.".to_string(),
                diagnostic: None,
                error_code: Some(crate::agent_status::CLAUDE_OTTTO_SIGNED_IN.to_string()),
                local_session_observed: None,
            });
        }
        daemon.remember_claude_verification_auth_marker(
            crate::agent_status::claude_credential_modified_marker(
                &ottto_core::ClaudeConfigDirSlot::Default,
            ),
        )?;
    }
    Ok(run_smoke_prompt(source))
}

fn run_smoke_prompt(source: &SourceKind) -> SmokeResult {
    if matches!(source, SourceKind::ClaudeCode) {
        if let Err(refusal) = crate::claude_spawn_gate::check_short_claude_run(
            &ottto_core::ClaudeConfigDirSlot::Default,
        ) {
            return SmokeResult {
                command_found: true,
                succeeded: false,
                exit_status: None,
                duration_ms: 0,
                message: if refusal.waits_for_claude_refresh() {
                    "Claude Code needs to refresh its sign-in first: open Claude Code once (or wait a few minutes), then Verify. Ottto did not start Claude Code, because doing so now could sign this account out.".to_string()
                } else {
                    "Ottto could not safely check Claude Code's saved sign-in, so it skipped the live check: open Claude Code once, then Verify.".to_string()
                },
                diagnostic: Some(format!("quiet_window:{}", refusal.code())),
                error_code: Some(CLAUDE_LOGIN_REFRESH_PENDING_CODE.to_string()),
                local_session_observed: None,
            };
        }
    }
    let command = smoke_command(source);
    let before_session_count = if matches!(source, SourceKind::Pi) {
        Some(pi_session_file_count())
    } else {
        None
    };
    let mut result = run_bounded_command(
        command.program,
        &command.args,
        SMOKE_COMMAND_TIMEOUT,
        source_display_name(source),
        before_session_count,
    );
    match source {
        SourceKind::Codex => record_smoke_prompt(
            crate::provider_calls::Provider::Openai,
            crate::provider_calls::CallKind::CodexSmokePrompt,
            crate::agent_status::codex_cli_home_claimed_account_hash(),
            &result,
        ),
        SourceKind::ClaudeCode => record_smoke_prompt(
            crate::provider_calls::Provider::Anthropic,
            crate::provider_calls::CallKind::ClaudeSmokePrompt,
            crate::provider_calls::claude_slot_account_hash(
                &ottto_core::ClaudeConfigDirSlot::Default,
            ),
            &result,
        ),
        // Pi's default route names no provider, but it is a real model
        // request.
        SourceKind::Pi => record_smoke_prompt(
            crate::provider_calls::Provider::Unknown,
            crate::provider_calls::CallKind::PiDefaultSmokePrompt,
            None,
            &result,
        ),
    }
    classify_source_smoke_failure(source, &mut result);
    result
}

/// One provider-call log line per smoke prompt that started: at least one
/// request carrying the prompt.
fn record_smoke_prompt(
    provider: crate::provider_calls::Provider,
    kind: crate::provider_calls::CallKind,
    account_identifier_hash: Option<String>,
    result: &SmokeResult,
) {
    use crate::provider_calls::{CallResult, ProviderCall, Trigger};
    if !result.command_found {
        return;
    }
    let outcome = if result.succeeded {
        CallResult::Ok
    } else if result.error_code.as_deref() == Some("smoke_timeout") {
        CallResult::Timeout
    } else {
        result
            .exit_status
            .map_or(CallResult::Error("not_observed"), CallResult::Exit)
    };
    crate::provider_calls::record(ProviderCall::subprocess(
        provider,
        kind,
        crate::provider_calls::trigger_or(Trigger::Other),
        account_identifier_hash.as_deref(),
        outcome,
        Duration::from_millis(u64::try_from(result.duration_ms).unwrap_or(u64::MAX)),
        1,
    ));
}

struct SmokeCommand {
    program: &'static str,
    args: Vec<String>,
}

fn smoke_command(source: &SourceKind) -> SmokeCommand {
    match source {
        SourceKind::Codex => SmokeCommand {
            program: "codex",
            args: vec![
                "exec",
                "--ignore-user-config",
                "--ignore-rules",
                "--ephemeral",
                "--json",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "-c",
                "model_reasoning_effort=low",
                SMOKE_PROMPT,
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        },
        SourceKind::ClaudeCode => SmokeCommand {
            program: "claude",
            args: vec![
                "-p",
                SMOKE_PROMPT,
                "--name",
                "ottto test",
                "--settings",
                r#"{"env":{"OTEL_LOGS_EXPORTER":"none","OTEL_TRACES_EXPORTER":"none","OTEL_METRICS_EXPORTER":"none"}}"#,
                "--session-id",
                &crate::internal_session::internal_session_id(),
                "--disallowedTools",
                "*",
                "--no-session-persistence",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        },
        SourceKind::Pi => pi_smoke_command(None),
    }
}

fn pi_smoke_command(route: Option<&PiModelRoute>) -> SmokeCommand {
    let version = detect_agent_installation(&SourceKind::Pi).version;
    pi_smoke_command_with_version(route, version.as_deref())
}

fn pi_smoke_command_with_version(
    route: Option<&PiModelRoute>,
    version: Option<&str>,
) -> SmokeCommand {
    let mut args = vec!["--no-builtin-tools", "--no-context-files", "--print"]
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if let Some(route) = route.filter(|route| !pi_route_is_unscoped(route)) {
        args.extend([
            "--provider".to_string(),
            route.provider.clone(),
            "--model".to_string(),
            route.model.clone(),
        ]);
        if let Some(thinking_level) = route.thinking_level.as_deref() {
            args.extend(["--thinking".to_string(), thinking_level.to_string()]);
        }
    }
    // parse_version accepts missing or malformed patch components and extra parts.
    let version = version.filter(|v| {
        let core = v.trim();
        core.split('.').count() == 3
            && core
                .split('.')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    });
    if version
        .and_then(crate::mcp_inventory::parse_version)
        .is_some_and(|v| v >= (0, 76, 0))
    {
        args.extend([
            "--session-id".to_string(),
            crate::internal_session::internal_session_id(),
        ]);
    }
    args.push(SMOKE_PROMPT.to_string());
    SmokeCommand {
        program: "pi",
        args,
    }
}

fn pi_route_is_unscoped(route: &PiModelRoute) -> bool {
    route.provider == "default" && route.model == "default"
}

fn pi_route_provider(route: &PiModelRoute) -> Option<String> {
    (!pi_route_is_unscoped(route)).then(|| route.provider.clone())
}

fn pi_route_model(route: &PiModelRoute) -> Option<String> {
    (!pi_route_is_unscoped(route)).then(|| route.model.clone())
}

fn pi_route_label(route: &PiModelRoute) -> String {
    if pi_route_is_unscoped(route) {
        "default route".to_string()
    } else {
        format!("{} / {}", route.provider, route.model)
    }
}

fn run_bounded_command(
    program: &str,
    args: &[String],
    timeout: Duration,
    display_name: &str,
    before_session_count: Option<usize>,
) -> SmokeResult {
    let start = Instant::now();
    let Some(program_path) = crate::command_env::executable_path(program) else {
        return SmokeResult {
            command_found: false,
            succeeded: false,
            exit_status: None,
            duration_ms: start.elapsed().as_millis(),
            message: format!("{program} is not installed or not executable."),
            diagnostic: None,
            error_code: Some("command_not_found".to_string()),
            local_session_observed: None,
        };
    };
    let mut command = Command::new(program_path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    if program == "pi" {
        command.envs(crate::command_env::provider_env_with_refresh(true));
    }
    // The Claude smoke runs on the default login, the one its gate checked.
    let claude_login = (program == "claude").then_some(ottto_core::ClaudeConfigDirSlot::Default);
    if let Some(login) = claude_login.as_ref() {
        crate::claude_spawn_gate::pin_claude_login(&mut command, login);
    }
    let mut child = match crate::local_resource_diagnostics::cli_children::spawn(&mut command) {
        Ok(child) => child,
        Err(_) => {
            return SmokeResult {
                command_found: false,
                succeeded: false,
                exit_status: None,
                duration_ms: start.elapsed().as_millis(),
                message: format!("{program} is not installed or not executable."),
                diagnostic: None,
                error_code: Some("command_not_found".to_string()),
                local_session_observed: None,
            };
        }
    };
    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (diagnostic, usage_limited) =
                    read_command_diagnostic_with_flags(stdout_reader, stderr_reader);
                return SmokeResult {
                    command_found: true,
                    succeeded: status.success(),
                    exit_status: status.code(),
                    duration_ms: start.elapsed().as_millis(),
                    message: if status.success() {
                        format!("{display_name} smoke session completed.")
                    } else if usage_limited {
                        usage_limited_smoke_message(display_name)
                    } else if program == "claude" {
                        match diagnostic.as_deref() {
                            Some(diagnostic) => format!("The Claude Code test run failed before Ottto could check it: {diagnostic}"),
                            None => "The Claude Code test run failed before Ottto could check it.".to_string(),
                        }
                    } else if let Some(diagnostic) = diagnostic.as_deref() {
                        format!(
                            "{display_name} smoke session failed before verification could complete: {diagnostic}"
                        )
                    } else {
                        format!("{display_name} smoke session failed before verification could complete. Check the local {display_name} auth and provider configuration, then retry Verify.")
                    },
                    diagnostic,
                    error_code: if status.success() {
                        None
                    } else if usage_limited {
                        Some(SMOKE_USAGE_LIMIT_ERROR_CODE.to_string())
                    } else {
                        Some("smoke_command_failed".to_string())
                    },
                    local_session_observed: local_session_observed(before_session_count),
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let left_running = match claude_login.as_ref() {
                    Some(login) => crate::claude_spawn_gate::stop_claude_child(
                        child.into_inner(),
                        login,
                        "smoke",
                    ),
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        false
                    }
                };
                // A run left to finish keeps its pipes open: do not wait on them.
                let (diagnostic, usage_limited) = if left_running {
                    (None, false)
                } else {
                    read_command_diagnostic_with_flags(stdout_reader, stderr_reader)
                };
                return SmokeResult {
                    command_found: true,
                    succeeded: false,
                    exit_status: None,
                    duration_ms: start.elapsed().as_millis(),
                    message: if usage_limited {
                        usage_limited_smoke_message(display_name)
                    } else if program == "claude" {
                        CLAUDE_SMOKE_TIMEOUT_MESSAGE.to_string()
                    } else {
                        format!(
                        "{display_name} smoke session timed out before verification could complete."
                    )
                    },
                    diagnostic,
                    error_code: Some(
                        if usage_limited {
                            SMOKE_USAGE_LIMIT_ERROR_CODE
                        } else {
                            "smoke_timeout"
                        }
                        .to_string(),
                    ),
                    local_session_observed: local_session_observed(before_session_count),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(_) => {
                let _ = child.kill();
                return SmokeResult {
                    command_found: true,
                    succeeded: false,
                    exit_status: None,
                    duration_ms: start.elapsed().as_millis(),
                    message: format!("{display_name} smoke session could not be observed."),
                    diagnostic: None,
                    error_code: Some("smoke_observation_failed".to_string()),
                    local_session_observed: local_session_observed(before_session_count),
                };
            }
        }
    }
}

fn local_session_observed(before_session_count: Option<usize>) -> Option<bool> {
    before_session_count.map(|before| pi_session_file_count() > before)
}

fn pi_session_file_count() -> usize {
    pi_session_files().map_or(0, |files| files.len())
}

struct PiSessionCensus {
    root: OpenPiSessionRoot,
    files: BTreeSet<PathBuf>,
}

fn pi_session_files() -> Result<BTreeSet<PathBuf>, LocalApiError> {
    Ok(pi_session_census()?
        .map(|census| census.files)
        .unwrap_or_default())
}

fn pi_session_census() -> Result<Option<PiSessionCensus>, LocalApiError> {
    let Some(root) = open_pi_session_root()? else {
        return Ok(None);
    };
    let files = pi_session_files_for_root(&root)?;
    Ok(Some(PiSessionCensus { root, files }))
}

fn prepare_pi_live_session_census() -> Result<PiSessionCensus, LocalApiError> {
    let root = open_or_create_pi_session_root()?;
    let files = pi_session_files_for_root(&root)?;
    Ok(PiSessionCensus { root, files })
}

#[cfg(test)]
fn pi_session_files_in(root: &Path) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    let Some(root) = open_pi_session_root_direct(root)? else {
        return Ok(BTreeSet::new());
    };
    pi_session_files_for_root(&root)
}

/// Every Pi session file under `root`, as a complete set or a refusal. The
/// walk never follows a symlink, so it cannot loop; the tree's own size is
/// the only bound.
fn pi_session_files_for_root(root: &OpenPiSessionRoot) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    verify_pi_session_root_path_identity(root)?;
    let mut files = BTreeSet::new();
    collect_pi_session_files(&root.path, &mut files)?;
    verify_pi_session_root_path_identity(root)?;
    validate_discovered_pi_session_files(root, files)
}

fn validate_discovered_pi_session_files(
    root: &OpenPiSessionRoot,
    files: BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, LocalApiError> {
    let mut validated = BTreeSet::new();
    for path in files {
        let file = open_pi_session_file_beneath_root(root, &path).map_err(|_| {
            pi_session_import_refused("session tree changed during bounded discovery")
        })?;
        let metadata = file.metadata().map_err(|_| {
            pi_session_import_refused("session tree changed during bounded discovery")
        })?;
        if !metadata.is_file() {
            return Err(pi_session_import_refused(
                "session tree changed during bounded discovery",
            ));
        }
        validated.insert(path);
    }
    verify_pi_session_root_path_identity(root)?;
    Ok(validated)
}

#[cfg(unix)]
fn verify_pi_session_root_path_identity(root: &OpenPiSessionRoot) -> Result<(), LocalApiError> {
    let opened = root
        .directory
        .metadata()
        .map_err(|_| pi_session_import_refused("session root identity could not be verified"))?;
    let current = fs::metadata(&root.path)
        .map_err(|_| pi_session_import_refused("session root changed during bounded discovery"))?;
    if !current.is_dir() || opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(pi_session_import_refused(
            "session root changed during bounded discovery",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_pi_session_root_path_identity(root: &OpenPiSessionRoot) -> Result<(), LocalApiError> {
    let _ = root;
    require_pi_session_import_platform_support()
}

fn collect_pi_session_files(
    path: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), LocalApiError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        pi_session_import_refused("session traversal could not inspect a directory entry")
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    };
    if metadata.is_file() {
        if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
            files.insert(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(path)
        .map_err(|_| pi_session_import_refused("session traversal could not open a directory"))?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            pi_session_import_refused("session traversal could not read a directory entry")
        })?;
        collect_pi_session_files(&entry.path(), files)?;
    }
    Ok(())
}

fn new_pi_route_session_files(before: &PiSessionCensus) -> Result<Vec<PathBuf>, LocalApiError> {
    Ok(pi_session_files_for_root(&before.root)?
        .difference(&before.files)
        .cloned()
        .collect())
}

/// Local Pi session files modified at or after `since`. The passive
/// (no-live-smoke) subscription-OAuth verify path uses only their presence as
/// local evidence; it never runs `pi` and never uploads or reads transcript
/// contents (the direct Pi import endpoint is retired).
fn recent_pi_session_files(since: SystemTime) -> Result<Option<Vec<PathBuf>>, LocalApiError> {
    let Some(root) = open_pi_session_root()? else {
        return Ok(None);
    };
    let files = pi_session_files_for_root(&root)?;
    pi_session_files_modified_since(&root, files, since).map(Some)
}

/// Keep only session files whose on-disk mtime is at or after `since`. Files
/// whose metadata can't be read are dropped (treated as not-recent), matching
/// the conservative behavior of the live census. Pure helper so the mtime
/// bound used by the passive Pi route verifier is unit-testable without the
/// network calls.
fn pi_session_files_modified_since(
    root: &OpenPiSessionRoot,
    files: impl IntoIterator<Item = PathBuf>,
    since: SystemTime,
) -> Result<Vec<PathBuf>, LocalApiError> {
    let mut recent = Vec::new();
    for path in files {
        let file = match open_pi_session_file_beneath_root(root, &path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(pi_session_import_refused(
                    "session tree changed during recent-file selection",
                ))
            }
        };
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|_| {
                pi_session_import_refused("session tree changed during recent-file selection")
            })?;
        if modified >= since {
            recent.push(path);
        }
    }
    verify_pi_session_root_path_identity(root)?;
    Ok(recent)
}

fn pi_session_import_refused(reason: &str) -> LocalApiError {
    LocalApiError::LocalOperationFailed(format!("Pi session import refused: {reason}"))
}

const fn pi_session_import_supported_on_target() -> bool {
    cfg!(unix)
}

fn require_pi_session_import_platform_support() -> Result<(), LocalApiError> {
    if pi_session_import_supported_on_target() {
        Ok(())
    } else {
        Err(pi_session_import_refused(
            PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON,
        ))
    }
}

struct OpenPiSessionRoot {
    path: PathBuf,
    directory: fs::File,
}

fn open_pi_session_root() -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    let home = home_path("");
    open_pi_session_root_from_home(&home, &crate::agent_status::pi_sessions_dir(&home))
}

fn open_or_create_pi_session_root() -> Result<OpenPiSessionRoot, LocalApiError> {
    require_pi_session_import_platform_support()?;
    let home = home_path("");
    open_or_create_pi_session_root_from_home_io(&home, &crate::agent_status::pi_sessions_dir(&home))
        .map_err(|_| pi_session_import_refused("session root could not be safely established"))
}

#[cfg(test)]
fn open_pi_session_root_direct(root: &Path) -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    require_pi_session_import_platform_support()?;
    match open_pi_session_root_direct_io(root) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LocalApiError::LocalOperationFailed(error.to_string())),
    }
}

fn open_pi_session_root_from_home(
    home: &Path,
    sessions: &Path,
) -> Result<Option<OpenPiSessionRoot>, LocalApiError> {
    require_pi_session_import_platform_support()?;
    match open_pi_session_root_from_home_io(home, sessions) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LocalApiError::LocalOperationFailed(error.to_string())),
    }
}

#[cfg(unix)]
fn open_pi_session_root_direct_io(root: &Path) -> std::io::Result<OpenPiSessionRoot> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(root)?;
    Ok(OpenPiSessionRoot {
        path: root.to_path_buf(),
        directory,
    })
}

/// The components of `sessions` below `home`, walked one by one from the
/// trusted home directory. A sessions directory outside `home`, relative, or
/// with `..` is refused, and never as NotFound, so neither open path reports
/// it as "no root". (`Path` drops interior `.` components.)
#[cfg(unix)]
fn pi_session_components<'a>(
    home: &Path,
    sessions: &'a Path,
) -> std::io::Result<Vec<&'a std::ffi::OsStr>> {
    let outside = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory is not below the home directory",
        )
    };
    sessions
        .strip_prefix(home)
        .map_err(|_| outside())?
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(outside()),
        })
        .collect()
}

#[cfg(unix)]
fn open_pi_session_root_from_home_io(
    home: &Path,
    sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    walk_pi_session_root_from_home(home, sessions, open_pi_directory_component)
}

#[cfg(unix)]
fn open_or_create_pi_session_root_from_home_io(
    home: &Path,
    sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    walk_pi_session_root_from_home(home, sessions, open_or_create_pi_directory_component)
}

/// Walks `sessions` one component at a time from the trusted home directory,
/// each opened by `open`.
#[cfg(unix)]
fn walk_pi_session_root_from_home(
    home: &Path,
    sessions: &Path,
    open: fn(&fs::File, &std::ffi::OsStr) -> std::io::Result<fs::File>,
) -> std::io::Result<OpenPiSessionRoot> {
    let components = pi_session_components(home, sessions)?;
    let trusted_home = open_pi_session_root_direct_io(home)?;
    let mut directory = trusted_home.directory;
    let mut path = home.to_path_buf();
    for component in components {
        directory = open(&directory, component)?;
        path.push(component);
    }
    Ok(OpenPiSessionRoot { path, directory })
}

#[cfg(unix)]
fn open_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<fs::File> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory contains a NUL byte",
        )
    })?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_or_create_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<fs::File> {
    open_or_create_pi_directory_component_with(directory, name, mkdir_pi_directory_component)
}

#[cfg(unix)]
fn open_or_create_pi_directory_component_with<Mkdir>(
    directory: &fs::File,
    name: &std::ffi::OsStr,
    mkdir: Mkdir,
) -> std::io::Result<fs::File>
where
    Mkdir: FnOnce(&fs::File, &std::ffi::OsStr) -> std::io::Result<()>,
{
    match open_pi_directory_component(directory, name) {
        Ok(opened) => Ok(opened),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(create_error) = mkdir(directory, name) {
                if create_error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(create_error);
                }
            }
            // Always reopen through the held parent descriptor. This accepts a
            // benign EEXIST race only when the winner created a real directory;
            // O_NOFOLLOW refuses a symlink or other replacement.
            open_pi_directory_component(directory, name)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn mkdir_pi_directory_component(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Pi session directory contains a NUL byte",
        )
    })?;
    let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
    if created < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn open_pi_session_root_direct_io(_root: &Path) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
fn open_pi_session_root_from_home_io(
    _home: &Path,
    _sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
fn open_or_create_pi_session_root_from_home_io(
    _home: &Path,
    _sessions: &Path,
) -> std::io::Result<OpenPiSessionRoot> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(unix)]
fn open_pi_session_file_beneath_root(
    root: &OpenPiSessionRoot,
    path: &Path,
) -> std::io::Result<fs::File> {
    let relative = path.strip_prefix(&root.path).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Pi session file escaped its session root",
        )
    })?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Pi session file is not root-relative",
        ));
    }

    let mut directory = root.directory.try_clone()?;
    for (position, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("components validated above")
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Pi session file contains a NUL byte",
            )
        })?;
        let is_final = position + 1 == components.len();
        let flags = if is_final {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let opened = unsafe { fs::File::from_raw_fd(fd) };
        if is_final {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!("non-empty component list returns its final object")
}

#[cfg(not(unix))]
fn open_pi_session_file_beneath_root(
    _root: &OpenPiSessionRoot,
    _path: &Path,
) -> std::io::Result<fs::File> {
    Err(pi_session_import_unsupported_io_error())
}

#[cfg(not(unix))]
fn pi_session_import_unsupported_io_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON,
    )
}

fn emit_api_key_verification_marker(
    otlp_endpoint: &str,
    ingest_key: &str,
    source: &SourceKind,
    key_id: &str,
    organization_id: Option<&str>,
) -> Result<String, LocalApiError> {
    let url = otlp_metrics_url(otlp_endpoint)?;
    let marker_id = format!("m3-{}-{}", source_slug(source), current_millis());
    let body = verification_marker_body(
        source,
        None,
        None,
        &marker_id,
        Some(key_id),
        organization_id,
    );
    let _: serde_json::Value = backend_post_json(
        &url,
        &body,
        &[
            ("X-API-Key", ingest_key),
            (VERIFICATION_MARKER_HEADER, "true"),
        ],
    )?;
    Ok(marker_id)
}

fn verification_marker_body(
    source: &SourceKind,
    setup_run_id: Option<&str>,
    machine: Option<&MachineIdentity>,
    marker_id: &str,
    key_id: Option<&str>,
    organization_id: Option<&str>,
) -> serde_json::Value {
    let mut attributes = vec![
        json!({"key": VERIFICATION_MARKER_ATTRIBUTE, "value": {"boolValue": true}}),
        json!({"key": "ottto.source", "value": {"stringValue": source_slug(source)}}),
        json!({"key": "ottto.marker_id", "value": {"stringValue": marker_id}}),
    ];
    if let Some(setup_run_id) = setup_run_id {
        attributes.push(json!({
            "key": "ottto.setup_run_id",
            "value": {"stringValue": setup_run_id}
        }));
    }
    if let Some(machine) = machine {
        attributes.push(json!({
            "key": "ottto.machine_id",
            "value": {"stringValue": machine.machine_id.as_str()}
        }));
    }
    if let Some(key_id) = key_id {
        attributes.push(json!({
            "key": "ottto.key_id",
            "value": {"stringValue": key_id}
        }));
    }
    if let Some(organization_id) = organization_id {
        attributes.push(json!({
            "key": "ottto.organization_id",
            "value": {"stringValue": organization_id}
        }));
    }
    json!({
        "resourceMetrics": [{
            "scopeMetrics": [{
                "metrics": [{
                    "name": VERIFICATION_MARKER_METRIC_NAME,
                    "sum": {
                        "dataPoints": [{
                            "asInt": "0",
                            "attributes": attributes
                        }]
                    }
                }]
            }]
        }]
    })
}

fn otlp_metrics_url(raw_endpoint: &str) -> Result<String, LocalApiError> {
    let endpoint = raw_endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(LocalApiError::InvalidRequest(
            "otlp_endpoint cannot be empty".to_string(),
        ));
    }
    if !is_trusted_otlp_endpoint(endpoint) {
        return Err(LocalApiError::NetworkUnavailable);
    }
    if endpoint.ends_with("/v1/metrics") {
        return Ok(endpoint.to_string());
    }
    if endpoint.ends_with("/v1") {
        return Ok(format!("{endpoint}/metrics"));
    }
    Ok(format!("{endpoint}/v1/metrics"))
}

fn is_trusted_otlp_endpoint(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }
    value == DEFAULT_API_BASE_URL
        || value.starts_with(&format!("{DEFAULT_API_BASE_URL}/"))
        || value == DIRECT_API_BASE_URL
        || value.starts_with(&format!("{DIRECT_API_BASE_URL}/"))
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"))
        || has_loopback_http_origin(value, "localhost")
        || has_loopback_http_origin(value, "127.0.0.1")
}

fn has_loopback_http_origin(value: &str, host: &str) -> bool {
    let prefix = format!("http://{host}");
    let Some(rest) = value.strip_prefix(&prefix) else {
        return false;
    };
    rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')
}

fn no_fresh_telemetry_code(source: &SourceKind, smoke: &SmokeResult) -> &'static str {
    if source == &SourceKind::Pi && smoke.local_session_observed == Some(true) {
        "pi_session_created_not_uploaded"
    } else if source == &SourceKind::Pi {
        "pi_no_local_session_created"
    } else {
        "no_fresh_telemetry"
    }
}

fn verification_failure_code(
    source: &SourceKind,
    smoke: &SmokeResult,
    verification: &SetupRunVerificationResponse,
) -> String {
    verification
        .error_code
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| no_fresh_telemetry_code(source, smoke).to_string())
}

fn verification_failure_message(
    source: &SourceKind,
    smoke: &SmokeResult,
    code: &str,
    clear_condition: Option<&str>,
) -> String {
    if code == "telemetry_disabled_by_admin" {
        return telemetry_disabled_by_admin_message(source);
    }
    if code == no_fresh_telemetry_code(source, smoke) {
        return no_fresh_telemetry_message(source, smoke);
    }
    if let Some(clear_condition) = clear_condition
        .map(str::trim)
        .filter(|condition| !condition.is_empty())
    {
        return format!(
            "{} verification could not complete. {}",
            source_display_name(source),
            clear_condition
        );
    }
    no_fresh_telemetry_message(source, smoke)
}

fn telemetry_disabled_by_admin_message(source: &SourceKind) -> String {
    format!(
        "{} telemetry is turned off in this workspace. Turn telemetry on in Ottto, then retry Verify.",
        source_display_name(source)
    )
}

fn read_command_diagnostic_with_flags(
    stdout_reader: Option<mpsc::Receiver<String>>,
    stderr_reader: Option<mpsc::Receiver<String>>,
) -> (Option<String>, bool) {
    let stderr = collect_pipe_raw(stderr_reader);
    let stdout = collect_pipe_raw(stdout_reader);
    let raw = match (stderr, stdout) {
        (Some(stderr), Some(stdout)) => Some(format!("{stderr}; stdout: {stdout}")),
        (Some(stderr), None) => Some(stderr),
        (None, Some(stdout)) => Some(stdout),
        (None, None) => None,
    };
    let usage_limited = command_diagnostic_is_usage_limited(raw.as_deref());
    let diagnostic = raw.as_deref().and_then(redact_command_diagnostic);
    (diagnostic, usage_limited)
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

fn collect_pipe_raw(reader: Option<mpsc::Receiver<String>>) -> Option<String> {
    let output = reader
        .and_then(|receiver| receiver.recv_timeout(PIPE_DRAIN_TIMEOUT).ok())
        .unwrap_or_default();
    (!output.trim().is_empty()).then_some(output)
}

fn redact_command_diagnostic(input: &str) -> Option<String> {
    let compact = input
        .split_whitespace()
        .take(80)
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return None;
    }
    let mut redacted = redact_inline(&compact);
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            redacted = redacted.replace(&home, "~");
        }
    }
    let sanitized = redacted
        .split_whitespace()
        .map(|token| {
            let trimmed = token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}'
                )
            });
            let command_token = trimmed.trim_end_matches(['.', ':']);
            if command_token == "/login" {
                token
            } else if trimmed.starts_with('/')
                || trimmed.starts_with("~/")
                || trimmed.starts_with("file:/")
            {
                "[path]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(truncate_diagnostic(&sanitized))
}

fn truncate_diagnostic(value: &str) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 280;
    if value.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return value.to_string();
    }
    let mut truncated = value.chars().take(MAX_DIAGNOSTIC_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn command_diagnostic_is_usage_limited(diagnostic: Option<&str>) -> bool {
    diagnostic.is_some_and(crate::text_indicates_usage_limited)
}

fn command_diagnostic_requires_claude_reauth(diagnostic: Option<&str>) -> bool {
    let Some(diagnostic) = diagnostic else {
        return false;
    };
    let normalized = diagnostic.to_ascii_lowercase();
    normalized.contains("not logged in")
        || normalized.contains("not signed in")
        || normalized.contains("oauth session expired")
        || normalized.contains("oauth token expired")
        || (normalized.contains("token is expired")
            && (normalized.contains("sign in again") || normalized.contains("/login")))
        || (normalized.contains("failed to authenticate")
            && normalized.contains("could not be refreshed"))
}

fn classify_source_smoke_failure(source: &SourceKind, result: &mut SmokeResult) {
    if matches!(source, SourceKind::ClaudeCode)
        && !result.succeeded
        && command_diagnostic_requires_claude_reauth(result.diagnostic.as_deref())
    {
        result.error_code = Some(CLAUDE_OAUTH_REAUTH_REQUIRED_CODE.to_string());
        let diagnostic = result
            .diagnostic
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        result.message = if diagnostic.contains("not logged in") || diagnostic.contains("not signed in") {
            "Claude Code is not signed in. Open Claude Code, sign in, then retry Verify. Ottto itself is still connected."
        } else {
            "Claude Code sign-in expired. Open Claude Code, sign in again, then retry Verify. Ottto itself is still connected."
        }.to_string();
    }
}

fn usage_limited_smoke_message(display_name: &str) -> String {
    format!("{display_name} is signed in, but its usage limit is reached. Wait for quota to reset or update usage, then retry Verify.")
}

fn smoke_failure_verification_result(
    source: SourceKind,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    smoke_failure_verification_result_with_config(source, config, smoke, smoke_after)
}

fn smoke_failure_verification_result_with_config(
    source: SourceKind,
    config: SourceConfigState,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceVerificationResult {
    if !smoke.command_found {
        // Presence was granted by config or usage metadata (desktop-app-only
        // installs), but the CLI binary itself cannot be executed. Local
        // session files keep syncing, so a hard `Failed` (blocking
        // `verify_failed` + telemetry blocker) would be both wrong and scary.
        return cli_unavailable_verification_result(source, config);
    }
    let usage_limited = smoke.error_code.as_deref() == Some(SMOKE_USAGE_LIMIT_ERROR_CODE);
    // The quiet window held the smoke back so the login can refresh first:
    // nothing failed, the check simply waits for that.
    let refresh_pending = smoke.error_code.as_deref() == Some(CLAUDE_LOGIN_REFRESH_PENDING_CODE);
    let provider_reauth_required =
        smoke.error_code.as_deref() == Some(CLAUDE_OAUTH_REAUTH_REQUIRED_CODE);
    verification_result_with_config(
        source,
        config,
        if usage_limited
            || refresh_pending
            || smoke.error_code.as_deref() == Some(crate::agent_status::CLAUDE_OTTTO_SIGNED_IN)
        {
            SourceVerificationStatus::Warning
        } else if provider_reauth_required {
            SourceVerificationStatus::ReconnectRequired
        } else {
            SourceVerificationStatus::Failed
        },
        false,
        0,
        None,
        None,
        smoke_after,
        smoke
            .error_code
            .as_deref()
            .unwrap_or("smoke_command_failed"),
        &smoke.message,
    )
}

/// Whether the source's CLI binary is genuinely present on this machine, using
/// the canonical presence contract (binary found, or — for Codex/Pi — a genuine
/// user config directory). Claude requires the binary: a lone
/// `~/.claude/settings.json` that Ottto's own patch writes does not count. Used
/// to short-circuit verification before running a doomed smoke.
fn source_binary_present(source: &SourceKind) -> bool {
    crate::agent_configs::detection::source_present_locally(source)
}

/// A non-blocking verification result for a source whose data/config is
/// present on this Mac but whose CLI binary cannot be found or executed — the
/// desktop-app-only shape (for example Codex used through the ChatGPT desktop
/// app, or a Claude Code desktop install whose vendored binary moved). Session
/// data keeps syncing from local files; only the live CLI check is
/// unavailable, so this uses the dedicated `agent_cli_unavailable` code that
/// projects as a visible soft warning instead of a blocking `verify_failed`.
fn cli_unavailable_verification_result(
    source: SourceKind,
    config: SourceConfigState,
) -> SourceVerificationResult {
    let name = source_display_name(&source);
    let binary = crate::agent_configs::detection::source_binary_name(&source);
    let text = format!(
        "Ottto keeps syncing {name} activity from this Mac's local session data, but couldn't find the `{binary}` command-line tool to run a live check. Install the {name} CLI on this Mac, then run Verify.",
    );
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Warning,
        false,
        0,
        None,
        None,
        None,
        AGENT_CLI_UNAVAILABLE_CODE,
        &text,
    )
}

/// A clean, non-blocking verification result for a source that is not installed
/// on this machine. Uses a dedicated `source_not_installed` code so the health
/// projection renders it as informational `not_found` (finish setup) rather than
/// a blocking `verify_failed`/`repair_required` telemetry problem.
fn not_installed_verification_result(
    source: SourceKind,
    config: SourceConfigState,
) -> SourceVerificationResult {
    let text = format!(
        "{} is not installed on this Mac, so there is nothing to verify. Install {} on this Mac to start sending telemetry, or leave it off here.",
        source_display_name(&source),
        source_display_name(&source),
    );
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Warning,
        false,
        0,
        None,
        None,
        None,
        SOURCE_NOT_INSTALLED_CODE,
        &text,
    )
}

fn smoke_result_metadata(smoke: &SmokeResult) -> serde_json::Value {
    json!({
        "command_found": smoke.command_found,
        "exit_status": smoke.exit_status,
        "duration_ms": smoke.duration_ms,
        "diagnostic": smoke.diagnostic.clone(),
        "local_session_observed": smoke.local_session_observed,
    })
}

fn pi_route_summary_metadata(result: &SourceVerificationResult) -> serde_json::Value {
    let routes_total = result.route_results.len();
    let routes_verified = result
        .route_results
        .iter()
        .filter(|route| route.verified)
        .count();
    json!({
        "source": source_slug(&SourceKind::Pi),
        "status": verification_status_slug(&result.status),
        "records_seen": result.records_seen,
        "last_record_id": result.last_record_id,
        "last_received_at": result.last_received_at,
        "smoke_after": result.smoke_after,
        "routes_total": routes_total,
        "routes_verified": routes_verified,
        "routes_failed": routes_total.saturating_sub(routes_verified),
        "route_results": result.route_results,
        "error_code": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(result.message.code) },
        "error_message": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(result.message.text.clone()) },
    })
}

fn setup_scan_sources(requested_sources: Vec<SourceKind>) -> Vec<SourceKind> {
    let source_filter = if requested_sources.is_empty() {
        vec![SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi]
    } else {
        requested_sources
    };
    source_filter
        .into_iter()
        .filter(|source| !setup_source_paused(source))
        .collect()
}

fn build_local_scan(
    machine: &MachineIdentity,
    requested_sources: Vec<SourceKind>,
) -> SetupScanPayload {
    let source_filter = setup_scan_sources(requested_sources);
    let mut machine_json = BTreeMap::new();
    machine_json.insert("id".to_string(), json!(machine.machine_id));
    machine_json.insert("name".to_string(), json!(machine.display_name));
    machine_json.insert(
        "platform".to_string(),
        json!(operating_system_slug(&machine.os)),
    );
    machine_json.insert("arch".to_string(), json!(machine.arch));

    let mut companion = BTreeMap::new();
    companion.insert("client_name".to_string(), json!(OTTTO_CLIENT_NAME));
    companion.insert("protocol_version".to_string(), json!(PROTOCOL_VERSION));
    companion.insert(
        "local_platform_version".to_string(),
        json!(machine.local_platform_version),
    );
    companion.insert(
        "capabilities".to_string(),
        json!({
            "deeplink": { "registered": true },
            "setup_run": true,
            "smoke_verification": true,
        }),
    );

    let mut service = BTreeMap::new();
    service.insert("state".to_string(), json!("running"));
    service.insert("socket".to_string(), json!("available"));

    SetupScanPayload {
        machine: machine_json,
        companion,
        relay_runtime: BTreeMap::from([("state".to_string(), json!("unknown"))]),
        service,
        sources: source_filter.iter().map(scan_source).collect(),
        missing_fields: Vec::new(),
    }
}

fn scan_source(source: &SourceKind) -> SetupScanSource {
    #[cfg(test)]
    tests::SETUP_SCAN_PROBES.with(|count| count.set(count.get() + 1));
    match source {
        SourceKind::Codex => {
            let command_found = executable_exists("codex");
            let config = home_path(".codex/config.toml");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = false;
            let local_import_ready =
                (command_found || config.exists() || home_path(".codex/sessions").exists())
                    && snapshot_device_credentials_include_source("codex")
                    && codex_config_state_at(&config, "~/.codex/config.toml", "", false)
                        .drift
                        .is_empty();
            let managed_config = codex_managed_config_preview(config_body.as_deref());
            let local_import_ready = local_import_ready && !source_patch_disabled(source);
            let mut scan_entry = setup_scan_source(
                source,
                "codex",
                command_found || config.exists() || home_path(".codex/sessions").exists(),
                command_found,
                telemetry_installed,
                if local_import_ready {
                    "healthy"
                } else {
                    "needs_repair"
                },
                BTreeMap::from([
                    ("billing_provider".to_string(), json!("openai")),
                    ("model_provider".to_string(), json!("openai")),
                    ("billing_channel".to_string(), json!("subscription")),
                    ("auth_mode".to_string(), json!("oauth")),
                ]),
            );
            scan_entry.managed_config = managed_config;
            scan_entry.local_import_ready = Some(local_import_ready);
            scan_entry.live_telemetry_required = Some(false);
            scan_entry
        }
        SourceKind::ClaudeCode => {
            let command_found = executable_exists("claude");
            let config = home_path(".claude/settings.json");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = config_body
                .as_deref()
                .is_some_and(claude_code_telemetry_config_installed);
            let managed_config = claude_managed_config_preview(config_body.as_deref());
            let mut scan_entry = setup_scan_source(
                source,
                "claude_code",
                command_found || config.exists(),
                command_found,
                telemetry_installed,
                if telemetry_installed {
                    "healthy"
                } else {
                    "needs_repair"
                },
                BTreeMap::from([
                    ("billing_provider".to_string(), json!("anthropic")),
                    ("model_provider".to_string(), json!("anthropic")),
                    ("billing_channel".to_string(), json!("subscription")),
                    ("auth_mode".to_string(), json!("oauth")),
                ]),
            );
            scan_entry.managed_config = managed_config;
            scan_entry
        }
        SourceKind::Pi => {
            let command_found = executable_exists("pi");
            let present = crate::agent_configs::detection::source_present_locally(source);
            let telemetry_installed = snapshot_device_credentials_include_source("pi");
            setup_scan_source(
                source,
                "pi",
                present,
                command_found,
                telemetry_installed,
                if telemetry_installed {
                    "healthy"
                } else if present {
                    "needs_repair"
                } else {
                    "not_found"
                },
                BTreeMap::new(),
            )
        }
    }
}

fn setup_scan_source(
    source_kind: &SourceKind,
    source: &'static str,
    detected: bool,
    installed: bool,
    telemetry_installed: bool,
    local_health: &'static str,
    attribution_guess: BTreeMap<String, serde_json::Value>,
) -> SetupScanSource {
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    SetupScanSource {
        source,
        captured_at: captured_at.clone(),
        detected,
        installed,
        telemetry_installed,
        local_health,
        missing_fields: Vec::new(),
        attribution_guess,
        agent_status: crate::agent_status_refresh::setup_snapshot(
            source_kind,
            captured_at,
            expires_at,
        ),
        managed_config: None,
        local_import_ready: None,
        live_telemetry_required: None,
    }
}

const MANAGED_CONFIG_PREVIEW_MAX_LINES: usize = 40;
const MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH: usize = 240;

/// Mask token-shaped content in one managed-config line. Never trusts a
/// specific format: long opaque character runs, anything after "bearer", and
/// values of secret-bearing keys (key/token/secret/header/authorization) are
/// all replaced. The backend re-sanitizes on ingest as defense-in-depth.
fn redact_managed_config_line(line: &str) -> String {
    let mut redacted = String::new();
    let mut token = String::new();
    fn flush(token: &mut String, out: &mut String) {
        // Long opaque runs are masked, but pure UPPER_SNAKE runs are env-key
        // names (OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is 32 chars), not secrets.
        let looks_like_env_key = token
            .chars()
            .all(|character| character.is_ascii_uppercase() || character == '_');
        if token.len() >= 32 && !looks_like_env_key {
            out.push_str("…redacted…");
        } else {
            out.push_str(token);
        }
        token.clear();
    }
    for character in line.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '_' | '-') {
            token.push(character);
        } else {
            flush(&mut token, &mut redacted);
            redacted.push(character);
        }
    }
    flush(&mut token, &mut redacted);

    let lowered = redacted.to_ascii_lowercase();
    if let Some(index) = lowered.find("bearer") {
        redacted.truncate(index + "bearer".len());
        redacted.push_str(" …redacted…");
    }
    if let Some(delimiter_index) = redacted.find(['=', ':']) {
        let key = redacted[..delimiter_index].to_ascii_lowercase();
        if ["key", "token", "secret", "header", "authorization"]
            .iter()
            .any(|marker| key.contains(marker))
        {
            let delimiter = redacted[delimiter_index..].chars().next().unwrap_or('=');
            redacted = format!("{}{delimiter} …redacted…", &redacted[..delimiter_index]);
        }
    }
    redacted
}

/// Redacted preview of the Ottto-managed fence region for the scan payload.
/// `path_label` is a home-relative label ("~/.codex/config.toml") so machine
/// user names never leave the device. Returns `None` when the file is
/// missing or holds no complete fence.
/// Ottto-managed env keys in `~/.claude/settings.json`, in write order (see
/// `claude_code_relay_env_with_base`). Claude Code's config is JSON, so the
/// fence-based extractor can never apply; the preview instead renders the
/// managed keys as they actually exist on disk.
const CLAUDE_MANAGED_ENV_KEYS: [&str; 13] = [
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_RESOURCE_ATTRIBUTES",
];

/// Redacted preview of the Ottto-managed env keys inside
/// `~/.claude/settings.json`. Reports what is really on disk (never the
/// template): only keys present in the file appear, and values ride through
/// the same redaction as the fence path. Returns `None` when the file is
/// missing, unparseable, or holds none of the managed keys.
fn claude_managed_config_preview(body: Option<&str>) -> Option<serde_json::Value> {
    let body = body?;
    let settings: serde_json::Value = serde_json::from_str(body).ok()?;
    let env = settings.get("env")?.as_object()?;
    let mut lines: Vec<String> = Vec::new();
    for key in CLAUDE_MANAGED_ENV_KEYS {
        let Some(value) = env.get(key) else {
            continue;
        };
        let rendered = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let line: String = format!("{key} = \"{rendered}\"")
            .chars()
            .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
            .collect();
        lines.push(redact_managed_config_line(&line));
    }
    if lines.is_empty() {
        return None;
    }
    Some(json!({
        "path": "~/.claude/settings.json",
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": lines,
    }))
}

/// Redacted preview of the Ottto-managed region in `~/.codex/config.toml`.
/// Handles both on-disk shapes: the legacy `# ottto:start/end` fenced block,
/// and the current unfenced managed `otel` table (dotted `otel.*` keys or
/// `[otel]`/`[otel.*]` sections) that `patch_existing_codex_otel_table`
/// maintains. Returns `None` when the file is missing or holds no managed
/// region.
fn codex_managed_config_preview(body: Option<&str>) -> Option<serde_json::Value> {
    let body = body?;
    if let Some(preview) = managed_config_preview("~/.codex/config.toml", Some(body)) {
        return Some(preview);
    }
    let mut lines: Vec<String> = Vec::new();
    let mut inside_otel_section = false;
    for line in body.lines() {
        if lines.len() >= MANAGED_CONFIG_PREVIEW_MAX_LINES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .trim_matches('"');
            inside_otel_section = name == "otel" || name.starts_with("otel.");
            if !inside_otel_section {
                continue;
            }
        } else if !inside_otel_section && !trimmed.starts_with("otel.") {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let capped: String = line
            .chars()
            .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
            .collect();
        lines.push(redact_managed_config_line(&capped));
    }
    if lines.is_empty() {
        return None;
    }
    Some(json!({
        "path": "~/.codex/config.toml",
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": lines,
    }))
}

fn managed_config_preview(path_label: &str, body: Option<&str>) -> Option<serde_json::Value> {
    let body = body?;
    let lines = crate::agent_configs::fence::extract_fence_lines(body)?;
    let redacted: Vec<String> = lines
        .iter()
        .take(MANAGED_CONFIG_PREVIEW_MAX_LINES)
        .map(|line| {
            let capped: String = line
                .chars()
                .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
                .collect();
            redact_managed_config_line(&capped)
        })
        .collect();
    Some(json!({
        "path": path_label,
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": redacted,
    }))
}

fn read_optional_to_string(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path).ok()
}

#[cfg(test)]
fn codex_config_has_relay_otel(body: &str) -> bool {
    codex_config_relay_port(body).is_some()
}

#[cfg(test)]
fn codex_config_relay_port(body: &str) -> Option<u16> {
    let Ok(document) = body.parse::<DocumentMut>() else {
        return None;
    };
    let otel = document.get("otel").and_then(Item::as_table)?;
    let prompt_logging_disabled = otel
        .get("log_user_prompt")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        == Some(false);
    if !prompt_logging_disabled {
        return None;
    }
    let logs = codex_exporter_relay_port(otel, "exporter", "logs")?;
    let traces = codex_exporter_relay_port(otel, "trace_exporter", "traces")?;
    let metrics = codex_exporter_relay_port(otel, "metrics_exporter", "metrics")?;
    if logs == traces && traces == metrics {
        Some(logs)
    } else {
        None
    }
}

fn codex_exporter_relay_port(
    otel: &dyn toml_edit::TableLike,
    exporter_key: &str,
    signal: &str,
) -> Option<u16> {
    let otlp_http = otel
        .get(exporter_key)
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("otlp-http"))
        .and_then(Item::as_table_like)?;
    let endpoint = otlp_http
        .get("endpoint")
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())?;
    let suffix = format!("/v1/{signal}");
    if !endpoint.ends_with(&suffix) {
        return None;
    }
    let relay_base_url = endpoint.strip_suffix(&suffix)?;
    let relay_port = crate::otlp_relay::local_relay_port_from_endpoint(relay_base_url)?;
    let headers = otlp_http.get("headers").and_then(Item::as_table_like)?;
    if headers
        .get(crate::otlp_relay::LOCAL_RELAY_HEADER)
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())
        == Some(crate::otlp_relay::CODEX_RELAY_SOURCE)
    {
        Some(relay_port)
    } else {
        None
    }
}

fn claude_code_telemetry_config_installed(body: &str) -> bool {
    let relay_port = claude_code_settings_relay_port(body);
    claude_code_settings_has_relay_env(body)
        && claude_code_settings_has_statusline_helper(body)
        && claude_statusline_wrapper_ready(&default_support_dir())
        && relay_port.is_some_and(loopback_listener_available)
        && snapshot_device_credentials_include_source(crate::otlp_relay::CLAUDE_CODE_RELAY_SOURCE)
}

fn snapshot_device_credentials_include_source(source: &str) -> bool {
    crate::snapshot_client::load_snapshot_device_credentials()
        .ok()
        .is_some_and(|(device, secret)| {
            if source == "codex" && (device.device_id.trim().is_empty() || secret.trim().is_empty())
            {
                return false;
            }
            device
                .sources
                .iter()
                .any(|configured_source| configured_source == source)
        })
}

fn claude_code_settings_has_relay_env(body: &str) -> bool {
    claude_code_settings_relay_port(body).is_some()
}

fn claude_code_settings_relay_port(body: &str) -> Option<u16> {
    let Ok(settings) = serde_json::from_str::<serde_json::Value>(body) else {
        return None;
    };
    let env = settings.get("env").and_then(|value| value.as_object())?;

    let metrics_endpoint = env
        .get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let logs_endpoint = env
        .get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let traces_endpoint = env
        .get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let metrics_port = relay_port_from_signal_endpoint(metrics_endpoint, "metrics")?;
    let logs_port = relay_port_from_signal_endpoint(logs_endpoint, "logs")?;
    let traces_port = relay_port_from_signal_endpoint(traces_endpoint, "traces")?;
    if metrics_port != logs_port || logs_port != traces_port {
        return None;
    }

    let expected = [
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".to_string()),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1".to_string()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_string()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_string()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_string()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_string()),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Ottto-Local-Relay=claude_code".to_string(),
        ),
    ];
    for (key, expected_value) in expected {
        if env.get(key).and_then(|value| value.as_str()) != Some(expected_value.as_str()) {
            return None;
        }
    }
    let metadata_valid = env
        .get("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS")
        .and_then(|value| value.as_str())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|timeout| timeout >= 10000)
        && env
            .get("OTEL_RESOURCE_ATTRIBUTES")
            .and_then(|value| value.as_str())
            .is_some_and(|attributes| {
                attributes.contains("service.name=claude-code")
                    && attributes.contains("ottto.source=claude_code")
                    && attributes.contains("ottto.machine_id=")
            });
    if metadata_valid {
        Some(metrics_port)
    } else {
        None
    }
}

fn relay_port_from_signal_endpoint(endpoint: &str, signal: &str) -> Option<u16> {
    let suffix = format!("/v1/{signal}");
    if !endpoint.ends_with(&suffix) {
        return None;
    }
    crate::otlp_relay::local_relay_port_from_endpoint(endpoint.strip_suffix(&suffix)?)
}

fn claude_code_settings_has_statusline_helper(body: &str) -> bool {
    let Ok(settings) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .is_some_and(is_ottto_statusline_command)
}

fn loopback_listener_available(port: u16) -> bool {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
}

fn home_path(relative: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(relative)
}

fn executable_exists(program: &str) -> bool {
    crate::command_env::executable_path(program).is_some()
}

fn validated_api_base_url(raw: Option<&str>) -> Result<String, LocalApiError> {
    let env_value = std::env::var("OTTTO_API_BASE_URL").ok();
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(env_value.as_deref())
        .unwrap_or(DEFAULT_API_BASE_URL)
        .trim_end_matches('/');
    if !is_trusted_api_base_url(value) {
        return Err(LocalApiError::NetworkUnavailable);
    }
    Ok(value.to_string())
}

/// Resolve the backend base URL used to validate an apps control token.
///
/// SECURITY: control-token validation is the *only* gate that authorizes an
/// `Untrusted` local peer to mutate telemetry config (write/delete the user's
/// ingest key). That validation must therefore target a backend the untrusted
/// caller cannot choose. Unlike [`validated_api_base_url`], this resolver
/// deliberately IGNORES any request-supplied `api_base_url`: a co-resident
/// local attacker could otherwise point validation at their own
/// `http://localhost:<port>` server that returns HTTP 200 and forge approval of
/// an unsigned token (the local freshness check never verifies the JWT
/// signature — see [`decode_control_token_payload`], which has no pinned public
/// key, so the trusted backend is the cryptographic gate).
///
/// The `http://localhost` / `http://127.0.0.1` allowance exists only for
/// developer and test use, so it is honored ONLY when it arrives through the
/// developer-controlled `OTTTO_API_BASE_URL` environment variable — never from
/// the request body. A request-supplied *production* base (`ottto.net/backend`
/// or `api.ottto.net`) IS honored, because it points at the real ottto backend
/// which rejects a forged/unsigned token; this keeps legitimate production
/// flows (which may target either host) working unchanged. Any other request
/// value (notably a loopback URL) is ignored and validation falls back to the
/// production default. Note the precedence is env > request(production) >
/// default: a daemon configured with a trusted `OTTTO_API_BASE_URL` validates
/// against that, and an *untrusted* env override fails closed (NetworkUnavailable)
/// rather than silently falling back to a request-supplied host.
fn control_token_validation_base_url(requested: Option<&str>) -> Result<String, LocalApiError> {
    // 1. The developer-controlled env override wins outright (it may legitimately
    //    point at a local backend for dev/test).
    if let Some(env_value) = std::env::var("OTTTO_API_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
    {
        if !is_trusted_api_base_url(&env_value) {
            return Err(LocalApiError::NetworkUnavailable);
        }
        return Ok(env_value);
    }
    // 2. With no env override, honor a request-supplied PRODUCTION backend (safe:
    //    the real backend rejects forged tokens), but IGNORE any non-production
    //    request value — that loopback redirect is the bypass we are closing.
    if let Some(production) = requested
        .map(|value| value.trim().trim_end_matches('/'))
        .filter(|value| !value.is_empty())
        .filter(|value| is_production_api_base_url(value))
    {
        return Ok(production.to_string());
    }
    // 3. Production default.
    Ok(DEFAULT_API_BASE_URL.to_string())
}

/// A production ottto backend URL (`ottto.net/backend` or `api.ottto.net`,
/// optionally with a sub-path). Unlike [`is_trusted_api_base_url`] this excludes
/// the loopback dev allowance, so it is safe to honor even from an untrusted
/// request body when deciding where to validate a control token.
pub(crate) fn is_production_api_base_url(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }
    value == DEFAULT_API_BASE_URL
        || value == DIRECT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{DEFAULT_API_BASE_URL}/"))
        || value.starts_with(&format!("{DIRECT_API_BASE_URL}/"))
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"))
}

fn is_trusted_api_base_url(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }

    value == DEFAULT_API_BASE_URL
        || value == DIRECT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"))
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

fn api_url_with_base(api_base_url: &str, path: &str) -> String {
    format!("{}{}", api_base_url.trim_end_matches('/'), path)
}

fn form_url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

fn operating_system_slug(os: &ottto_protocol::OperatingSystem) -> &'static str {
    match os {
        ottto_protocol::OperatingSystem::Macos => "macos",
        ottto_protocol::OperatingSystem::Windows => "windows",
        ottto_protocol::OperatingSystem::Linux => "linux",
        ottto_protocol::OperatingSystem::Unknown => "unknown",
    }
}

fn source_from_slug(source: &str) -> Option<SourceKind> {
    match source {
        "codex" => Some(SourceKind::Codex),
        "claude_code" | "claude-code" => Some(SourceKind::ClaudeCode),
        "pi" => Some(SourceKind::Pi),
        _ => None,
    }
}

fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn current_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn rfc3339_after_minutes(minutes: u64) -> Option<String> {
    let macos = Command::new("/bin/date")
        .args(["-u", &format!("-v+{minutes}M"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if macos.is_some() {
        return macos;
    }
    Command::new("/bin/date")
        .args([
            "-u",
            "-d",
            &format!("+{minutes} minutes"),
            "+%Y-%m-%dT%H:%M:%SZ",
        ])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn codex_local_import_verification(config: SourceConfigState) -> SourceVerificationResult {
    verification_result_with_config(SourceKind::Codex, config, SourceVerificationStatus::Warning, false, 0, None, None, None,
        "codex_local_import", "Codex uses local session import. Live telemetry is disabled; this check does not prove an upload. Restart existing Codex processes after configuration cleanup and check collector status for import progress.")
}

fn verify_source(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    repair: bool,
) -> Result<SourceVerificationResult, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let mut result = verify_source_unchecked(daemon, authorization, source, repair)?;
    attach_verification_check(&mut result);
    Ok(result)
}

fn verify_source_unchecked(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    repair: bool,
) -> Result<SourceVerificationResult, LocalApiError> {
    let tracking_generation = daemon
        .tracking_episode(&source)
        .map(|(generation, _)| generation);
    let mut config = source_config_state_for_daemon(daemon, &source)?;
    if source_requires_config_patch(&source) && source_patch_disabled(&source) {
        let message = patch_disabled_message(&source);
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::Warning,
            false,
            0,
            None,
            None,
            None,
            "patch_disabled",
            &message.text,
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    if source_requires_config_patch(&source) && !config.drift.is_empty() {
        if repair {
            execute_write_config_repair(daemon, authorization, &source)?;
            config = source_config_state_for_daemon(daemon, &source)?;
        }
        if !config.drift.is_empty() && source != SourceKind::ClaudeCode {
            let result = config_drift_verification_result(source, config, repair);
            daemon.record_verification_result(&result)?;
            return Ok(result);
        }
    }

    let status = status_for(daemon, authorization)?;
    let recoverable_pending_account =
        status.account.state == LocalAccountState::ClaimPending && status.account.user.is_some();
    if status.account.state != LocalAccountState::Connected
        && (source == SourceKind::Codex || !recoverable_pending_account)
    {
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::AccountNotConnected,
            false,
            0,
            None,
            None,
            None,
            "account_not_connected",
            "This Mac isn't connected to Ottto yet. Use Sign in in the Ottto app, then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let Some(connection) = daemon.connection_for_authorized_client()? else {
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            None,
            "reconnect_required",
            "This Mac needs a fresh Ottto sign-in. Use Sign in in the Ottto app, then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    };

    if source == SourceKind::Codex {
        let result = if !snapshot_device_credentials_include_source("codex") {
            verification_result_with_config(source, config, SourceVerificationStatus::Warning, false,
                0, None, None, None, "relay_device_not_provisioned",
                "Codex local import needs this Mac's source registration. Finish setup in Ottto, then check again.")
        } else if source_binary_present(&source) {
            codex_local_import_verification(config)
        } else {
            not_installed_verification_result(source, config)
        };
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let mut setup_credentials = match setup_run_token_for_connection(
        &connection.api_base_url,
        &connection,
    ) {
        Ok(credentials) => {
            if recoverable_pending_account {
                daemon.clear_recoverable_pending_auth_for_authorized_client()?;
            }
            credentials
        }
        Err(error) => {
            // A refresh failure proving the bound account was deleted
            // server-side frees the binding for a fresh first claim by any
            // user instead of dead-ending on reconnect/reset ceremony.
            if backend_error_indicates_account_gone(&error) {
                let _ = daemon.mark_account_not_found();
            }
            record_verify_refresh_rejection(daemon, &connection, &error);
            let result = verification_result_with_config(
                    source,
                    config,
                    SourceVerificationStatus::ReconnectRequired,
                    false,
                    0,
                    None,
                    None,
                    None,
                    "setup_run_token_missing",
                    "This Mac's local Ottto connection needs a fresh sign-in. Use Sign in in the Ottto app, then try verifying again.",
                );
            daemon.record_verification_result(&result)?;
            return Ok(result);
        }
    };
    let api_base_url = setup_credentials.connection.api_base_url.clone();

    // Before anything else: if the source CLI is genuinely not installed on this
    // Mac, there is nothing to smoke. Running the smoke anyway returns
    // "not installed or not executable", which the health projection renders as
    // a BLOCKING telemetry failure and stalls onboarding on a machine that never
    // had the app. Report a clean, non-blocking not-installed result instead.
    if !source_binary_present(&source) {
        let result = not_installed_verification_result(source.clone(), config);
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    if source == SourceKind::Pi {
        let connection = setup_credentials.connection.clone();
        let pi_token = setup_credentials.setup_run_token.clone();
        let result = match run_pi_route_verification(
            &api_base_url,
            &connection,
            &pi_token,
            tracking_generation.map(|generation| (daemon, generation)),
        ) {
            Ok(result) => result,
            Err(LocalApiError::Backend(details)) if details.status == Some(401) => {
                // Token expired mid-Pi-verify. Try a single refresh + retry.
                match refresh_setup_run_token_via_device_secret(&api_base_url, &connection) {
                    Ok(refreshed) => match run_pi_route_verification(
                        &api_base_url,
                        &refreshed.connection,
                        &refreshed.setup_run_token,
                        tracking_generation.map(|generation| (daemon, generation)),
                    ) {
                        Ok(retry) => retry,
                        Err(err) => verification_result_for_backend_error_with_config(
                            source.clone(),
                            empty_source_config(&source),
                            None,
                            &err,
                        ),
                    },
                    Err(err) => verification_result_for_backend_error_with_config(
                        source.clone(),
                        empty_source_config(&source),
                        None,
                        &err,
                    ),
                }
            }
            Err(other) => verification_result_for_backend_error_with_config(
                source.clone(),
                empty_source_config(&source),
                None,
                &other,
            ),
        };
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    // Codex/Claude verification proves telemetry by polling the backend for
    // records that the LOCAL OTLP relay forwards, and that forward requires the
    // relay device binding + relay-device-secret. On a freshly-claimed Mac those
    // are provisioned by the setup-run install action — not by claim completion,
    // and not by `ottto fix` (which only patches the agent's OTLP config) — so
    // within that window the relay drops every exported record (502) and the
    // backend poll returns 0. Running a smoke anyway and reporting
    // `no_fresh_telemetry` mis-attributes "telemetry transport is still being
    // set up" to "the agent produced no telemetry", which is what made a fresh
    // install fail to verify Codex even though the smoke ran and `fix` reported
    // success. Detect the missing provisioning up front and return an accurate,
    // actionable status instead of running a doomed smoke.
    if !relay_device_is_provisioned() {
        let result = verification_result_with_config(
            source.clone(),
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            None,
            "relay_device_not_provisioned",
            "This Mac just connected and is still finishing telemetry setup. Open the Ottto app to finish setup (or wait a moment), then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let smoke_after = current_rfc3339();
    let smoke = run_verification_smoke_prompt(daemon, &source)?;
    let result = if !smoke.succeeded
        && smoke.error_code.as_deref() == Some(CLAUDE_OAUTH_REAUTH_REQUIRED_CODE)
    {
        smoke_failure_verification_result_with_config(
            source.clone(),
            config,
            &smoke,
            Some(smoke_after.clone()),
        )
    } else if !config.drift.is_empty() {
        // Claude auth is a higher-priority source blocker than telemetry config
        // drift. Run the smoke first so an expired provider session gets the
        // source-scoped sign-in action; otherwise preserve the normal Repair
        // guidance for the outstanding drift.
        config_drift_verification_result(source.clone(), config, repair)
    } else if !smoke.succeeded {
        smoke_failure_verification_result_with_config(
            source.clone(),
            config,
            &smoke,
            Some(smoke_after.clone()),
        )
    } else {
        let _ = emit_setup_run_fast_verification_marker_with_refresh_mut(
            &api_base_url,
            &mut setup_credentials,
            &source,
            "manual_verify",
        );
        match wait_for_verification_with_refresh_mut(
            &api_base_url,
            &mut setup_credentials,
            &source,
            &smoke_after,
        ) {
            Ok(response) if response.verified => verification_result_with_config(
                source.clone(),
                config,
                SourceVerificationStatus::Verified,
                true,
                response.records_seen,
                response.last_record_id,
                response.last_received_at,
                Some(response.smoke_after),
                "verified",
                &format!("{} verification passed.", source_display_name(&source)),
            ),
            Ok(response) => {
                let failure_code = verification_failure_code(&source, &smoke, &response);
                let failure_message = verification_failure_message(
                    &source,
                    &smoke,
                    &failure_code,
                    response.clear_condition.as_deref(),
                );
                verification_result_with_config(
                    source.clone(),
                    config,
                    SourceVerificationStatus::NoFreshTelemetry,
                    false,
                    response.records_seen,
                    response.last_record_id,
                    response.last_received_at,
                    Some(response.smoke_after),
                    &failure_code,
                    &failure_message,
                )
            }
            Err(error) => {
                record_verify_refresh_rejection(daemon, &connection, &error);
                verification_result_for_backend_error_with_config(
                    source,
                    config,
                    Some(smoke_after.clone()),
                    &error,
                )
            }
        }
    };
    daemon.record_verification_result_with_tracking(
        &result,
        tracking_generation.map(|generation| (generation, smoke_after.as_str())),
    )?;
    Ok(result)
}

/// Record an authoritative terminal refresh answer met during Verify, the
/// same way agent reads do (`observe_setup_run_read`), so local health stops
/// reporting the dead run as complete and Sign-in may reconnect this Mac.
/// Anything other than a terminal refresh rejection says nothing about the
/// run and is ignored; an outcome for a since-replaced binding is dropped by
/// the daemon.
fn record_verify_refresh_rejection(
    daemon: &LocalDaemon,
    binding: &LocalConnectionBinding,
    error: &LocalApiError,
) {
    if let Some(rejection) = terminal_refresh_rejection(error) {
        let _ = daemon.record_setup_run_read_rejected(binding, rejection);
    }
}

/// Re-run source verification from inside the daemon (the background
/// re-verify loop), with the same post-verify convergence steps the manual
/// Verify command performs: refresh agent status for soft failures and push
/// the local-health projection so the app and backend see the new state on
/// their next poll instead of dwelling on a stale failure.
pub(crate) fn reverify_failed_source(
    daemon: &LocalDaemon,
    source: SourceKind,
) -> Result<SourceVerificationResult, LocalApiError> {
    let authorization = RequestAuthorization::TrustedCompanionApp;
    let result =
        crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Schedule, || {
            verify_source(daemon, &authorization, source, false)
        })?;
    if verification_result_should_refresh_agent_status(&result) {
        if let Err(error) =
            refresh_agent_status_for(daemon, &authorization, Some(result.source.clone()))
        {
            eprintln!(
                "background re-verify agent status refresh skipped: {}",
                cli_error_message(&error)
            );
        }
    }
    if let Err(error) = crate::snapshot_sync::upload_local_health_projection_now(daemon) {
        eprintln!(
            "background re-verify local health projection upload skipped: {}",
            crate::snapshot_sync::safe_error(&error)
        );
    }
    Ok(result)
}

/// True when the local OTLP relay can actually forward telemetry to the backend
/// — i.e. both the relay device binding (`FileDeviceStore`) and the
/// relay-device-secret exist. Mirrors
/// `snapshot_client::load_snapshot_device_credentials`. On a freshly-claimed Mac
/// these are provisioned asynchronously by the setup-run install action, so a
/// Codex/Claude verify uses this to avoid running a doomed smoke and reporting
/// `no_fresh_telemetry` while telemetry transport is still being set up.
fn relay_device_is_provisioned() -> bool {
    matches!(FileDeviceStore::default().load(), Ok(Some(_)))
        && KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .is_ok()
}

fn run_pi_route_verification(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    tracking: Option<(&LocalDaemon, u64)>,
) -> Result<SourceVerificationResult, LocalApiError> {
    let mut credentials = SetupRunCredentials {
        setup_run_token: setup_run_token.to_string(),
        connection: connection.clone(),
    };
    run_pi_route_verification_with_credentials(api_base_url, &mut credentials, tracking)
}

fn run_pi_route_verification_with_credentials(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    tracking: Option<(&LocalDaemon, u64)>,
) -> Result<SourceVerificationResult, LocalApiError> {
    let mut routes = read_pi_smoke_routes();
    if routes.is_empty() {
        routes.push(PiModelRoute {
            provider: "default".to_string(),
            model: "default".to_string(),
            thinking_level: None,
            classification: crate::agent_status::PiRouteClassification {
                model_provider: None,
                billing_provider: None,
                billing_channel: None,
                auth_mode: None,
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("unknown".to_string()),
            },
        });
    }

    let mut route_results = Vec::new();
    for route in &routes {
        route_results.push(run_one_pi_route_verification(
            api_base_url,
            credentials,
            route,
            tracking,
        ));
    }
    Ok(pi_route_aggregate_result(route_results))
}

fn run_one_pi_route_verification(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    route: &PiModelRoute,
    tracking: Option<(&LocalDaemon, u64)>,
) -> SourceRouteVerificationResult {
    // A subscription-OAuth route (openai-codex / anthropic / github-copilot)
    // authenticates via a single-use *rotating* refresh token that Ottto must not
    // consume. Running a live `pi` smoke would burn that token (the provider then
    // returns 401 refresh_token_reused — which also breaks the agent's own CLI),
    // and Ottto cannot re-mint it. So verify these routes PASSIVELY from telemetry
    // the local_sessions collector already uploaded, and surface an actionable
    // re-auth Warning (not a hard smoke Failed) when none is fresh. Non-OAuth
    // routes (api_key / gateway / service_account) still run a live smoke.
    if route_is_subscription_oauth(route) {
        return verify_pi_subscription_oauth_route_passively(api_base_url, credentials, route);
    }

    // The direct Pi import endpoint is retired, so Verify no longer uploads the
    // smoke transcript. The post-smoke census already ran through the held
    // pre-smoke root; a new local session without matching backend usage
    // settles as the existing local-only Warning, never as an upload success.
    let (_, smoke_after, smoke) = match run_pi_route_pre_smoke(route) {
        Ok(ready) => ready,
        Err(failed) => return *failed,
    };
    if !smoke.succeeded {
        return pi_route_result_from_smoke(route, &smoke, Some(smoke_after));
    }

    let filters = if pi_route_is_unscoped(route) {
        None
    } else {
        Some(SetupRunVerificationFilters {
            model: Some(route.model.clone()),
            model_provider: route.classification.model_provider.clone(),
            billing_provider: route.classification.billing_provider.clone(),
        })
    };
    let result = match wait_for_setup_run_verification_with_refresh_mut_timeout(
        api_base_url,
        credentials,
        &SourceKind::Pi,
        &smoke_after,
        filters.as_ref(),
        SetupVerificationTimeouts {
            wait: PI_VERIFICATION_WAIT_TIMEOUT,
            request: PI_VERIFICATION_HTTP_TIMEOUT,
        },
    ) {
        Ok(verification) => pi_route_result_from_verification(route, &smoke, verification),
        Err(error) => {
            pi_route_result_from_backend_error(route, &smoke, Some(smoke_after.clone()), &error)
        }
    };
    // Only this execution path ran a smoke and polled its own records. Passive
    // routes return above, even though they also populate smoke_after.
    if let Some((daemon, generation)) = tracking {
        let evidence = pi_route_aggregate_result(vec![result.clone()]);
        let _ = daemon.confirm_tracking_smoke(&evidence, generation, &smoke_after);
    }
    result
}

fn run_pi_route_pre_smoke(
    route: &PiModelRoute,
) -> Result<(PiSessionCensus, String, SmokeResult), Box<SourceRouteVerificationResult>> {
    run_pi_route_pre_smoke_with(
        route,
        prepare_pi_live_session_census,
        run_pi_route_smoke_prompt,
    )
}

fn run_pi_route_pre_smoke_with<Prepare, RunSmoke>(
    route: &PiModelRoute,
    prepare: Prepare,
    run_smoke: RunSmoke,
) -> Result<(PiSessionCensus, String, SmokeResult), Box<SourceRouteVerificationResult>>
where
    Prepare: FnOnce() -> Result<PiSessionCensus, LocalApiError>,
    RunSmoke: FnOnce(&PiModelRoute) -> SmokeResult,
{
    let before_session_census = match prepare() {
        Ok(census) => census,
        Err(_) => {
            eprintln!("Pi route pre-smoke session safety check failed.");
            return Err(Box::new(pi_route_pre_smoke_census_failure(route)));
        }
    };
    let smoke_after = current_rfc3339();
    let mut smoke = run_smoke(route);
    if !smoke.succeeded {
        // A failed command is already terminal for this route. Its generic
        // pathname count is not authoritative and a second filesystem error
        // must not replace the real smoke diagnostic.
        smoke.local_session_observed = None;
        return Ok((before_session_census, smoke_after, smoke));
    }
    // `run_bounded_command` retains its generic count-based Pi observation for
    // older callers, but that count reopens the pathname. Live route Verify
    // already owns a held pre-smoke root descriptor, so only a post-smoke
    // difference derived through that same descriptor can authorize local-only
    // success. A replaced/unreadable root fails before backend polling instead
    // of reclassifying another directory's pre-existing transcripts as smoke
    // evidence.
    let local_session_observed = match new_pi_route_session_files(&before_session_census) {
        Ok(files) => !files.is_empty(),
        Err(_) => {
            eprintln!("Pi route post-smoke session safety check failed.");
            return Err(Box::new(pi_route_post_smoke_census_failure(
                route,
                &smoke,
                smoke_after,
            )));
        }
    };
    smoke.local_session_observed = Some(local_session_observed);
    Ok((before_session_census, smoke_after, smoke))
}

/// Every Pi route result's route classification and billing identity hints,
/// with the no-evidence defaults most results share: failed, nothing seen, no
/// command run. Callers override only the fields that differ.
fn pi_route_result_base(route: &PiModelRoute) -> SourceRouteVerificationResult {
    let identity = pi_route_billing_identity_hints(route);
    SourceRouteVerificationResult {
        provider: pi_route_provider(route),
        model: pi_route_model(route),
        model_provider: route.classification.model_provider.clone(),
        billing_provider: route.classification.billing_provider.clone(),
        billing_channel: route.classification.billing_channel.clone(),
        auth_mode: route.classification.auth_mode.clone(),
        gateway_provider: route.classification.gateway_provider.clone(),
        subscription_product: route.classification.subscription_product.clone(),
        source_category: route.classification.source_category.clone(),
        account_identifier_hash: identity.account_identifier_hash,
        organization_identifier_hash: identity.organization_identifier_hash,
        credential_fingerprint_hash: identity.credential_fingerprint_hash,
        billing_identity_evidence: identity.billing_identity_evidence,
        billing_identity_confidence: identity.billing_identity_confidence,
        status: SourceVerificationStatus::Failed,
        verified: false,
        records_seen: 0,
        last_record_id: None,
        last_received_at: None,
        smoke_after: None,
        command_found: false,
        command_succeeded: false,
        exit_status: None,
        duration_ms: 0,
        diagnostic: None,
        error_code: None,
        local_session_observed: None,
        message: StableMessage {
            code: String::new(),
            text: String::new(),
        },
        check: None,
    }
}

fn pi_route_pre_smoke_census_failure(route: &PiModelRoute) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        error_code: Some(PI_SESSION_CENSUS_FAILED_CODE.to_string()),
        message: StableMessage {
            code: PI_SESSION_CENSUS_FAILED_CODE.to_string(),
            text: format!(
                "Pi route {} could not run a smoke because Ottto could not safely establish a complete local session baseline. Check that Pi's sessions directory is a real, readable directory, then retry Verify.",
                pi_route_label(route)
            ),
        },
        ..base
    }
}

fn pi_route_post_smoke_census_failure(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: String,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        smoke_after: Some(smoke_after),
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(PI_SESSION_CENSUS_FAILED_CODE.to_string()),
        message: StableMessage {
            code: PI_SESSION_CENSUS_FAILED_CODE.to_string(),
            text: format!(
                "Pi route {} completed smoke, but Ottto could not safely establish complete post-smoke local session evidence. No local session evidence was accepted; check that Pi's sessions directory is a real, readable directory, then retry Verify.",
                pi_route_label(route)
            ),
        },
        ..base
    }
}

/// error_code (and aggregate code) for a Pi route that has no fresh telemetry and
/// authenticates via a rotating provider OAuth token Ottto can't re-mint: the
/// recovery is a provider re-sign-in (`ottto fix --app pi` yields the steps).
const PI_OAUTH_REAUTH_CODE: &str = "pi_oauth_reauth_required";

/// Pi is accepted through local session/route evidence for now. Live telemetry
/// matching is intentionally not a hard acceptance gate until the Pi live
/// ingestion path is productized again.
const PI_LOCAL_ONLY_CODE: &str = "pi_local_only";

/// How far back to look for already-uploaded telemetry when verifying a
/// subscription-OAuth Pi route passively (we don't run a live smoke, so we treat
/// recent observed usage as the verification signal).
const PI_PASSIVE_LOOKBACK_HOURS: u32 = 6;

/// True for a Pi route whose provider OAuth token rotates on use (subscription
/// auth_mode=oauth: openai-codex / anthropic / github-copilot). These must not be
/// live-smoked.
fn route_is_subscription_oauth(route: &PiModelRoute) -> bool {
    is_subscription_oauth(
        route.classification.auth_mode.as_deref(),
        route.classification.billing_channel.as_deref(),
    )
}

fn is_subscription_oauth(auth_mode: Option<&str>, billing_channel: Option<&str>) -> bool {
    auth_mode == Some("oauth") && billing_channel == Some("subscription")
}

/// `now - hours` as an RFC3339 UTC timestamp (mirrors `current_rfc3339`'s
/// `/bin/date` approach). Falls back to "now" on failure, which simply tightens
/// the passive lookback (safe — it requires fresher telemetry).
fn rfc3339_hours_ago(hours: u32) -> String {
    Command::new("/bin/date")
        .args(["-u", &format!("-v-{hours}H"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(current_rfc3339)
}

/// Verify a subscription-OAuth Pi route without a live smoke: query the backend
/// for recently-observed usage for this route (model/provider filtered) over
/// a passive lookback window. Fresh usage -> Verified; fresh local route/account
/// evidence -> local-only verified Warning; none -> an actionable re-auth
/// Warning (never a hard smoke failure); backend error -> error result.
fn verify_pi_subscription_oauth_route_passively(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    route: &PiModelRoute,
) -> SourceRouteVerificationResult {
    let lookback = rfc3339_hours_ago(PI_PASSIVE_LOOKBACK_HOURS);
    // Recent local Pi sessions count as local route evidence so a valid OAuth
    // route with fresh local use is not mislabeled `pi_oauth_reauth_required`.
    // Only file presence and mtime are read; nothing is uploaded because the
    // direct Pi import endpoint is retired. The mtime bound matches the passive
    // lookback window. Non-fatal on error.
    let local_evidence_since = SystemTime::now()
        .checked_sub(Duration::from_secs(
            u64::from(PI_PASSIVE_LOOKBACK_HOURS) * 3600,
        ))
        .unwrap_or(UNIX_EPOCH);
    let recent_session_files = match recent_pi_session_files(local_evidence_since) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("Pi passive route session discovery failed (non-fatal): {error}");
            None
        }
    };
    let recent_local_session_observed = recent_session_files
        .as_ref()
        .is_some_and(|files| !files.is_empty());
    let local_session_observed = Some(recent_local_session_observed);
    let local_evidence_observed = pi_route_has_local_verification_evidence(
        &pi_route_billing_identity_hints(route),
        recent_local_session_observed,
    );
    let filters = if pi_route_is_unscoped(route) {
        None
    } else {
        Some(SetupRunVerificationFilters {
            model: Some(route.model.clone()),
            model_provider: route.classification.model_provider.clone(),
            billing_provider: route.classification.billing_provider.clone(),
        })
    };
    // A single query is enough: no smoke runs, so polling for 60s can't make new
    // records appear — they either already exist in the lookback window or not.
    match setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        get_setup_run_verification_with_base(
            api_base_url,
            active,
            token,
            &SourceKind::Pi,
            &lookback,
            filters.as_ref(),
        )
    }) {
        Ok(verification) if verification.verified => pi_route_passive_result(
            route,
            SourceVerificationStatus::Verified,
            true,
            verification.records_seen,
            verification.last_record_id,
            verification.last_received_at,
            Some(lookback),
            None,
            format!(
                "Pi route {} verification passed from recent usage.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Ok(_) if local_evidence_observed => pi_route_passive_result(
            route,
            SourceVerificationStatus::Warning,
            true,
            0,
            None,
            None,
            Some(lookback),
            Some(PI_LOCAL_ONLY_CODE.to_string()),
            format!(
                "Verified Pi route {} from local route/account evidence. Pi is local-only for this rotating-OAuth route; live telemetry matching is not required.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Ok(_) => pi_route_passive_result(
            route,
            SourceVerificationStatus::Warning,
            false,
            0,
            None,
            None,
            Some(lookback),
            Some(PI_OAUTH_REAUTH_CODE.to_string()),
            format!(
                "Pi route {} needs a provider re-sign-in: no recent matching usage, and Ottto can't live-probe this route. Run `ottto fix --app pi` for recovery steps.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Err(error) => pi_route_result_from_backend_error(
            route,
            &pi_passive_placeholder_smoke(local_session_observed),
            Some(lookback),
            &error,
        ),
    }
}

/// A non-run `SmokeResult` placeholder for the passive verify path (no live `pi`
/// smoke was executed) so we can reuse the existing backend-error result builder.
fn pi_passive_placeholder_smoke(local_session_observed: Option<bool>) -> SmokeResult {
    SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: None,
        duration_ms: 0,
        message: "Checked recent Pi usage; no live smoke was run for this rotating-OAuth route."
            .to_string(),
        diagnostic: None,
        error_code: Some(PI_OAUTH_REAUTH_CODE.to_string()),
        local_session_observed,
    }
}

/// Build a route result for the passive (no-live-smoke) verification path.
#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
fn pi_route_passive_result(
    route: &PiModelRoute,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    error_code: Option<String>,
    text: String,
    local_session_observed: Option<bool>,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    let code = error_code.clone().unwrap_or_else(|| "verified".to_string());
    SourceRouteVerificationResult {
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        command_found: true,
        error_code,
        local_session_observed,
        message: StableMessage { code, text },
        ..base
    }
}

/// The live route smoke. Its local session evidence comes only from the held
/// root's pre/post census, so the command itself counts nothing.
fn run_pi_route_smoke_prompt(route: &PiModelRoute) -> SmokeResult {
    let command = pi_smoke_command(Some(route));
    let result = run_bounded_command(
        command.program,
        &command.args,
        PI_SMOKE_COMMAND_TIMEOUT,
        "Pi",
        None,
    );
    let provider = match route.classification.model_provider.as_deref() {
        Some("openai") => Some(crate::provider_calls::Provider::Openai),
        Some("anthropic") => Some(crate::provider_calls::Provider::Anthropic),
        _ => None,
    };
    if let Some(provider) = provider {
        record_smoke_prompt(
            provider,
            crate::provider_calls::CallKind::PiSmokePrompt,
            pi_route_billing_identity_hints(route).account_identifier_hash,
            &result,
        );
    }
    result
}

fn pi_route_billing_identity_hints(route: &PiModelRoute) -> BillingIdentityHints {
    let auth = read_pi_agent_auth();
    pi_identity_hints_for_route(auth.as_ref(), route)
}

fn pi_route_has_local_verification_evidence(
    identity: &BillingIdentityHints,
    recent_local_session_observed: bool,
) -> bool {
    recent_local_session_observed
        || identity.billing_identity_evidence.is_some()
        || identity.account_identifier_hash.is_some()
        || identity.organization_identifier_hash.is_some()
        || identity.credential_fingerprint_hash.is_some()
}

fn pi_route_result_from_smoke(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        smoke_after,
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(
            smoke
                .error_code
                .clone()
                .unwrap_or_else(|| "smoke_command_failed".to_string()),
        ),
        local_session_observed: smoke.local_session_observed,
        message: StableMessage {
            code: smoke
                .error_code
                .clone()
                .unwrap_or_else(|| "smoke_command_failed".to_string()),
            text: format!(
                "Pi route {} failed smoke: {}",
                pi_route_label(route),
                smoke.message
            ),
        },
        ..base
    }
}

fn pi_route_result_from_verification(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    verification: SetupRunVerificationResponse,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    let local_only_verified = !verification.verified && smoke.local_session_observed == Some(true);
    let status = if verification.verified {
        SourceVerificationStatus::Verified
    } else if local_only_verified {
        SourceVerificationStatus::Warning
    } else {
        SourceVerificationStatus::NoFreshTelemetry
    };
    let code = if verification.verified {
        "verified".to_string()
    } else if local_only_verified {
        PI_LOCAL_ONLY_CODE.to_string()
    } else {
        no_fresh_telemetry_code(&SourceKind::Pi, smoke).to_string()
    };
    let text = if verification.verified {
        format!("Pi route {} verification passed.", pi_route_label(route))
    } else if local_only_verified {
        format!(
            "Pi route {} created a local session. Ottto is treating Pi as local-only; live telemetry is not required for this route.",
            pi_route_label(route)
        )
    } else {
        format!(
            "Pi route {} completed smoke, but Ottto did not receive matching usage.",
            pi_route_label(route)
        )
    };
    SourceRouteVerificationResult {
        status,
        verified: verification.verified || local_only_verified,
        records_seen: verification.records_seen,
        last_record_id: verification.last_record_id,
        last_received_at: verification.last_received_at,
        smoke_after: Some(verification.smoke_after),
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: if verification.verified {
            None
        } else {
            Some(code.clone())
        },
        local_session_observed: smoke.local_session_observed,
        message: StableMessage { code, text },
        ..base
    }
}

fn pi_route_result_from_backend_error(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceRouteVerificationResult {
    let source_result =
        verification_result_for_backend_error(SourceKind::Pi, smoke_after.clone(), error);
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        status: source_result.status,
        smoke_after,
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(source_result.message.code.clone()),
        local_session_observed: smoke.local_session_observed,
        message: StableMessage {
            code: source_result.message.code,
            text: format!(
                "Pi route {} could not be verified: {}",
                pi_route_label(route),
                source_result.message.text
            ),
        },
        ..base
    }
}

fn pi_route_aggregate_result(
    route_results: Vec<SourceRouteVerificationResult>,
) -> SourceVerificationResult {
    let total = route_results.len();
    let live_passed = route_results
        .iter()
        .filter(|route| route.verified && route.status == SourceVerificationStatus::Verified)
        .count();
    let local_only_passed = route_results
        .iter()
        .filter(|route| {
            route.verified
                && route.status == SourceVerificationStatus::Warning
                && route.error_code.as_deref() == Some(PI_LOCAL_ONLY_CODE)
        })
        .count();
    // A route awaiting a provider re-sign-in is a soft, actionable Warning — not a
    // hard smoke failure — even though it isn't verified: Ottto deliberately did
    // not (and can't safely) live-probe a rotating-OAuth route, so "no fresh
    // telemetry yet" must not aggregate to Failed.
    let reauth_pending = route_results
        .iter()
        .filter(|route| {
            !route.verified && route.error_code.as_deref() == Some(PI_OAUTH_REAUTH_CODE)
        })
        .count();
    let hard_failed = total
        .saturating_sub(live_passed)
        .saturating_sub(local_only_passed)
        .saturating_sub(reauth_pending);
    let status = if total > 0 && live_passed == total {
        SourceVerificationStatus::Verified
    } else if total > 0 && hard_failed == 0 {
        // Everything is live-verified, local-only verified, and/or awaiting re-auth.
        SourceVerificationStatus::Warning
    } else if live_passed > 0 || local_only_passed > 0 || reauth_pending > 0 {
        SourceVerificationStatus::Warning
    } else {
        SourceVerificationStatus::Failed
    };
    let all_reauth_pending =
        live_passed == 0 && local_only_passed == 0 && hard_failed == 0 && reauth_pending > 0;
    let all_local_only =
        live_passed == 0 && local_only_passed > 0 && hard_failed == 0 && reauth_pending == 0;
    let all_census_failed = total > 0
        && route_results
            .iter()
            .all(|route| route.error_code.as_deref() == Some(PI_SESSION_CENSUS_FAILED_CODE));
    let all_telemetry_disabled = total > 0
        && route_results
            .iter()
            .all(|route| route.error_code.as_deref() == Some("telemetry_disabled_by_admin"));
    let status = if all_telemetry_disabled {
        SourceVerificationStatus::NoFreshTelemetry
    } else {
        status
    };
    let (code, text): (&str, String) = match status {
        SourceVerificationStatus::Verified => {
            ("verified", format!("Verified {total} Pi model routes."))
        }
        SourceVerificationStatus::Warning if all_local_only => (
            PI_LOCAL_ONLY_CODE,
            format!(
                "Verified {local_only_passed} Pi model route(s) from local session evidence. Pi is local-only; live telemetry is not required."
            ),
        ),
        SourceVerificationStatus::Warning if all_reauth_pending => (
            PI_OAUTH_REAUTH_CODE,
            "Re-sign in to the Pi provider, then re-run Verify — Ottto can't re-mint a rotating provider OAuth token."
                .to_string(),
        ),
        SourceVerificationStatus::Warning => (
            "pi_route_warnings",
            if live_passed > 0 || local_only_passed > 0 {
                format!(
                    "Verified {live_passed} live and {local_only_passed} local-only of {total} Pi model routes; review the remaining routes."
                )
            } else {
                format!(
                    "Pi has {total} model routes awaiting review; re-sign in if a provider asks."
                )
            },
        ),
        SourceVerificationStatus::Failed if all_census_failed => (
            PI_SESSION_CENSUS_FAILED_CODE,
            "Pi verification could not safely establish complete local session evidence before or after smoke. No local session evidence was accepted; check that Pi's sessions directory is a real, readable directory, then retry Verify."
                .to_string(),
        ),
        SourceVerificationStatus::NoFreshTelemetry if all_telemetry_disabled => (
            "telemetry_disabled_by_admin",
            telemetry_disabled_by_admin_message(&SourceKind::Pi),
        ),
        _ => (
            "pi_route_smoke_failed",
            "No Pi model routes passed smoke verification.".to_string(),
        ),
    };
    let last_route = route_results
        .iter()
        .filter(|route| route.last_received_at.is_some())
        .max_by_key(|route| route.last_received_at.as_deref().unwrap_or(""));
    SourceVerificationResult {
        source: SourceKind::Pi,
        config: empty_source_config(&SourceKind::Pi),
        status,
        verified: live_passed > 0 || local_only_passed > 0,
        records_seen: route_results.iter().map(|route| route.records_seen).sum(),
        last_record_id: last_route.and_then(|route| route.last_record_id.clone()),
        last_received_at: last_route.and_then(|route| route.last_received_at.clone()),
        smoke_after: route_results
            .iter()
            .filter_map(|route| route.smoke_after.clone())
            .min(),
        message: StableMessage {
            code: code.to_string(),
            text,
        },
        route_results,
        check: None,
    }
}

fn config_drift_verification_result(
    source: SourceKind,
    config: SourceConfigState,
    repair_requested: bool,
) -> SourceVerificationResult {
    if source == SourceKind::Codex
        && config
            .drift
            .iter()
            .any(|drift| drift.key == "codex.config_toml")
    {
        return verification_result_with_config(source, config, SourceVerificationStatus::Failed,
            false, 0, None, None, None, "manual_fence_review_required",
            "Codex configuration needs manual review. Ottto left it unchanged. Review the Ottto telemetry entries and fence markers in ~/.codex/config.toml, then run Verify again.");
    }
    let missing = !config.discovered
        || config
            .drift
            .iter()
            .any(|drift| drift.key.ends_with("config_file"));
    let code = if repair_requested {
        "config_drift_after_repair"
    } else if missing {
        "config_missing"
    } else {
        "config_drift"
    };
    let text = if repair_requested {
        format!(
            "{} telemetry config still does not match the active Ottto relay after repair.",
            source_display_name(&source)
        )
    } else if missing {
        format!(
            "{} telemetry config is missing. Use Repair in the Ottto app to update it, then run Verify again.",
            source_display_name(&source)
        )
    } else {
        format!(
            "{} telemetry config does not match the active Ottto relay. Use Repair in the Ottto app to update it, then run Verify again.",
            source_display_name(&source)
        )
    };
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Failed,
        false,
        0,
        None,
        None,
        None,
        code,
        &text,
    )
}

fn verification_result_for_backend_error(
    source: SourceKind,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    verification_result_for_backend_error_with_config(source, config, smoke_after, error)
}

fn verification_result_for_backend_error_with_config(
    source: SourceKind,
    config: SourceConfigState,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceVerificationResult {
    if matches!(error, LocalApiError::SetupRunConnectionMissing) {
        return verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            smoke_after,
            "setup_run_connection_missing",
            "This Mac needs a fresh Ottto sign-in. Use Sign in in the Ottto app, then try verifying again.",
        );
    }
    if let LocalApiError::Backend(details) = error {
        if is_telemetry_disabled_by_admin_error(error) {
            return verification_result_with_config(
                source.clone(),
                config,
                SourceVerificationStatus::NoFreshTelemetry,
                false,
                0,
                None,
                None,
                smoke_after,
                "telemetry_disabled_by_admin",
                &telemetry_disabled_by_admin_message(&source),
            );
        }
        if details.status == Some(401) {
            let expired = details
                .body_excerpt
                .as_deref()
                .is_some_and(|body| body.to_ascii_lowercase().contains("expired"));
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::ReconnectRequired,
                false,
                0,
                None,
                None,
                smoke_after,
                if expired {
                    "setup_run_token_expired"
                } else {
                    "setup_run_token_invalid"
                },
                "Your Ottto session has expired. Use Sign in in the Ottto app, then try verifying again.",
            );
        }
        if details.status == Some(404) {
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::ReconnectRequired,
                false,
                0,
                None,
                None,
                smoke_after,
                "setup_run_missing",
                "We can't find an active Ottto session for this Mac. Use Sign in in the Ottto app, then try verifying again.",
            );
        }
        if details.kind == BackendErrorKind::Rejected {
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::Failed,
                false,
                0,
                None,
                None,
                smoke_after,
                "verification_service_rejected",
                "Ottto couldn't verify this source. Use Sign in in the Ottto app to refresh your session, then try again.",
            );
        }
    }
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Failed,
        false,
        0,
        None,
        None,
        smoke_after,
        "verification_service_unavailable",
        "Could not reach Ottto verification. Check your network and retry.",
    )
}

fn is_telemetry_disabled_by_admin_error(error: &LocalApiError) -> bool {
    matches!(
        error,
        LocalApiError::Backend(details)
            if details.status == Some(403)
                && backend_error_has_detail_code(details, "telemetry_disabled_by_admin")
    )
}

fn backend_error_has_detail_code(details: &BackendErrorDetails, code: &str) -> bool {
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(detail) = value.get("detail") else {
        return false;
    };
    detail.as_str() == Some(code)
        || detail.get("code").and_then(serde_json::Value::as_str) == Some(code)
}

fn no_fresh_telemetry_message(source: &SourceKind, smoke: &SmokeResult) -> String {
    if source == &SourceKind::Pi && smoke.local_session_observed == Some(true) {
        return "Pi created a local session, but Ottto did not receive a matching verification signal for this setup run. Check the backend binding and local upload path, then retry Verify.".to_string();
    }
    if source == &SourceKind::Pi {
        return "Pi smoke completed, but no new local Pi session file was observed and Ottto did not receive matching usage. Check the configured Pi provider route, then retry Verify.".to_string();
    }
    format!(
        "Ottto did not receive a fresh {} verification signal after the smoke session. Check that {} setup is connected, then retry Verify.",
        source_display_name(source),
        source_display_name(source),
    )
}

#[derive(Debug, Deserialize)]
struct SetupRunVerificationResponse {
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: String,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    clear_condition: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SetupRunVerificationFilters {
    model: Option<String>,
    model_provider: Option<String>,
    billing_provider: Option<String>,
}

#[derive(Clone, Copy)]
struct SetupVerificationTimeouts {
    wait: Duration,
    request: Duration,
}

fn get_setup_run_verification_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    get_setup_run_verification_with_base_timeout(
        api_base_url,
        connection,
        setup_run_token,
        source,
        smoke_after,
        filters,
        SETUP_VERIFICATION_HTTP_TIMEOUT,
    )
}

fn get_setup_run_verification_with_base_timeout(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    request_timeout: Duration,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/verification",
            connection.setup_run_id
        ),
    );
    let mut params = vec![
        ("source", source_slug(source).to_string()),
        ("smoke_after", smoke_after.to_string()),
    ];
    if let Some(filters) = filters {
        if let Some(model) = filters.model.as_deref() {
            params.push(("model", model.to_string()));
        }
        if let Some(model_provider) = filters.model_provider.as_deref() {
            params.push(("model_provider", model_provider.to_string()));
        }
        if let Some(billing_provider) = filters.billing_provider.as_deref() {
            params.push(("billing_provider", billing_provider.to_string()));
        }
    }
    // `source` and `smoke_after` are always present, so the query is never empty.
    let url = url_with_query_params(url, params);
    backend_get_json_with_timeout(
        &url,
        &[("X-Ottto-Setup-Run-Token", setup_run_token)],
        request_timeout,
    )
}

fn agent_context_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentContextQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/agent-context",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(days) = query.days {
        params.push(("days", days.to_string()));
    }
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    if let Some(max_tokens) = query.max_tokens {
        params.push(("max_tokens", max_tokens.to_string()));
    }
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    url_with_query_params(url, params)
}

fn agent_costs_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentCostsQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/costs",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(days) = query.days {
        params.push(("days", days.to_string()));
    }
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    push_non_empty_query(&mut params, "bucket", query.bucket.as_deref());
    push_non_empty_query(&mut params, "mode", query.mode.as_deref());
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    push_non_empty_query(&mut params, "dimensions", query.dimensions.as_deref());
    if query.daily {
        params.push(("daily", "true".to_string()));
    }
    url_with_query_params(url, params)
}

fn agent_sessions_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentSessionsQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/sessions",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(limit) = query.limit {
        params.push(("limit", limit.to_string()));
    }
    push_non_empty_query(&mut params, "cursor", query.cursor.as_deref());
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "model", query.model.as_deref());
    push_non_empty_query(
        &mut params,
        "billing_provider",
        query.billing_provider.as_deref(),
    );
    push_non_empty_query(
        &mut params,
        "billing_channel",
        query.billing_channel.as_deref(),
    );
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    push_non_empty_query(&mut params, "min_cost", query.min_cost.as_deref());
    push_non_empty_query(&mut params, "max_cost", query.max_cost.as_deref());
    push_non_empty_query(&mut params, "sort_by", query.sort_by.as_deref());
    push_non_empty_query(&mut params, "sort_dir", query.sort_dir.as_deref());
    push_non_empty_query(&mut params, "search", query.search.as_deref());
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    url_with_query_params(url, params)
}

fn agent_recommendations_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    _query: &AgentRecommendationsQuery,
) -> String {
    api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/recommendations",
            connection.setup_run_id
        ),
    )
}

fn agent_provider_impact_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentProviderImpactQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/provider-impact",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    push_non_empty_query(&mut params, "date_from", query.date_from.as_deref());
    push_non_empty_query(&mut params, "date_to", query.date_to.as_deref());
    push_non_empty_query(&mut params, "provider", query.provider.as_deref());
    push_non_empty_query(&mut params, "app", query.app.as_deref());
    push_non_empty_query(&mut params, "kind", query.kind.as_deref());
    push_non_empty_query(&mut params, "confidence", query.confidence.as_deref());
    push_non_empty_query(
        &mut params,
        "impact_priority",
        query.impact_priority.as_deref(),
    );
    push_non_empty_query(&mut params, "status", query.status.as_deref());
    push_non_empty_query(&mut params, "q", query.q.as_deref());
    if let Some(limit) = query.limit {
        params.push(("limit", limit.to_string()));
    }
    url_with_query_params(url, params)
}

fn url_with_query_params(url: String, params: Vec<(&'static str, String)>) -> String {
    if params.is_empty() {
        return url;
    }
    let query_string = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_url_encode(key), form_url_encode(&value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{url}?{query_string}")
}

fn push_non_empty_query(
    params: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        params.push((key, value.to_string()));
    }
}

fn backend_post_json<T: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_post_json_with_timeout(url, body, headers, BACKEND_REQUEST_TIMEOUT)
}

fn backend_post_json_with_timeout<T: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<T, LocalApiError> {
    // Backend calls carry tokens, secrets or claims in headers or bodies.
    let mut request = crate::retry_tls::credential_agent()
        .post(url)
        .set("Accept", "application/json")
        .timeout(timeout);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .send_json(body)
        .map_err(|error| backend_error_from_ureq(url, error))?;
    backend_success(url, response)?
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

fn backend_get_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_get_json_with_timeout(url, headers, BACKEND_REQUEST_TIMEOUT)
}

fn backend_get_agent_read_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_get_json_with_timeout(url, headers, AGENT_READ_HTTP_TIMEOUT)
}

fn backend_get_json_with_timeout<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<T, LocalApiError> {
    // Every caller authenticates with a header credential.
    let mut request = crate::retry_tls::credential_agent()
        .get(url)
        .set("Accept", "application/json")
        .timeout(timeout);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .call()
        .map_err(|error| backend_error_from_ureq(url, error))?;
    backend_success(url, response)?
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

/// Credential requests never follow a redirect, so ureq returns a 3xx as
/// `Ok`. Only a 2xx response is a backend success worth decoding.
fn backend_success(url: &str, response: ureq::Response) -> Result<ureq::Response, LocalApiError> {
    let status = response.status();
    if (200..300).contains(&status) {
        return Ok(response);
    }
    Err(LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: safe_backend_endpoint(url),
        status: Some(status),
        body_excerpt: None,
        reason_code: None,
    }))
}

fn backend_error_from_ureq(url: &str, error: ureq::Error) -> LocalApiError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().ok();
            let body_excerpt = body.as_deref().and_then(safe_backend_body_excerpt);
            let reason_code = body.as_deref().and_then(backend_reason_code);
            LocalApiError::Backend(BackendErrorDetails {
                kind: if status >= 500 {
                    BackendErrorKind::Unavailable
                } else {
                    BackendErrorKind::Rejected
                },
                endpoint: safe_backend_endpoint(url),
                status: Some(status),
                body_excerpt,
                reason_code,
            })
        }
        ureq::Error::Transport(transport) if transport_error_timed_out(&transport) => {
            LocalApiError::TimedOut(format!(
                "backend request timed out for {}",
                safe_backend_endpoint(url)
            ))
        }
        ureq::Error::Transport(transport) => LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Unreachable,
            endpoint: safe_backend_endpoint(url),
            status: None,
            body_excerpt: safe_backend_body_excerpt(&transport.to_string()),
            reason_code: None,
        }),
    }
}

fn transport_error_timed_out(transport: &ureq::Transport) -> bool {
    let mut source = StdError::source(transport);
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
            return matches!(
                io_error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            );
        }
        source = error.source();
    }
    transport
        .to_string()
        .to_ascii_lowercase()
        .contains("timed out")
}

fn backend_response_unexpected(url: &str, detail: String) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: safe_backend_endpoint(url),
        status: None,
        body_excerpt: safe_backend_body_excerpt(&detail),
        reason_code: None,
    })
}

fn safe_backend_endpoint(url: &str) -> String {
    let endpoint = url.split('?').next().unwrap_or(url);
    for (marker, replacement) in [
        (
            "/api/v1/telemetry/device-credential-preparations/",
            "[preparation]",
        ),
        ("/api/v1/telemetry/devices/", "[device]"),
    ] {
        let Some(start) = endpoint.find(marker) else {
            continue;
        };
        let identifier_start = start + marker.len();
        let suffix = endpoint[identifier_start..]
            .find('/')
            .map(|offset| &endpoint[identifier_start + offset..])
            .unwrap_or_default();
        if marker == "/api/v1/telemetry/devices/" && suffix != "/relay-token" {
            continue;
        }
        return format!("{}{}{}", &endpoint[..identifier_start], replacement, suffix);
    }
    endpoint.to_string()
}

/// The stable machine code an Ottto error body names: a top-level `code`, a
/// `detail.code`, or a `detail` that is itself a code
/// (`{"detail":"timezone_query_unsupported"}`). Only short lowercase
/// snake_case tokens qualify, so free-text detail never becomes a code.
fn backend_reason_code(body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let detail = value.get("detail");
    let named = [
        value.get("code"),
        detail.and_then(|detail| detail.get("code")),
    ]
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    .find(|code| is_backend_reason_code(code));
    let code = named.or_else(|| {
        detail
            .and_then(serde_json::Value::as_str)
            .filter(|code| code.contains('_') && is_backend_reason_code(code))
    })?;
    Some(code.to_string())
}

fn is_backend_reason_code(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn safe_backend_body_excerpt(body: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(detail) = value.get("detail").and_then(serde_json::Value::as_object) {
            if detail.get("code").and_then(serde_json::Value::as_str) == Some("reattach_required") {
                let safe = json!({
                    "detail": {
                        "code": "reattach_required",
                        "message": detail.get("message").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 120)),
                        "reason": detail.get("reason").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 40)),
                        "device_name": detail.get("device_name").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 80)),
                        "last_seen_at": detail.get("last_seen_at").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 40)),
                        "can_reconnect": detail.get("can_reconnect").and_then(serde_json::Value::as_bool),
                    }
                });
                return serde_json::to_string(&safe).ok();
            }
        }
    }
    let compact = body
        .split_whitespace()
        .take(40)
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return None;
    }
    Some(truncate_diagnostic(&redact_inline(&compact)))
}

fn wait_for_setup_run_verification_with_base_timeout(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    timeouts: SetupVerificationTimeouts,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    let start = Instant::now();
    loop {
        let response = get_setup_run_verification_with_base_timeout(
            api_base_url,
            connection,
            setup_run_token,
            source,
            smoke_after,
            filters,
            timeouts.request,
        )?;
        if response.verified || start.elapsed() >= timeouts.wait {
            return Ok(response);
        }
        thread::sleep(VERIFICATION_POLL_INTERVAL);
    }
}

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
fn verification_result(
    source: SourceKind,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    code: &str,
    text: &str,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    verification_result_with_config(
        source,
        config,
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        code,
        text,
    )
}

#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
fn verification_result_with_config(
    source: SourceKind,
    config: SourceConfigState,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    code: &str,
    text: &str,
) -> SourceVerificationResult {
    SourceVerificationResult {
        source,
        config,
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        message: StableMessage {
            code: code.to_string(),
            text: text.to_string(),
        },
        route_results: Vec::new(),
        check: None,
    }
}

/// Record what kind of check produced `result` and what it established, from
/// the result alone. A positive scope needs a Verified/Warning status, and no
/// scope names an account: nothing in a result binds accepted usage to one.
fn attach_verification_check(result: &mut SourceVerificationResult) {
    let positive_status = matches!(
        result.status,
        SourceVerificationStatus::Verified | SourceVerificationStatus::Warning
    );
    let check = match result.source {
        SourceKind::Codex => SourceVerificationCheck {
            method: Some(SourceVerificationMethod::ConfigurationCheck),
            scope: if positive_status
                && !result.verified
                && result.message.code == "codex_local_import"
                && result.config.drift.is_empty()
            {
                SourceVerificationScope::Configuration
            } else {
                SourceVerificationScope::NotEstablished
            },
        },
        SourceKind::ClaudeCode => SourceVerificationCheck {
            method: Some(SourceVerificationMethod::LivePrompt),
            scope: if result.verified && result.status == SourceVerificationStatus::Verified {
                SourceVerificationScope::UsageReceived
            } else {
                SourceVerificationScope::NotEstablished
            },
        },
        SourceKind::Pi => {
            for route in &mut result.route_results {
                route.check = Some(pi_route_verification_check(route));
            }
            let checks = result
                .route_results
                .iter()
                .filter_map(|route| route.check.as_ref())
                .collect::<Vec<_>>();
            let method = checks.first().and_then(|first| {
                if checks.iter().all(|check| check.method == first.method) {
                    first.method
                } else {
                    Some(SourceVerificationMethod::Mixed)
                }
            });
            let all =
                |scope: SourceVerificationScope| checks.iter().all(|check| check.scope == scope);
            let established = checks
                .iter()
                .filter(|check| check.scope != SourceVerificationScope::NotEstablished)
                .count();
            let scope = if !positive_status || established == 0 {
                SourceVerificationScope::NotEstablished
            } else if all(SourceVerificationScope::UsageReceived) {
                SourceVerificationScope::UsageReceived
            } else if all(SourceVerificationScope::LocalEvidence) {
                SourceVerificationScope::LocalEvidence
            } else {
                SourceVerificationScope::Partial
            };
            SourceVerificationCheck { method, scope }
        }
    };
    result.check = Some(check);
}

/// Same route split as Verify's dispatch and the aggregate's route counting.
fn pi_route_verification_check(route: &SourceRouteVerificationResult) -> SourceVerificationCheck {
    let passive =
        is_subscription_oauth(route.auth_mode.as_deref(), route.billing_channel.as_deref());
    SourceVerificationCheck {
        method: Some(if passive {
            SourceVerificationMethod::PassiveRecentUsage
        } else {
            SourceVerificationMethod::LivePrompt
        }),
        scope: if !route.verified {
            SourceVerificationScope::NotEstablished
        } else if route.status == SourceVerificationStatus::Verified {
            SourceVerificationScope::UsageReceived
        } else if route.status == SourceVerificationStatus::Warning
            && route.error_code.as_deref() == Some(PI_LOCAL_ONLY_CODE)
        {
            SourceVerificationScope::LocalEvidence
        } else {
            SourceVerificationScope::NotEstablished
        },
    }
}

fn verification_status_slug(status: &SourceVerificationStatus) -> &'static str {
    match status {
        SourceVerificationStatus::Verified => "verified",
        SourceVerificationStatus::Warning => "warning",
        SourceVerificationStatus::NoFreshTelemetry => "no_fresh_telemetry",
        SourceVerificationStatus::AccountNotConnected => "account_not_connected",
        SourceVerificationStatus::ReconnectRequired => "reconnect_required",
        SourceVerificationStatus::Failed => "failed",
    }
}

fn source_slug(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "codex",
        SourceKind::ClaudeCode => "claude_code",
        SourceKind::Pi => "pi",
    }
}

fn source_display_name(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "Codex",
        SourceKind::ClaudeCode => "Claude Code",
        SourceKind::Pi => "Pi",
    }
}

#[cfg(test)]
pub(crate) use tests::{owner_return_credential_for_test, owner_return_seed_for_test};

#[cfg(test)]
pub(crate) use tests::account_return_claim_for_test;

#[cfg(test)]
#[rustfmt::skip]
pub(crate) mod tests;

#[cfg(all(test, unix))]
#[path = "control_smoke_session_tests.rs"]
mod smoke_session_tests;
