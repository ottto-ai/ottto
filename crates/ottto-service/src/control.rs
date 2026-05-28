use crate::{
    agent_configs::{
        claude_env, codex_toml, detection::detect_agent_installation, fence::AgentConfigError,
    },
    agent_status::{
        pi_identity_hints_for_route, read_pi_agent_auth, read_pi_smoke_routes,
        BillingIdentityHints, PiModelRoute,
    },
    current_rfc3339_timestamp, diagnostics_local_only_upload_report,
    keychain::TelemetryKeyStore,
    BackendErrorDetails, BackendErrorKind, LocalApiError, LocalDaemon, PendingAuthClaim,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ottto_core::{
    compiled_build_id, compiled_release_channel, compiled_release_version, default_support_dir,
    execute_local_uninstall, generate_control_token, install_owner_for_path,
    local_lifecycle_home_dir, plan_local_uninstall, redact_inline, release_channel_from_str,
    ControlTokenStore, FileAccountStore, FileConnectionStore, FileDeviceStore, KeychainSecretStore,
    LocalConnectionBinding, LocalDeviceBinding, UninstallExecutionOptions, OTTTO_CLIENT_NAME,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_SERVICE_BINARY_NAME, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
use ottto_protocol::{
    AgentInstallationDetection, AgentStatusSnapshot, AuthCompleteResponse, AuthResetResponse,
    AuthStartResponse, CliError, CliErrorCode, ConfigDrift, ControlResult, ControlResultStatus,
    DiagnosticsBundle, DiagnosticsRetentionDisclosure, DiagnosticsUploadApproval,
    DiagnosticsUploadAuthorization, DiagnosticsUploadReport, DiagnosticsUploadStatus, InstallOwner,
    LocalAccountBinding, LocalAccountOrganization, LocalAccountState, LocalAccountUser,
    LocalClientKind, LocalControlCommand, LocalControlRequest, LocalControlResponse,
    MachineIdentity, RedactedValue, RelayRuntimeState, RelayState, ReleaseChannel,
    RepairActionKind, RepairPlan, RepairPlanStatus, SecretString, ServiceOwnerState,
    SourceConfigState, SourceKind, SourceRouteVerificationResult, SourceVerificationResult,
    SourceVerificationStatus, StableMessage, TelemetryControlAction, UninstallExecutionResult,
    UpdateGate, UpdateState, UpdateStatus, DIAGNOSTICS_RETENTION_DISCLOSURE,
    LOCAL_CONTROL_PROTOCOL_VERSION, PROTOCOL_VERSION,
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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, Item, Table};

const DEFAULT_API_BASE_URL: &str = "https://ottto.net/backend";
const DIRECT_API_BASE_URL: &str = "https://api.ottto.net";
const SMOKE_PROMPT: &str = "Reply with exactly: ottto smoke test";
const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SMOKE_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const VERIFICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const VERIFICATION_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: u64 = 15;
const VERIFICATION_MARKER_METRIC_NAME: &str = "ottto.verification.smoke";
const VERIFICATION_MARKER_ATTRIBUTE: &str = "ottto.verification";
const VERIFICATION_MARKER_HEADER: &str = "X-Ottto-Verification";
const MAX_CONFIG_BACKUPS_PER_SOURCE: usize = 10;
const OTTTO_CONFIG_BACKUP_RETENTION_ENV: &str = "OTTTO_CONFIG_BACKUP_RETENTION";
#[cfg(target_os = "macos")]
const OTTTO_COMPANION_BUNDLE_IDENTIFIER: &str = "net.ottto.Companion";

#[derive(Debug, Clone, Default)]
pub struct LocalClientPeer {
    pub pid: Option<u32>,
    #[cfg(test)]
    trusted_for_tests: bool,
}

impl LocalClientPeer {
    pub fn from_pid(pid: u32) -> Self {
        Self {
            pid: Some(pid),
            #[cfg(test)]
            trusted_for_tests: false,
        }
    }

    #[cfg(test)]
    fn trusted_for_tests() -> Self {
        Self {
            pid: None,
            trusted_for_tests: true,
        }
    }
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
    if request.protocol_version != LOCAL_CONTROL_PROTOCOL_VERSION {
        return LocalControlResponse {
            request_id,
            ok: false,
            payload: None,
            error: Some(CliError {
                message: format!(
                    "unsupported local control protocol_version {}; expected {}",
                    request.protocol_version, LOCAL_CONTROL_PROTOCOL_VERSION
                ),
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
    match handle_command(daemon, authorization, request.command, client_install_owner) {
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

pub fn handle_request_json_with_peer(
    daemon: &LocalDaemon,
    request_json: &str,
    peer: Option<LocalClientPeer>,
) -> String {
    let response = match serde_json::from_str::<LocalControlRequest>(request_json) {
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

    let Some(pid) = peer.pid else {
        return false;
    };

    trusted_companion_pid(pid)
}

#[cfg(target_os = "macos")]
fn trusted_companion_pid(pid: u32) -> bool {
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

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

    let Some(requirement_text) = companion_code_requirement() else {
        return true;
    };
    let Ok(requirement) = requirement_text.parse::<SecRequirement>() else {
        return false;
    };
    code.check_validity(Flags::NONE, &requirement).is_ok()
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

#[cfg(target_os = "macos")]
fn companion_code_requirement() -> Option<String> {
    if let Ok(requirement) = std::env::var("OTTTO_COMPANION_CODE_REQUIREMENT") {
        return Some(requirement);
    }
    std::env::var("OTTTO_COMPANION_TEAM_ID").ok().map(|team_id| {
        format!(
            "identifier \"{OTTTO_COMPANION_BUNDLE_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{team_id}\""
        )
    })
}

fn handle_command(
    daemon: &LocalDaemon,
    authorization: RequestAuthorization,
    command: LocalControlCommand,
    client_install_owner: InstallOwner,
) -> Result<serde_json::Value, LocalApiError> {
    match command {
        LocalControlCommand::Status {
            refresh_agent_status,
        } => {
            if refresh_agent_status {
                refresh_agent_status_for(daemon, &authorization, None)?;
            }
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            status.service_owner = service_owner_state(client_install_owner);
            to_value(status)
        }
        LocalControlCommand::AuthStatus => to_value(status_for(daemon, &authorization)?),
        LocalControlCommand::AgentStatusRefresh { source } => {
            to_value(refresh_agent_status_for(daemon, &authorization, source)?)
        }
        LocalControlCommand::AuthStart => to_value(auth_start(daemon, &authorization)?),
        LocalControlCommand::AuthComplete { claim_code, nonce } => {
            to_value(auth_complete(daemon, &authorization, &claim_code, &nonce)?)
        }
        LocalControlCommand::AuthReset { local_only } => {
            to_value(auth_reset(daemon, &authorization, local_only)?)
        }
        LocalControlCommand::Account => to_value(account_for(daemon, &authorization)?),
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
            to_value(verify_source(daemon, &authorization, source, repair)?)
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

fn account_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<LocalAccountBinding, LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => Ok(daemon.status(token)?.account),
        RequestAuthorization::TrustedCompanionApp => daemon.account_for_trusted_client(),
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

fn require_authorized_local_client(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<(), LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => {
            daemon.status(token)?;
            Ok(())
        }
        RequestAuthorization::TrustedCompanionApp => {
            daemon.status_for_trusted_client()?;
            Ok(())
        }
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
}

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
fn telemetry_control_with_detector(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
    detector: &dyn Fn(&SourceKind) -> AgentInstallationDetection,
) -> Result<ControlResult, LocalApiError> {
    let mut key_id = key_id;
    if !matches!(source, SourceKind::Codex | SourceKind::ClaudeCode) {
        return Err(LocalApiError::InvalidRequest(
            "telemetry control supports codex and claude_code only".to_string(),
        ));
    }

    let api_base_url = validated_api_base_url(api_base_url.as_deref())?;
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
            require_non_empty_field(key_id.as_deref(), "key_id")?;
        }
        TelemetryControlAction::Status => {}
    }

    let claims =
        validate_control_token_with_backend(&api_base_url, &control_token, &action, &source)?;
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
            let key_id = key_id
                .as_deref()
                .expect("disable key_id validated before backend call");
            remove_telemetry_config(daemon, &source)?;
            TelemetryKeyStore::production()
                .delete(&source, key_id)
                .map_err(|error| {
                    LocalApiError::LocalOperationFailed(format!(
                        "telemetry key removal failed: {error}"
                    ))
                })?;
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

    let requires_restart = matches!(action, TelemetryControlAction::EnableTelemetry);
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
        return Ok(ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        });
    }
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    match source {
        SourceKind::Codex => patch_codex_config_with_relay_base(&relay_base_url),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            patch_claude_code_env_with_relay_base(&machine, &relay_base_url)
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
        SourceKind::Codex => remove_codex_config(),
        SourceKind::ClaudeCode => {
            let _ = daemon.status_for_trusted_client()?;
            remove_claude_code_env()
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
    let mut plan = propose_repair_plan(daemon, authorization, source.clone(), dry_run)?;
    if dry_run {
        return Ok(plan);
    }

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
        ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        }
    } else {
        execute_write_config_repair(daemon, authorization, &source)?
    };
    let after = source_config_state_for_daemon(daemon, &source)?;

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
                    "{} telemetry config already matched the active local relay.",
                    source_display_name(&source)
                )
            }
        } else {
            format!(
                "{} telemetry config still has drift after repair.",
                source_display_name(&source)
            )
        };
    }
    Ok(plan)
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
        SourceKind::Codex => patch_codex_config_with_relay_base(&relay_base_url),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            patch_claude_code_settings_with_relay_base(&machine, &relay_base_url)
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
    let url = api_url_with_base(api_base_url, "/api/v1/apps/control-token/validate");
    let request = BackendControlTokenValidationRequest {
        token: token.to_string(),
        source: source_slug(source).to_string(),
        action: action_slug(action).to_string(),
    };
    match backend_post_json::<BackendControlTokenValidationResponse>(&url, &request, &[]) {
        Ok(response) => Ok(BackendControlTokenClaims {
            organization_id: response
                .organization_id
                .filter(|value| !value.trim().is_empty()),
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
    if token.trim().is_empty() {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let payload = decode_control_token_payload(token)?;
    if payload.get("type").and_then(|value| value.as_str()) != Some("apps_control") {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("source").and_then(|value| value.as_str()) != Some(source_slug(source)) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("action").and_then(|value| value.as_str()) != Some(action_slug(action)) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let exp = payload
        .get("exp")
        .and_then(|value| value.as_u64())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LocalApiError::StatePoisoned)?
        .as_secs();
    if exp <= now {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    Ok(())
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
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    match authorization {
        RequestAuthorization::Token(token) => {
            daemon.refresh_agent_status(token, source, captured_at, expires_at)
        }
        RequestAuthorization::TrustedCompanionApp => {
            daemon.refresh_agent_status_for_trusted_client(source, captured_at, expires_at)
        }
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

fn auth_start(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<AuthStartResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    let nonce = generate_control_token().map_err(|_| LocalApiError::StatePoisoned)?;
    let claim = create_setup_claim(&status.machine, &nonce)?;
    let claim_url = append_nonce_to_claim_url(&claim.claim_url, &nonce);
    daemon.begin_auth_with_claim(PendingAuthClaim {
        claim_code: claim.claim_code,
        claim_token: claim.claim_token,
        nonce,
        claim_url,
        expires_at: claim.expires_at,
    })
}

fn auth_complete(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
    nonce: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    let pending = daemon.pending_auth_claim(claim_code, nonce)?;
    let completed = complete_setup_claim(&pending, &status.machine)?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&completed.setup_run_token)
        .map_err(|_| LocalApiError::StatePoisoned)?;
    let account = LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: completed.user.id,
            email: completed.user.email,
            display_name: completed.user.display_name,
        }),
        organization: Some(LocalAccountOrganization {
            id: completed.organization.id,
            name: completed.organization.name,
        }),
        connected_at: Some(completed.connected_at.clone()),
        last_refreshed_at: Some(completed.connected_at.clone()),
        message: Some(StableMessage {
            code: "connected".to_string(),
            text: "This Mac is connected to Ottto.".to_string(),
        }),
    };
    let response = daemon.complete_auth_with_account(
        claim_code,
        nonce,
        account.clone(),
        completed.setup_run_id.clone(),
        completed.setup_run_token_expires_at.clone(),
        completed.machine_id.clone(),
    )?;
    FileAccountStore::default()
        .save(&account)
        .map_err(|_| LocalApiError::StatePoisoned)?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: completed.setup_run_id,
            setup_run_token_expires_at: completed.setup_run_token_expires_at,
            machine_id: completed.machine_id,
            api_base_url: validated_api_base_url(None)?,
        })
        .map_err(|_| LocalApiError::StatePoisoned)?;
    Ok(response)
}

fn auth_reset(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    local_only: bool,
) -> Result<AuthResetResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let mut cloud_disconnect: Option<SetupRunDisconnectResponse> = None;

    if !local_only {
        let connection = daemon
            .connection_for_authorized_client()?
            .ok_or_else(cloud_logout_requires_connection_error)?;
        let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .map_err(|_| cloud_logout_requires_connection_error())?;
        let api_base_url = validated_api_base_url(Some(connection.api_base_url.as_str()))?;
        cloud_disconnect = Some(disconnect_setup_run_with_refresh(
            &api_base_url,
            &connection,
            &setup_run_token,
        )?);
    }

    FileAccountStore::default()
        .reset()
        .map_err(|_| LocalApiError::StatePoisoned)?;
    FileConnectionStore::default()
        .reset()
        .map_err(|_| LocalApiError::StatePoisoned)?;
    let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
    let mut reset = daemon.reset_account_for_authorized_client()?;
    reset.local_only = local_only;
    reset.cloud_disconnected = cloud_disconnect.is_some();
    reset.setup_run_id = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.setup_run_id.clone());
    reset.disconnected_at = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.disconnected_at.clone());
    reset.message = StableMessage {
        code: if local_only {
            "local_disconnect_complete".to_string()
        } else {
            "cloud_disconnect_complete".to_string()
        },
        text: if local_only {
            "Local Ottto credentials were cleared without changing cloud state.".to_string()
        } else {
            "This Mac was disconnected from Ottto.".to_string()
        },
    };
    Ok(reset)
}

fn cloud_logout_requires_connection_error() -> LocalApiError {
    LocalApiError::InvalidRequest(
        "logout requires an active Ottto cloud connection; use --local-only only to clear local state without updating Ottto"
            .to_string(),
    )
}

#[derive(Debug, Deserialize)]
struct SetupClaimCreateResponse {
    claim_code: String,
    claim_token: String,
    claim_url: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct SetupClaimCompleteResponse {
    setup_run_id: String,
    setup_run_token: String,
    setup_run_token_expires_at: String,
    machine_id: Option<String>,
    connected_at: String,
    user: SetupClaimCompleteUser,
    organization: SetupClaimCompleteOrganization,
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
    let body = json!({
        "machine_id": machine.machine_id,
        "hardware_uuid": machine.hardware_uuid,
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
    });
    backend_post_json(&url, &body, &[])
}

fn complete_setup_claim(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
) -> Result<SetupClaimCompleteResponse, LocalApiError> {
    let url = api_url(&format!(
        "/api/v1/setup-claims/{}/local-client/complete",
        claim.claim_code
    ));
    let body = json!({
        "nonce": claim.nonce,
        "machine_id": machine.machine_id,
        "machine_name": machine.display_name,
        "platform": "macos",
    });
    backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Setup-Claim-Token", claim.claim_token.as_str())],
    )
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
    serde_json::to_value(value).map_err(|_| LocalApiError::StatePoisoned)
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
    let manifest = ureq::get(&manifest_url)
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
        };
    }

    if manifest.channel != local_channel {
        let download_url = app_download_url(&manifest);
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
            Some("newer release manifest version is available".to_string())
        } else {
            Some(format!(
                "release manifest reports a different build ({}) for the same version",
                manifest.commit
            ))
        }
    } else {
        Some("current build matches the release manifest channel".to_string())
    };
    let (update_command, update_instructions) = if update_required {
        update_route_for_owner(install_owner, &manifest.supported_install_owners)
    } else {
        (None, None)
    };
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
    }
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

    owner_drift |= known_owner_conflict(client_owner, daemon_owner)
        || known_owner_conflict(client_owner, plist_owner)
        || known_owner_conflict(client_owner, loaded_owner);

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

fn known_owner_conflict(left: InstallOwner, right: InstallOwner) -> bool {
    left != InstallOwner::Unknown && right != InstallOwner::Unknown && left != right
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
        LocalApiError::RepairLocked => CliErrorCode::RepairLocked,
        LocalApiError::StatePoisoned => CliErrorCode::Internal,
        LocalApiError::EmptyControlToken => CliErrorCode::InvalidRequest,
        LocalApiError::NoPendingAuthClaim | LocalApiError::AuthClaimMismatch => {
            CliErrorCode::InvalidRequest
        }
        LocalApiError::SetupRunConnectionMissing => CliErrorCode::NeedsUserAction,
        LocalApiError::SetupRunConnectionMismatch => CliErrorCode::InvalidRequest,
        LocalApiError::InvalidRequest(_) => CliErrorCode::InvalidRequest,
        LocalApiError::ManualFenceReviewRequired => CliErrorCode::ManualFenceReviewRequired,
        LocalApiError::LocalOperationFailed(_) => CliErrorCode::Internal,
        LocalApiError::NetworkUnavailable => CliErrorCode::NetworkUnavailable,
        LocalApiError::TimedOut(_) => CliErrorCode::TimedOut,
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
            if body.contains("expired") {
                return "Setup run expired. Open the Ottto app from Ottto to attach an active setup run.".to_string();
            }
            if backend.status == Some(401) || backend.status == Some(403) {
                if diagnostics_upload {
                    return "Ottto rejected the diagnostics upload. Sign in again or use a fresh support claim.".to_string();
                }
                if logout_disconnect {
                    return "Ottto rejected the cloud logout for this Mac. Reconnect from ottto.net/apps or use `ottto logout --local-only` only to clear local state.".to_string();
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
                    "Ottto rejected the cloud logout for this Mac. Reconnect from ottto.net/apps or use `ottto logout --local-only` only to clear local state.".to_string()
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

fn setup_run(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    sources: Vec<SourceKind>,
    claim_code: Option<String>,
    setup_run_id: Option<String>,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    let status = status_for(daemon, authorization)?;
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
            api_base_url: api_base_url.clone(),
        };
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .save(&attached.setup_run_token)
            .map_err(|_| LocalApiError::StatePoisoned)?;
        FileConnectionStore::default()
            .save(&binding)
            .map_err(|_| LocalApiError::StatePoisoned)?;
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

    let scan = build_local_scan(&status.machine, sources);
    let mut detail = publish_scan_result(&api_base_url, &connection, &setup_run_token, &scan)?;
    let action_results = process_setup_actions(
        daemon,
        &api_base_url,
        &connection,
        &setup_run_token,
        &status.machine,
    )?;
    if let Some(last) = action_results.last() {
        if let Some(refreshed) = &last.detail {
            detail = refreshed.clone();
        }
    }

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
            json!({
                "source": source.source,
                "state": source.state,
                "readiness_percent": source.readiness_percent,
                "missing_fields": source.missing_fields,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "status": detail.run.status,
        "setup_run_id": connection.setup_run_id,
        "claim_code_provided": claim_code_provided,
        "source_count": source_count,
        "detected_sources": detected_sources,
        "next_question": detail.next_question,
        "next_action": detail.next_action,
        "actions": action_results,
    }))
}

fn setup_answer(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    answer_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let answer_type = match answer_type.trim() {
        "skip_source" | "disable_source" => answer_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_answer only supports skip_source and disable_source".to_string(),
            ))
        }
    };
    let detail = save_setup_answer(
        &api_base_url,
        &connection,
        &setup_run_token,
        &source,
        &answer_type,
    )?;
    setup_result_from_detail(&connection, detail, false, Vec::new())
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
    let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let action_type = match action_type.trim() {
        "install_source" | "verify_source" => action_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_action only supports install_source and verify_source".to_string(),
            ))
        }
    };
    queue_setup_action(
        &api_base_url,
        &connection,
        &setup_run_token,
        &source,
        &action_type,
    )?;
    let action_results = process_setup_actions(
        daemon,
        &api_base_url,
        &connection,
        &setup_run_token,
        &status.machine,
    )?;
    let detail = action_results
        .last()
        .and_then(|result| result.detail.clone())
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "queued setup action did not return a setup-run detail".to_string(),
            )
        })?;
    setup_result_from_detail(&connection, detail, false, action_results)
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
    detected: bool,
    installed: bool,
    telemetry_installed: bool,
    local_health: &'static str,
    missing_fields: Vec<String>,
    attribution_guess: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_status: Option<AgentStatusSnapshot>,
}

#[derive(Debug, Serialize)]
struct SetupActionResult {
    action_id: String,
    action_type: String,
    source: Option<String>,
    status: String,
    detail: Option<SetupRunDetailApiResponse>,
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
            json!({
                "source": source.source,
                "state": source.state,
                "readiness_percent": source.readiness_percent,
                "missing_fields": source.missing_fields,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "status": detail.run.status,
        "setup_run_id": connection.setup_run_id,
        "claim_code_provided": claim_code_provided,
        "source_count": source_count,
        "detected_sources": detected_sources,
        "next_question": detail.next_question,
        "next_action": detail.next_action,
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
    let body = json!({
        "machine_id": machine.machine_id,
        "hardware_uuid": machine.hardware_uuid,
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
    });
    backend_post_json(&url, &body, &[])
}

#[derive(Debug, Deserialize)]
struct SetupRunRefreshResponse {
    setup_run_token: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct SetupRunDisconnectResponse {
    setup_run_id: String,
    #[allow(dead_code)]
    run_status: String,
    #[allow(dead_code)]
    client_disconnected: bool,
    disconnected_at: String,
}

/// Mint a fresh `setup_run_token` for the current run using the daemon's
/// long-lived device secret. The token is persisted to Keychain and the
/// connection's expiry timestamp is updated. Returns the new token so the
/// caller can immediately retry whatever 401'd.
fn refresh_setup_run_token_via_device_secret(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
) -> Result<String, LocalApiError> {
    let device = FileDeviceStore::default()
        .load()
        .map_err(|_| LocalApiError::StatePoisoned)?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .map_err(|_| LocalApiError::SetupRunConnectionMissing)?;

    let url = api_url_with_base(
        api_base_url,
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
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&response.setup_run_token)
        .map_err(|_| LocalApiError::StatePoisoned)?;
    let mut refreshed = connection.clone();
    refreshed.setup_run_token_expires_at = response.expires_at.clone();
    FileConnectionStore::default()
        .save(&refreshed)
        .map_err(|_| LocalApiError::StatePoisoned)?;
    Ok(response.setup_run_token)
}

fn disconnect_setup_run_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    match disconnect_setup_run_local_client(api_base_url, connection, setup_run_token) {
        Ok(response) => Ok(response),
        Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
            let fresh_token = refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
            disconnect_setup_run_local_client(api_base_url, connection, &fresh_token)
        }
        Err(other) => Err(other),
    }
}

fn disconnect_setup_run_local_client(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/disconnect",
            connection.setup_run_id
        ),
    );
    let body = json!({ "reason": "logout" });
    backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

/// Call `wait_for_setup_run_verification_with_base` with one transparent
/// retry on 401: refresh the companion token via device-secret auth, then
/// re-issue the verify call with the new token. Other errors pass through.
fn wait_for_verification_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    match wait_for_setup_run_verification_with_base(
        api_base_url,
        connection,
        setup_run_token,
        source,
        smoke_after,
        None,
    ) {
        Ok(response) => Ok(response),
        Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
            let fresh_token = refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
            wait_for_setup_run_verification_with_base(
                api_base_url,
                connection,
                &fresh_token,
                source,
                smoke_after,
                None,
            )
        }
        Err(other) => Err(other),
    }
}

fn publish_scan_result(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    scan: &SetupScanPayload,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/scan-result",
            connection.setup_run_id
        ),
    );
    backend_post_json(&url, scan, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

fn save_setup_answer(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    answer_type: &str,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/answers",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "source": source_slug(source),
        "answer_type": answer_type,
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

fn queue_setup_action(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    action_type: &str,
) -> Result<SetupRunActionApiResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/actions",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "source": source_slug(source),
        "action_type": action_type,
        "requested_by": "companion_app",
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

fn process_setup_actions(
    daemon: &LocalDaemon,
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    machine: &MachineIdentity,
) -> Result<Vec<SetupActionResult>, LocalApiError> {
    let mut results = Vec::new();
    for _ in 0..8 {
        let next = get_next_setup_action(api_base_url, connection, setup_run_token)?;
        let Some(action) = next.action else {
            break;
        };
        record_setup_action_event(
            api_base_url,
            connection,
            setup_run_token,
            &action,
            SetupActionEvent {
                event_type: "action.started",
                status: "running",
                message: "Local daemon started setup action",
                metadata: None,
            },
        )?;
        let source_slug = action.source.clone();
        let source = source_slug.as_deref().and_then(source_from_slug);
        let (status, message, result) = match action.action_type.as_str() {
            "install_source" => run_install_source_action(
                daemon,
                api_base_url,
                connection,
                setup_run_token,
                &action,
                machine,
            )?,
            "verify_source" => {
                if let Some(source) = source {
                    run_verify_source_action(
                        daemon,
                        api_base_url,
                        connection,
                        setup_run_token,
                        &action,
                        source,
                    )?
                } else {
                    (
                        "failed".to_string(),
                        "Setup action source was missing".to_string(),
                        json!({
                            "verified": false,
                            "error_code": "source_missing",
                            "error_message": "Setup action source was missing",
                        }),
                    )
                }
            }
            _ => (
                "failed".to_string(),
                format!("Unsupported setup action {}", action.action_type),
                json!({
                    "error_code": "unsupported_action",
                    "error_message": format!("Unsupported setup action {}", action.action_type),
                }),
            ),
        };
        let detail = complete_setup_action(
            api_base_url,
            connection,
            setup_run_token,
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
        });
    }
    Ok(results)
}

#[derive(Debug, Deserialize)]
struct SetupRunNextActionResponse {
    action: Option<SetupRunActionApiResponse>,
}

fn get_next_setup_action(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
) -> Result<SetupRunNextActionResponse, LocalApiError> {
    heartbeat_setup_run(
        api_base_url,
        connection,
        setup_run_token,
        "polling_next_action",
    )?;
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/next-action",
            connection.setup_run_id
        ),
    );
    backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
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
        },
    });
    let _: serde_json::Value =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    Ok(())
}

fn record_setup_action_event(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    action: &SetupRunActionApiResponse,
    event: SetupActionEvent<'_>,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/actions/{}/events",
            connection.setup_run_id, action.id
        ),
    );
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "source": action.source,
        "metadata": event.metadata,
    });
    let _: serde_json::Value =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
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
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    action: &SetupRunActionApiResponse,
    status: &str,
    message: &str,
    result: serde_json::Value,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/actions/{}/complete",
            connection.setup_run_id, action.id
        ),
    );
    let body = json!({
        "status": status,
        "message": message,
        "result": result,
    });
    backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

fn run_install_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
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
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/install-sessions",
            connection.setup_run_id
        ),
    );
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
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
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
    let registered = register_telemetry_device(api_base_url, &install_session, machine)?;
    let device_id = registered.device.id.clone();
    FileDeviceStore::default()
        .save(&LocalDeviceBinding {
            device_id: registered.device.id.clone(),
            machine_id: registered
                .device
                .machine_id
                .clone()
                .or_else(|| connection.machine_id.clone())
                .or_else(|| Some(machine.machine_id.clone())),
            sources: registered.device.sources.clone(),
        })
        .map_err(|_| LocalApiError::StatePoisoned)?;
    KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .save(&registered.device_secret)
        .map_err(|_| LocalApiError::StatePoisoned)?;
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

    if !source_requires_config_patch(&source_kind) {
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
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            install_source_registration_result(
                &install_session.install_session_id,
                &device_id,
                source,
                &message,
            ),
        ));
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
        SourceKind::Codex => patch_codex_config_with_relay_base(&relay_base_url)?,
        SourceKind::ClaudeCode => {
            patch_claude_code_settings_with_relay_base(machine, &relay_base_url)?
        }
        SourceKind::Pi => unreachable!("Pi install actions do not patch OTLP config"),
    };
    let config_event_message = if patch.changed {
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
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: if patch.changed {
                "config.patched"
            } else {
                "config.unchanged"
            },
            status: "succeeded",
            message: &config_event_message,
            metadata: Some(json!({
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
            })),
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
        match emit_setup_run_verification_marker(api_base_url, &source_kind, connection, machine) {
            Ok(marker_id) => {
                record_install_session_event(
                    api_base_url,
                    &install_session.install_session_id,
                    &install_session.install_session_token,
                    InstallSessionEvent {
                        event_type: "verification.succeeded",
                        status: "succeeded",
                        message: "Sent synthetic telemetry verification marker",
                        metadata: Some(json!({
                            "source": source,
                            "marker_id": marker_id,
                        })),
                        device_id: Some(&device_id),
                    },
                )?;
            }
            Err(error) => {
                let error_message = error.to_string();
                record_install_session_event(
                    api_base_url,
                    &install_session.install_session_id,
                    &install_session.install_session_token,
                    InstallSessionEvent {
                        event_type: "verification.failed",
                        status: "failed",
                        message: "Synthetic telemetry verification marker failed",
                        metadata: Some(json!({
                            "source": source,
                            "error_code": "verification_marker_failed",
                            "error_message": error_message,
                        })),
                        device_id: Some(&device_id),
                    },
                )?;
                return Ok((
                    "failed".to_string(),
                    format!(
                        "{} telemetry config was written, but verification marker failed",
                        source_display_name(&source_kind)
                    ),
                    json!({
                        "install_session_id": install_session.install_session_id,
                        "device_id": device_id,
                        "source": source,
                        "local_changes": "installed",
                        "config_patched": true,
                        "relay_running": true,
                        "relay_port": relay_port,
                        "relay_source": source,
                        "error_code": "verification_marker_failed",
                        "error_message": "Synthetic telemetry verification marker failed",
                    }),
                ));
            }
        }
    }

    let status = if relay_running { "succeeded" } else { "failed" }.to_string();
    let message = if relay_running {
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
            claude_code_settings_config_state_at(
                &home_path(".claude/settings.json"),
                "~/.claude/settings.json",
                &machine,
                &relay_base_url,
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
    relay_base_url: &str,
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
                    vec![config_drift("codex.config_file", "present", "missing")]
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
                    vec![config_drift("codex.config_file", "readable", "unreadable")]
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
    let body = match std::str::from_utf8(&bytes) {
        Ok(body) => body,
        Err(_) => {
            drift.push(config_drift("codex.config_toml", "valid", "invalid_utf8"));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
    };
    let document = match body.parse::<DocumentMut>() {
        Ok(document) => document,
        Err(_) => {
            drift.push(config_drift("codex.config_toml", "valid", "invalid"));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
    };
    let Some(otel) = document.get("otel").and_then(Item::as_table) else {
        drift.push(config_drift("otel", "present", "missing"));
        return SourceConfigState {
            discovered: true,
            path_hint: Some(path_hint.to_string()),
            fingerprint,
            drift,
        };
    };
    let prompt_logging_disabled = otel
        .get("log_user_prompt")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool());
    if prompt_logging_disabled != Some(false) {
        drift.push(config_drift(
            "otel.log_user_prompt",
            "false",
            prompt_logging_disabled
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_string()),
        ));
    }
    codex_exporter_config_drift(
        &mut drift,
        otel,
        "otel.exporter.otlp-http",
        "exporter",
        "logs",
        relay_base_url,
    );
    codex_exporter_config_drift(
        &mut drift,
        otel,
        "otel.trace_exporter.otlp-http",
        "trace_exporter",
        "traces",
        relay_base_url,
    );
    codex_exporter_config_drift(
        &mut drift,
        otel,
        "otel.metrics_exporter.otlp-http",
        "metrics_exporter",
        "metrics",
        relay_base_url,
    );
    SourceConfigState {
        discovered: true,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift,
    }
}

fn codex_exporter_config_drift(
    drift: &mut Vec<ConfigDrift>,
    otel: &Table,
    drift_prefix: &str,
    exporter_key: &str,
    signal: &str,
    relay_base_url: &str,
) {
    let otlp_http = otel
        .get(exporter_key)
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("otlp-http"))
        .and_then(Item::as_table_like);
    let expected_endpoint = expected_relay_endpoint(relay_base_url, signal);
    let observed_endpoint = otlp_http
        .and_then(|table| table.get("endpoint"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_str());
    if observed_endpoint != Some(expected_endpoint.as_str()) {
        drift.push(config_drift(
            format!("{drift_prefix}.endpoint"),
            expected_endpoint,
            observed_endpoint.unwrap_or("missing"),
        ));
    }
    let observed_protocol = otlp_http
        .and_then(|table| table.get("protocol"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_str());
    if observed_protocol != Some("binary") {
        drift.push(config_drift(
            format!("{drift_prefix}.protocol"),
            "binary",
            observed_protocol.unwrap_or("missing"),
        ));
    }
    let observed_header = otlp_http
        .and_then(|table| table.get("headers"))
        .and_then(Item::as_table_like)
        .and_then(|headers| headers.get(crate::otlp_relay::LOCAL_RELAY_HEADER))
        .and_then(Item::as_value)
        .and_then(|value| value.as_str());
    if observed_header != Some(crate::otlp_relay::CODEX_RELAY_SOURCE) {
        drift.push(config_drift(
            format!("{drift_prefix}.headers.X-Ottto-Local-Relay"),
            crate::otlp_relay::CODEX_RELAY_SOURCE,
            observed_header.unwrap_or("missing"),
        ));
    }
}

fn claude_code_settings_config_state_at(
    path: &Path,
    path_hint: &str,
    machine: &MachineIdentity,
    relay_base_url: &str,
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
    if !statusline_command.is_some_and(is_ottto_statusline_command) {
        drift.push(config_drift(
            "statusLine.command",
            "ottto claude-code-statusline wrapper",
            statusline_command.unwrap_or("missing"),
        ));
    }
    SourceConfigState {
        discovered: true,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift,
    }
}

fn expected_relay_endpoint(relay_base_url: &str, signal: &str) -> String {
    format!("{}/v1/{signal}", relay_base_url.trim_end_matches('/'))
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

#[derive(Debug, Deserialize)]
struct TelemetryDeviceRegisterApiResponse {
    device: TelemetryDeviceApiResponse,
    device_secret: String,
}

#[derive(Debug, Deserialize)]
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

fn register_telemetry_device(
    api_base_url: &str,
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
) -> Result<TelemetryDeviceRegisterApiResponse, LocalApiError> {
    let url = api_url_with_base(api_base_url, "/api/v1/telemetry/devices/register");
    let body = json!({
        "install_session_id": install_session.install_session_id,
        "install_session_token": install_session.install_session_token,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "client_name": OTTTO_CLIENT_NAME,
        "client_version": machine.local_platform_version,
        "machine_id": machine.machine_id,
        "hardware_uuid": machine.hardware_uuid,
    });
    backend_post_json(&url, &body, &[])
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigPatchResult {
    changed: bool,
    created: bool,
    backup_created: bool,
}

fn local_relay_base_url_for_daemon(daemon: &LocalDaemon) -> String {
    daemon
        .status_for_trusted_client()
        .map(|status| crate::otlp_relay::local_relay_base_url_from_state(&status.relay))
        .unwrap_or_else(|_| crate::otlp_relay::default_local_relay_base_url())
}

fn local_relay_port_for_daemon(daemon: &LocalDaemon) -> u16 {
    daemon
        .status_for_trusted_client()
        .map(|status| crate::otlp_relay::local_relay_port_from_state(&status.relay))
        .unwrap_or(crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT)
}

fn patch_codex_config_with_relay_base(
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let backup_root = default_support_dir();
    patch_codex_config_at_with_relay_base(
        &home_path(".codex/config.toml"),
        &backup_root,
        relay_base_url,
    )
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

fn patch_codex_config_at_with_relay_base(
    path: &Path,
    backup_root: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let existing_body = if path.exists() {
        fs::read_to_string(path).ok()
    } else {
        None
    };
    if existing_body
        .as_deref()
        .is_some_and(|body| codex_config_has_relay_otel_for_base(body, relay_base_url))
    {
        return Ok(ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        });
    }
    if let Some(result) =
        patch_existing_codex_otel_table(path, backup_root, relay_base_url, existing_body.as_deref())
    {
        return result;
    }
    let body = render_codex_relay_toml_block_for_base(relay_base_url);
    if !codex_toml::upsert_would_change(path, &body).map_err(agent_config_error)? {
        return Ok(ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        });
    }
    let backup_created = backup_existing_config(SourceKind::Codex, path, backup_root)?.is_some();
    let write = codex_toml::upsert_fence(path, &body).map_err(agent_config_error)?;
    Ok(ConfigPatchResult {
        changed: write.changed,
        created: write.created,
        backup_created,
    })
}

fn patch_existing_codex_otel_table(
    path: &Path,
    backup_root: &Path,
    relay_base_url: &str,
    existing_body: Option<&str>,
) -> Option<Result<ConfigPatchResult, LocalApiError>> {
    let existing_body = existing_body?;
    let mut document = match existing_body.parse::<DocumentMut>() {
        Ok(document) => document,
        Err(_) => return None,
    };
    document.get("otel")?;
    let replacement =
        match render_codex_relay_toml_block_for_base(relay_base_url).parse::<DocumentMut>() {
            Ok(replacement) => replacement,
            Err(error) => {
                return Some(Err(LocalApiError::LocalOperationFailed(format!(
                    "generated Codex telemetry config is invalid: {error}"
                ))));
            }
        };
    document["otel"] = replacement["otel"].clone();
    let next_body = document.to_string();
    if next_body == existing_body {
        return Some(Ok(ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        }));
    }
    let backup_created = match backup_existing_config(SourceKind::Codex, path, backup_root) {
        Ok(value) => value.is_some(),
        Err(error) => return Some(Err(error)),
    };
    Some(
        write_config_body(path, next_body.as_bytes()).map(|()| ConfigPatchResult {
            changed: true,
            created: false,
            backup_created,
        }),
    )
}

fn write_config_body(path: &Path, body: &[u8]) -> Result<(), LocalApiError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| LocalApiError::StatePoisoned)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp_path, body).map_err(|_| LocalApiError::StatePoisoned)?;
    fs::rename(tmp_path, path).map_err(|_| LocalApiError::StatePoisoned)
}

fn remove_codex_config() -> Result<ConfigPatchResult, LocalApiError> {
    remove_codex_config_at(&home_path(".codex/config.toml"))
}

fn remove_codex_config_at(path: &Path) -> Result<ConfigPatchResult, LocalApiError> {
    let write = codex_toml::remove_fence(path).map_err(agent_config_error)?;
    Ok(ConfigPatchResult {
        changed: write.changed,
        created: false,
        backup_created: false,
    })
}

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

fn patch_claude_code_settings_with_relay_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let backup_root = default_support_dir();
    patch_claude_code_settings_at_with_relay_base(
        &home_path(".claude/settings.json"),
        machine,
        &backup_root,
        relay_base_url,
    )
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
        return Ok(ConfigPatchResult {
            changed: false,
            created: false,
            backup_created: false,
        });
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
            fs::set_permissions(env_path, permissions).map_err(|_| LocalApiError::StatePoisoned)?;
        }
    }

    let shell_write =
        claude_env::upsert_fence(shell_rc_path, shell_body).map_err(agent_config_error)?;

    Ok(ConfigPatchResult {
        changed: env_write.changed || shell_write.changed,
        created: env_write.created || shell_write.created,
        backup_created: env_backup_created || shell_backup_created,
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
    )
}

fn patch_claude_code_settings_at_with_relay_base(
    path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let created = !path.exists();
    let existing_settings = if created {
        json!({})
    } else {
        let body = fs::read_to_string(path).map_err(|_| LocalApiError::StatePoisoned)?;
        serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|_| LocalApiError::StatePoisoned)?
    };
    let mut settings = existing_settings.clone();
    if !settings.is_object() {
        settings = json!({});
    }
    let delegated_statusline = match existing_claude_statusline_command(&settings) {
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

    let env_value = object.entry("env").or_insert_with(|| json!({}));
    if !env_value.is_object() {
        *env_value = json!({});
    }
    let env = env_value
        .as_object_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    for (key, value) in claude_code_relay_env_with_base(machine, relay_base_url) {
        env.insert(key.to_string(), serde_json::Value::String(value));
    }

    let settings_changed = settings != existing_settings;
    let backup_created = if settings_changed {
        backup_existing_config(SourceKind::ClaudeCode, path, backup_root)?.is_some()
    } else {
        false
    };
    let (_statusline_script, wrapper_changed) =
        write_claude_statusline_wrapper(backup_root, delegated_statusline.as_deref())?;
    if !settings_changed {
        return Ok(ConfigPatchResult {
            changed: wrapper_changed,
            created: false,
            backup_created: false,
        });
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| LocalApiError::StatePoisoned)?;
    }
    let body = serde_json::to_vec_pretty(&settings).map_err(|_| LocalApiError::StatePoisoned)?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, body).map_err(|_| LocalApiError::StatePoisoned)?;
    fs::rename(tmp_path, path).map_err(|_| LocalApiError::StatePoisoned)?;
    Ok(ConfigPatchResult {
        changed: true,
        created,
        backup_created,
    })
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
    fs::create_dir_all(support_dir).map_err(|_| LocalApiError::StatePoisoned)?;
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
    fs::write(&tmp_path, script).map_err(|_| LocalApiError::StatePoisoned)?;
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(&tmp_path, permissions).map_err(|_| LocalApiError::StatePoisoned)?;
    }
    fs::rename(&tmp_path, &path).map_err(|_| LocalApiError::StatePoisoned)?;
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
        .map_err(|_| LocalApiError::StatePoisoned)?
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
    fs::create_dir_all(&backup_dir).map_err(|_| LocalApiError::StatePoisoned)?;
    fs::copy(path, backup_dir.join(format!("{backup_id}.{extension}")))
        .map_err(|_| LocalApiError::StatePoisoned)?;
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
        .map_err(|_| LocalApiError::StatePoisoned)?
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
    let relay_base = relay_base_url.trim_end_matches('/');
    vec![
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".to_string()),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1".to_string()),
        ("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS", "10000".to_string()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_string()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_string()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_string()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_string()),
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
                "service.name=claude-code,ottto.source=claude_code,ottto.machine_id={}",
                machine.machine_id
            ),
        ),
    ]
}

fn run_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    action: &SetupRunActionApiResponse,
    source: SourceKind,
) -> Result<(String, String, serde_json::Value), LocalApiError> {
    if source == SourceKind::Pi {
        return run_pi_verify_source_action(
            daemon,
            api_base_url,
            connection,
            setup_run_token,
            action,
        );
    }
    let smoke_after = current_rfc3339();
    let smoke = run_smoke_prompt(&source);
    record_setup_action_event(
        api_base_url,
        connection,
        setup_run_token,
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
        let result = smoke_failure_verification_result(source.clone(), &smoke, Some(smoke_after));
        daemon.record_verification_result(&result)?;
        let message = result.message.text.clone();
        return Ok((
            "failed".to_string(),
            message.clone(),
            json!({
                "verified": false,
                "records_seen": 0,
                "last_record_id": serde_json::Value::Null,
                "last_received_at": serde_json::Value::Null,
                "smoke_after": result.smoke_after,
                "smoke": smoke_result_metadata(&smoke),
                "error_code": smoke.error_code.as_deref().unwrap_or("smoke_command_failed"),
                "error_message": message,
            }),
        ));
    }
    let verification = wait_for_setup_run_verification_with_base(
        api_base_url,
        connection,
        setup_run_token,
        &source,
        &smoke_after,
        None,
    )?;
    let no_telemetry_code = no_fresh_telemetry_code(&source, &smoke);
    let verification_message = if verification.verified {
        format!(
            "Saw {} recent {} telemetry records.",
            verification.records_seen,
            source_display_name(&source)
        )
    } else if source == SourceKind::Pi && smoke.local_session_observed == Some(true) {
        "Pi created a local session, but Ottto did not receive matching telemetry for this setup run. Check the backend binding and local upload path, then retry Verify.".to_string()
    } else if source == SourceKind::Pi {
        "Pi smoke completed, but no new local Pi session file was observed and Ottto did not receive telemetry. Check the configured Pi provider route, then retry Verify.".to_string()
    } else {
        format!(
            "No fresh {} telemetry was processed after the smoke prompt.",
            source_display_name(&source)
        )
    };
    let result = verification_result(
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
            no_telemetry_code
        },
        &verification_message,
    );
    daemon.record_verification_result(&result)?;
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
            "error_code": if verification.verified { serde_json::Value::Null } else { json!(no_telemetry_code) },
            "error_message": if verification.verified { serde_json::Value::Null } else { json!(result.message.text) },
        }),
    ))
}

fn run_pi_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    action: &SetupRunActionApiResponse,
) -> Result<(String, String, serde_json::Value), LocalApiError> {
    let result = run_pi_route_verification(api_base_url, connection, setup_run_token)?;
    record_setup_action_event(
        api_base_url,
        connection,
        setup_run_token,
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
    let action_status = if result.verified {
        "succeeded"
    } else {
        "failed"
    };
    Ok((
        action_status.to_string(),
        message.clone(),
        json!({
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
        }),
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

fn run_smoke_prompt(source: &SourceKind) -> SmokeResult {
    let command = smoke_command(source);
    let before_session_count = if matches!(source, SourceKind::Pi) {
        Some(pi_session_file_count())
    } else {
        None
    };
    run_bounded_command(
        command.program,
        &command.args,
        SMOKE_COMMAND_TIMEOUT,
        source_display_name(source),
        before_session_count,
    )
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
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
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
                "--disallowedTools",
                "*",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        },
        SourceKind::Pi => pi_smoke_command(None),
    }
}

fn pi_smoke_command(route: Option<&PiModelRoute>) -> SmokeCommand {
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    let mut child = match command.spawn() {
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

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let diagnostic = read_command_diagnostic(&mut child);
                return SmokeResult {
                    command_found: true,
                    succeeded: status.success(),
                    exit_status: status.code(),
                    duration_ms: start.elapsed().as_millis(),
                    message: if status.success() {
                        format!("{display_name} smoke session completed.")
                    } else if let Some(diagnostic) = diagnostic.as_deref() {
                        format!(
                            "{display_name} smoke session failed before telemetry could be sent: {diagnostic}"
                        )
                    } else {
                        format!("{display_name} smoke session failed before telemetry could be sent. Check the local {display_name} auth and provider configuration, then retry Verify.")
                    },
                    diagnostic,
                    error_code: if status.success() {
                        None
                    } else {
                        Some("smoke_command_failed".to_string())
                    },
                    local_session_observed: local_session_observed(before_session_count),
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return SmokeResult {
                    command_found: true,
                    succeeded: false,
                    exit_status: None,
                    duration_ms: start.elapsed().as_millis(),
                    message: format!(
                        "{display_name} smoke session timed out before telemetry could be sent."
                    ),
                    diagnostic: None,
                    error_code: Some("smoke_timeout".to_string()),
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
    pi_session_files().len()
}

fn pi_session_files() -> BTreeSet<PathBuf> {
    pi_session_files_in(&home_path(".pi/agent/sessions"))
}

fn pi_session_files_in(root: &Path) -> BTreeSet<PathBuf> {
    let mut files = BTreeSet::new();
    collect_pi_session_files(root, &mut files);
    files
}

fn collect_pi_session_files(path: &Path, files: &mut BTreeSet<PathBuf>) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if metadata.is_file() {
        if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
            files.insert(path.to_path_buf());
        }
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        collect_pi_session_files(&entry.path(), files);
    }
}

fn import_new_pi_route_sessions(
    api_base_url: &str,
    route: &PiModelRoute,
    before_session_files: &BTreeSet<PathBuf>,
) -> Result<Option<serde_json::Value>, LocalApiError> {
    let session_files = pi_session_files()
        .difference(before_session_files)
        .cloned()
        .collect::<Vec<_>>();
    if session_files.is_empty() {
        return Ok(None);
    }
    let relay_token = issue_pi_relay_token(api_base_url)?;
    upload_pi_import_run(api_base_url, &relay_token, route, &session_files).map(Some)
}

#[derive(Debug, Deserialize)]
struct RelayTokenApiResponse {
    token: String,
}

fn issue_pi_relay_token(api_base_url: &str) -> Result<String, LocalApiError> {
    issue_source_relay_token(api_base_url, &SourceKind::Pi)
}

fn issue_source_relay_token(
    api_base_url: &str,
    source: &SourceKind,
) -> Result<String, LocalApiError> {
    let (device, device_secret) = crate::snapshot_client::load_snapshot_device_credentials()
        .map_err(|error| LocalApiError::LocalOperationFailed(error.to_string()))?;
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/telemetry/devices/{}/relay-token", device.device_id),
    );
    let response: RelayTokenApiResponse = ureq::post(&url)
        .set("Accept", "application/json")
        .set("X-Ottto-Device-Secret", &device_secret)
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_json(json!({ "source": source_slug(source) }))
        .map_err(|error| backend_error_from_ureq(&url, error))?
        .into_json()
        .map_err(|error| backend_response_unexpected(&url, error.to_string()))?;
    Ok(response.token)
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

fn emit_setup_run_verification_marker(
    api_base_url: &str,
    source: &SourceKind,
    connection: &LocalConnectionBinding,
    machine: &MachineIdentity,
) -> Result<String, LocalApiError> {
    let relay_token = issue_source_relay_token(api_base_url, source)?;
    let url = api_url_with_base(api_base_url, "/v1/metrics");
    let marker_id = format!("m3-{}-{}", source_slug(source), current_millis());
    let authorization = format!("Bearer {relay_token}");
    let body = verification_marker_body(
        source,
        Some(connection.setup_run_id.as_str()),
        Some(machine),
        &marker_id,
        None,
        None,
    );
    let _: serde_json::Value = backend_post_json(
        &url,
        &body,
        &[
            ("Authorization", authorization.as_str()),
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

fn upload_pi_import_run(
    api_base_url: &str,
    relay_token: &str,
    route: &PiModelRoute,
    session_files: &[PathBuf],
) -> Result<serde_json::Value, LocalApiError> {
    let boundary = format!("ottto-pi-route-{}", current_millis());
    let mut body = Vec::new();
    for (field, value) in pi_route_import_defaults(route) {
        append_multipart_text_field(&mut body, &boundary, field, &value);
    }
    for path in session_files {
        let content = fs::read(path)
            .map_err(|error| LocalApiError::LocalOperationFailed(error.to_string()))?;
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("session.jsonl");
        append_multipart_file_field(&mut body, &boundary, "files", file_name, &content);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let url = api_url_with_base(api_base_url, "/api/v1/pi/import-runs");
    let response = ureq::post(&url)
        .set("Accept", "application/json")
        .set("Authorization", &format!("Bearer {relay_token}"))
        .set(
            "Content-Type",
            &format!("multipart/form-data; boundary={boundary}"),
        )
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_bytes(&body)
        .map_err(|error| backend_error_from_ureq(&url, error))?;
    response
        .into_json()
        .map_err(|error| backend_response_unexpected(&url, error.to_string()))
}

fn pi_route_import_defaults(route: &PiModelRoute) -> Vec<(&'static str, String)> {
    let mut defaults = Vec::new();
    if let Some(value) = route.classification.billing_provider.clone() {
        defaults.push(("billing_provider", value));
    }
    if let Some(value) = route.classification.model_provider.clone() {
        defaults.push(("model_provider", value));
    }
    if let Some(value) = route.classification.billing_channel.clone() {
        defaults.push(("billing_channel", value));
    }
    if let Some(value) = route.classification.auth_mode.clone() {
        defaults.push(("auth_mode", value));
    }
    if let Some(value) = route.classification.gateway_provider.clone() {
        defaults.push(("gateway_provider", value));
    }
    if let Some(value) = route.classification.subscription_product.clone() {
        defaults.push(("subscription_product", value));
    }
    defaults
}

fn append_multipart_text_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
            multipart_token(name)
        )
        .as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

fn append_multipart_file_field(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    file_name: &str,
    content: &[u8],
) {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
            multipart_token(name),
            multipart_token(file_name),
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/x-ndjson\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
}

fn multipart_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '"' | '\r' | '\n' => '_',
            _ => ch,
        })
        .collect()
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

fn read_command_diagnostic(child: &mut std::process::Child) -> Option<String> {
    let stderr = read_redacted_pipe(&mut child.stderr);
    let stdout = read_redacted_pipe(&mut child.stdout);
    match (stderr, stdout) {
        (Some(stderr), Some(stdout)) => Some(format!("{stderr}; stdout: {stdout}")),
        (Some(stderr), None) => Some(stderr),
        (None, Some(stdout)) => Some(stdout),
        (None, None) => None,
    }
}

fn read_redacted_pipe<R: Read>(pipe: &mut Option<R>) -> Option<String> {
    let mut output = String::new();
    if let Some(mut pipe) = pipe.take() {
        let _ = pipe.read_to_string(&mut output);
    }
    redact_command_diagnostic(&output)
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
            if trimmed.starts_with('/')
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
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Failed,
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

fn build_local_scan(
    machine: &MachineIdentity,
    requested_sources: Vec<SourceKind>,
) -> SetupScanPayload {
    let source_filter = if requested_sources.is_empty() {
        vec![SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi]
    } else {
        requested_sources
    };
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
    match source {
        SourceKind::Codex => {
            let command_found = executable_exists("codex");
            let config = home_path(".codex/config.toml");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = config_body
                .as_deref()
                .is_some_and(telemetry_config_installed);
            setup_scan_source(
                source,
                "codex",
                command_found || config.exists(),
                command_found,
                telemetry_installed,
                if telemetry_installed {
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
            )
        }
        SourceKind::ClaudeCode => {
            let command_found = executable_exists("claude");
            let config = home_path(".claude/settings.json");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = config_body
                .as_deref()
                .is_some_and(claude_code_telemetry_config_installed);
            setup_scan_source(
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
            )
        }
        SourceKind::Pi => {
            let command_found = executable_exists("pi");
            let sessions = home_path(".pi/agent/sessions");
            let telemetry_installed = snapshot_device_credentials_include_source("pi");
            setup_scan_source(
                source,
                "pi",
                command_found || sessions.exists(),
                command_found,
                telemetry_installed,
                if telemetry_installed {
                    "healthy"
                } else if command_found || sessions.exists() {
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
    SetupScanSource {
        source,
        detected,
        installed,
        telemetry_installed,
        local_health,
        missing_fields: Vec::new(),
        attribution_guess,
        agent_status: Some(local_agent_status(source_kind).redacted_for_backend()),
    }
}

fn local_agent_status(source: &SourceKind) -> AgentStatusSnapshot {
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    crate::agent_status::collect_agent_status(source, captured_at, expires_at)
}

fn read_optional_to_string(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn telemetry_config_installed(body: &str) -> bool {
    let relay_port = codex_config_relay_port(body);
    relay_port.is_some()
        && relay_port.is_some_and(loopback_listener_available)
        && snapshot_device_credentials_include_source(crate::otlp_relay::CODEX_RELAY_SOURCE)
}

#[cfg(test)]
fn codex_config_has_relay_otel(body: &str) -> bool {
    codex_config_relay_port(body).is_some()
}

fn codex_config_has_relay_otel_for_base(body: &str, relay_base_url: &str) -> bool {
    codex_config_relay_port(body).is_some_and(|port| {
        crate::otlp_relay::local_relay_base_url_for_port(port)
            == relay_base_url.trim_end_matches('/')
    })
}

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

#[cfg(test)]
fn codex_exporter_has_relay(otel: &Table, exporter_key: &str, signal: &str) -> bool {
    let expected_port = crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT;
    codex_exporter_relay_port(otel, exporter_key, signal) == Some(expected_port)
}

fn codex_exporter_relay_port(otel: &Table, exporter_key: &str, signal: &str) -> Option<u16> {
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
    if otlp_http
        .get("protocol")
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())
        != Some("binary")
    {
        return None;
    }
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
        && relay_port.is_some_and(loopback_listener_available)
        && snapshot_device_credentials_include_source(crate::otlp_relay::CLAUDE_CODE_RELAY_SOURCE)
}

fn snapshot_device_credentials_include_source(source: &str) -> bool {
    crate::snapshot_client::load_snapshot_device_credentials()
        .ok()
        .is_some_and(|(device, _secret)| {
            device
                .sources
                .iter()
                .any(|configured_source| configured_source == source)
        })
}

fn claude_code_settings_has_relay_env(body: &str) -> bool {
    claude_code_settings_relay_port(body).is_some()
}

#[cfg(test)]
fn claude_code_settings_has_relay_env_for_base(body: &str, relay_base_url: &str) -> bool {
    claude_code_settings_relay_port(body).is_some_and(|port| {
        crate::otlp_relay::local_relay_base_url_for_port(port)
            == relay_base_url.trim_end_matches('/')
    })
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

fn is_trusted_api_base_url(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }

    value == DEFAULT_API_BASE_URL
        || value == DIRECT_API_BASE_URL
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

fn verify_source(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    repair: bool,
) -> Result<SourceVerificationResult, LocalApiError> {
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
        if !config.drift.is_empty() {
            let result = config_drift_verification_result(source, config, repair);
            daemon.record_verification_result(&result)?;
            return Ok(result);
        }
    }

    let status = status_for(daemon, authorization)?;
    if status.account.state != LocalAccountState::Connected {
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
            "This Mac needs to reconnect to Ottto. Open ottto.net/apps in your browser to refresh, then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    };

    let setup_run_token = match KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() {
        Ok(token) => token,
        Err(_) => {
            match refresh_setup_run_token_via_device_secret(&connection.api_base_url, &connection) {
                Ok(token) => token,
                Err(_) => {
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
                    "This Mac's local Ottto connection needs a fresh sign-in. Open Ottto in your browser, then try verifying again.",
                );
                    daemon.record_verification_result(&result)?;
                    return Ok(result);
                }
            }
        }
    };

    if source == SourceKind::Pi {
        let pi_token = setup_run_token.clone();
        let result =
            match run_pi_route_verification(&connection.api_base_url, &connection, &pi_token) {
                Ok(result) => result,
                Err(LocalApiError::Backend(details)) if details.status == Some(401) => {
                    // Token expired mid-Pi-verify. Try a single refresh + retry.
                    match refresh_setup_run_token_via_device_secret(
                        &connection.api_base_url,
                        &connection,
                    ) {
                        Ok(fresh_token) => match run_pi_route_verification(
                            &connection.api_base_url,
                            &connection,
                            &fresh_token,
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

    let smoke_after = current_rfc3339();
    let smoke = run_smoke_prompt(&source);
    let result = if !smoke.succeeded {
        smoke_failure_verification_result_with_config(
            source.clone(),
            config,
            &smoke,
            Some(smoke_after),
        )
    } else {
        match wait_for_verification_with_refresh(
            &connection.api_base_url,
            &connection,
            &setup_run_token,
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
                &format!(
                    "Saw {} recent {} telemetry {}.",
                    response.records_seen,
                    source_display_name(&source),
                    if response.records_seen == 1 {
                        "record"
                    } else {
                        "records"
                    }
                ),
            ),
            Ok(response) => verification_result_with_config(
                source.clone(),
                config,
                SourceVerificationStatus::NoFreshTelemetry,
                false,
                response.records_seen,
                response.last_record_id,
                response.last_received_at,
                Some(response.smoke_after),
                no_fresh_telemetry_code(&source, &smoke),
                &no_fresh_telemetry_message(&source, &smoke),
            ),
            Err(error) => verification_result_for_backend_error_with_config(
                source,
                config,
                Some(smoke_after),
                &error,
            ),
        }
    };
    daemon.record_verification_result(&result)?;
    Ok(result)
}

fn run_pi_route_verification(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
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

    let route_results = routes
        .iter()
        .map(|route| {
            run_one_pi_route_verification(api_base_url, connection, setup_run_token, route)
        })
        .collect::<Vec<_>>();
    Ok(pi_route_aggregate_result(route_results))
}

fn run_one_pi_route_verification(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    route: &PiModelRoute,
) -> SourceRouteVerificationResult {
    let before_session_files = pi_session_files();
    let smoke_after = current_rfc3339();
    let smoke = run_pi_route_smoke_prompt(route, Some(before_session_files.len()));
    if !smoke.succeeded {
        return pi_route_result_from_smoke(route, &smoke, Some(smoke_after));
    }
    if let Err(error) = import_new_pi_route_sessions(api_base_url, route, &before_session_files) {
        eprintln!("Pi route smoke session import failed: {error}");
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
    match wait_for_setup_run_verification_with_base(
        api_base_url,
        connection,
        setup_run_token,
        &SourceKind::Pi,
        &smoke_after,
        filters.as_ref(),
    ) {
        Ok(verification) => pi_route_result_from_verification(route, &smoke, verification),
        Err(error) => pi_route_result_from_backend_error(route, &smoke, Some(smoke_after), &error),
    }
}

fn run_pi_route_smoke_prompt(
    route: &PiModelRoute,
    before_session_count: Option<usize>,
) -> SmokeResult {
    let command = pi_smoke_command(Some(route));
    run_bounded_command(
        command.program,
        &command.args,
        SMOKE_COMMAND_TIMEOUT,
        "Pi",
        before_session_count,
    )
}

fn pi_route_billing_identity_hints(route: &PiModelRoute) -> BillingIdentityHints {
    let auth = read_pi_agent_auth();
    pi_identity_hints_for_route(auth.as_ref(), route)
}

fn pi_route_result_from_smoke(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceRouteVerificationResult {
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
    }
}

fn pi_route_result_from_verification(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    verification: SetupRunVerificationResponse,
) -> SourceRouteVerificationResult {
    let identity = pi_route_billing_identity_hints(route);
    let status = if verification.verified {
        SourceVerificationStatus::Verified
    } else {
        SourceVerificationStatus::NoFreshTelemetry
    };
    let code = if verification.verified {
        "verified".to_string()
    } else {
        no_fresh_telemetry_code(&SourceKind::Pi, smoke).to_string()
    };
    let text = if verification.verified {
        format!(
            "Saw {} recent Pi telemetry records for {}.",
            verification.records_seen,
            pi_route_label(route)
        )
    } else {
        format!(
            "Pi route {} completed smoke, but Ottto did not receive matching telemetry.",
            pi_route_label(route)
        )
    };
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
        status,
        verified: verification.verified,
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
        status: source_result.status,
        verified: false,
        records_seen: 0,
        last_record_id: None,
        last_received_at: None,
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
    }
}

fn pi_route_aggregate_result(
    route_results: Vec<SourceRouteVerificationResult>,
) -> SourceVerificationResult {
    let total = route_results.len();
    let passed = route_results.iter().filter(|route| route.verified).count();
    let status = if total > 0 && passed == total {
        SourceVerificationStatus::Verified
    } else if passed > 0 {
        SourceVerificationStatus::Warning
    } else {
        SourceVerificationStatus::Failed
    };
    let (code, text) = match status {
        SourceVerificationStatus::Verified => ("verified", format!("Verified {total} Pi model routes.")),
        SourceVerificationStatus::Warning => (
            "pi_route_warnings",
            format!(
                "Verified {passed} of {total} Pi model routes; review warnings for the failed routes."
            ),
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
        verified: passed > 0,
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
    }
}

fn config_drift_verification_result(
    source: SourceKind,
    config: SourceConfigState,
    repair_requested: bool,
) -> SourceVerificationResult {
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
            "{} telemetry config is missing. Run `ottto verify --repair --app {}` or `ottto fix --app {}`.",
            source_display_name(&source),
            source_slug(&source),
            source_slug(&source)
        )
    } else {
        format!(
            "{} telemetry config does not match the active Ottto relay. Run `ottto verify --repair --app {}` or `ottto fix --app {}`.",
            source_display_name(&source),
            source_slug(&source),
            source_slug(&source)
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
            "This Mac needs to reconnect to Ottto. Open ottto.net/apps in your browser to refresh it, then try verifying again.",
        );
    }
    if let LocalApiError::Backend(details) = error {
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
                "Your Ottto session has expired. Open ottto.net/apps in your browser to refresh it, then try verifying again.",
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
                "We can't find an active Ottto session for this Mac. Open ottto.net/apps in your browser to start one, then try verifying again.",
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
                "Ottto couldn't verify this source. Open ottto.net/apps in your browser to refresh your session, then try again.",
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

fn no_fresh_telemetry_message(source: &SourceKind, smoke: &SmokeResult) -> String {
    if source == &SourceKind::Pi && smoke.local_session_observed == Some(true) {
        return "Pi created a local session, but Ottto did not receive matching telemetry for this setup run. Check the backend binding and local upload path, then retry Verify.".to_string();
    }
    if source == &SourceKind::Pi {
        return "Pi smoke completed, but no new local Pi session file was observed and Ottto did not receive telemetry. Check the configured Pi provider route, then retry Verify.".to_string();
    }
    format!(
        "No {} telemetry arrived after the smoke session. Check that {} telemetry export is enabled, then retry Verify.",
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
}

#[derive(Debug, Clone, Default)]
struct SetupRunVerificationFilters {
    model: Option<String>,
    model_provider: Option<String>,
    billing_provider: Option<String>,
}

fn get_setup_run_verification_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
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
    let query = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_url_encode(key), form_url_encode(&value)))
        .collect::<Vec<_>>()
        .join("&");
    let url = format!("{url}?{query}");
    backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
}

fn backend_post_json<T: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    let mut request = ureq::post(url)
        .set("Accept", "application/json")
        .timeout(BACKEND_REQUEST_TIMEOUT);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .send_json(body)
        .map_err(|error| backend_error_from_ureq(url, error))?;
    response
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

fn backend_get_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    let mut request = ureq::get(url)
        .set("Accept", "application/json")
        .timeout(BACKEND_REQUEST_TIMEOUT);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .call()
        .map_err(|error| backend_error_from_ureq(url, error))?;
    response
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

fn backend_error_from_ureq(url: &str, error: ureq::Error) -> LocalApiError {
    match error {
        ureq::Error::Status(status, response) => {
            let body_excerpt = response
                .into_string()
                .ok()
                .and_then(|body| safe_backend_body_excerpt(&body));
            LocalApiError::Backend(BackendErrorDetails {
                kind: if status >= 500 {
                    BackendErrorKind::Unavailable
                } else {
                    BackendErrorKind::Rejected
                },
                endpoint: safe_backend_endpoint(url),
                status: Some(status),
                body_excerpt,
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
    })
}

fn safe_backend_endpoint(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn safe_backend_body_excerpt(body: &str) -> Option<String> {
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

fn wait_for_setup_run_verification_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    let start = Instant::now();
    loop {
        let response = get_setup_run_verification_with_base(
            api_base_url,
            connection,
            setup_run_token,
            source,
            smoke_after,
            filters,
        )?;
        if response.verified || start.elapsed() >= VERIFICATION_WAIT_TIMEOUT {
            return Ok(response);
        }
        thread::sleep(VERIFICATION_POLL_INTERVAL);
    }
}

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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
mod tests {
    use super::*;
    use crate::keychain::{
        TelemetryKeyStore, TelemetryKeychainError, TELEMETRY_KEY_FILE_STORE_ENV,
    };
    use crate::{ControlToken, LocalDaemon};
    use ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV;
    use ottto_protocol::{LocalClientKind, MachineIdentity, OperatingSystem, SecretString};
    use serial_test::serial;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    // The per-file Mutex below serializes tests within control.rs that mutate
    // shared process env vars (HOME, OTTTO_*). The #[serial] markers on each
    // such test extend that boundary across the entire ottto-service test
    // binary so that other modules whose tests merely *read* HOME (snapshot_sync,
    // agent_status, agent_configs::detection, etc.) cannot observe HOME
    // mid-swap. Two named tests — verify_repair_repairs_codex_config_before_account_check
    // and verify_without_local_account_points_to_app_sign_in — failed at full
    // --test-threads, pass at 4; #[serial] on all env-mutating tests is the
    // robust fix, since the per-file Mutex only protects against intra-file
    // contention.
    static TELEMETRY_CONTROL_BACKEND_TEST_LOCK: Mutex<()> = Mutex::new(());
    static TELEMETRY_KEY_STORE_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Acquire the backend/env test lock, tolerating a poisoned mutex.
    ///
    /// The guarded value is `()` and every caller restores the process env it
    /// mutated via `EnvVarGuard` on scope exit, so a panic inside one critical
    /// section leaves no shared state for the next test to observe. Recovering
    /// the guard with `into_inner()` keeps a single legitimate test failure from
    /// cascading into a wall of spurious `PoisonError` panics in every later
    /// test that takes this lock — which is exactly what masked the real
    /// failure when these tests raced at full `--test-threads`.
    fn lock_backend_test_env() -> std::sync::MutexGuard<'static, ()> {
        TELEMETRY_CONTROL_BACKEND_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            Self::set_os(key, value.as_os_str().to_os_string())
        }

        fn set_str(key: &'static str, value: &str) -> Self {
            Self::set_os(key, OsString::from(value))
        }

        fn set_os(key: &'static str, value: OsString) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn telemetry_key_store_root(name: &str) -> PathBuf {
        let counter = TELEMETRY_KEY_STORE_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ottto-telemetry-control-{name}-{}-{counter}",
            std::process::id(),
        ))
    }

    fn control_test_root(name: &str) -> PathBuf {
        let counter = TELEMETRY_KEY_STORE_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ottto-control-{name}-{}-{}-{counter}",
            std::process::id(),
            current_millis()
        ));
        let _ = fs::remove_dir_all(&root);
        create_control_test_dir(&root);
        root
    }

    fn create_control_test_dir(path: &Path) {
        fs::create_dir_all(path).expect("create control test dir");
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("set control test dir permissions");
        }
    }

    fn fake_binary_path(root: &Path, name: &str) -> PathBuf {
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("fake bin dir");
        let binary = bin_dir.join(name);
        fs::write(&binary, "#!/bin/sh\n").expect("fake binary");
        binary
    }

    fn count_backup_files(path: &Path) -> usize {
        fs::read_dir(path)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .metadata()
                            .map(|metadata| metadata.is_file())
                            .unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[test]
    fn handles_authenticated_status_request() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_test".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        );

        assert!(response.ok, "{response:?}");
        assert_eq!(response.error, None);
        assert_eq!(
            response.payload.expect("payload").get("daemon"),
            Some(&serde_json::Value::String("running".to_string()))
        );
    }

    #[test]
    fn maps_bad_token_to_local_auth_error() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_test".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("bad-token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalAuthFailed
        );
    }

    #[test]
    fn browser_claim_commands_accept_cli_token_authorization_boundary() {
        for command in [
            LocalControlCommand::AuthStart,
            LocalControlCommand::AuthComplete {
                claim_code: "claim_test".to_string(),
                nonce: "nonce_test".to_string(),
            },
        ] {
            let response = handle_request(
                &daemon(),
                LocalControlRequest {
                    request_id: "req_cli_browser_claim".to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    token: Some("bad-token".to_string()),
                    client_kind: Some(LocalClientKind::Cli),
                    client_install_owner: None,
                    command,
                },
            );

            assert!(!response.ok);
            assert_eq!(
                response.error.expect("error").code,
                CliErrorCode::LocalAuthFailed
            );
        }
    }

    #[test]
    #[serial]
    fn logout_without_cloud_connection_points_to_local_only_escape_hatch() {
        let support_root = telemetry_key_store_root("logout-missing-connection");
        let _support_guard =
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_root);
        let response = handle_request(
            &daemon().with_account(connected_account()),
            LocalControlRequest {
                request_id: "req_logout_missing_connection".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::AuthReset { local_only: false },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error.message.contains("--local-only"));
    }

    #[test]
    #[serial]
    fn logout_backend_unavailable_preserves_local_state() {
        let secret_root = telemetry_key_store_root("logout-unavailable");
        fs::create_dir_all(&secret_root).expect("secret root");
        fs::write(secret_root.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT), "otsr_test")
            .expect("setup-run token");
        let _secret_guard = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_root);
        let api_base_url = unused_loopback_base_url();
        let daemon = daemon()
            .with_account(connected_account())
            .with_connection(Some(LocalConnectionBinding {
                setup_run_id: "setup_unavailable".to_string(),
                setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
                machine_id: Some("machine_test".to_string()),
                api_base_url,
            }));

        let response = handle_request(
            &daemon,
            LocalControlRequest {
                request_id: "req_logout_backend_unavailable".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::AuthReset { local_only: false },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::BackendUnreachable);
        assert!(error
            .message
            .contains("logout did not clear local credentials"));
        assert!(error
            .details
            .get("endpoint")
            .and_then(|value| match value {
                RedactedValue::String(endpoint) => Some(endpoint.as_str()),
                _ => None,
            })
            .is_some_and(|endpoint| endpoint
                .ends_with("/api/v1/setup-runs/setup_unavailable/local-client/disconnect")));
        assert_eq!(
            daemon
                .status("token")
                .expect("local state remains")
                .account
                .state,
            LocalAccountState::Connected
        );
        assert!(daemon
            .connection_for_authorized_client()
            .expect("connection lookup")
            .is_some());
    }

    #[test]
    fn raw_local_control_json_rejects_stale_protocol_version() {
        let response = handle_request_json_with_peer(
            &daemon(),
            r#"{"request_id":"req_stale","protocol_version":10,"token":"token","client_kind":"cli","command":"status"}"#,
            None,
        );
        let response: LocalControlResponse =
            serde_json::from_str(&response).expect("local control response");

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error
            .message
            .contains("unsupported local control protocol_version 10"));
    }

    #[test]
    fn typed_local_control_request_rejects_stale_protocol_version() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_typed_stale".to_string(),
                protocol_version: 10,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error
            .message
            .contains("unsupported local control protocol_version 10"));
    }

    #[test]
    fn validated_api_base_url_rejects_untrusted_https_origin() {
        assert!(validated_api_base_url(Some("https://attacker.example")).is_err());
    }

    #[test]
    fn validated_api_base_url_accepts_default_origin() {
        assert_eq!(
            validated_api_base_url(Some(DEFAULT_API_BASE_URL)).expect("valid"),
            DEFAULT_API_BASE_URL.to_string()
        );
    }

    #[test]
    fn validated_api_base_url_accepts_direct_production_origin() {
        assert_eq!(
            validated_api_base_url(Some(DIRECT_API_BASE_URL)).expect("valid"),
            DIRECT_API_BASE_URL.to_string()
        );
    }

    #[test]
    fn commits_equivalent_handles_short_and_long_hashes() {
        assert!(commits_equivalent("436d0f2a", "436d0f2a2352"));
        assert!(commits_equivalent("436d0f2a2352", "436D0F2A"));
        assert!(!commits_equivalent("436d0f2a", "deadbeef"));
        assert!(!commits_equivalent("436", "436d0f2a"));
        assert!(commits_equivalent("", ""));
    }

    #[test]
    fn version_tuple_collapses_dev_suffixes() {
        // Documents the prior false-current bug: dev builds with different
        // commits collapse to the same semver tuple, so commit comparison must
        // be the disambiguator.
        assert_eq!(
            version_tuple("0.1.0-dev-436d0f2a"),
            version_tuple("0.1.0-dev-deadbeef")
        );
    }

    fn release_manifest_for_update(
        version: &str,
        min_supported_version: Option<&str>,
        min_protocol_version: Option<u16>,
    ) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            product: "ottto-local-platform".to_string(),
            version: version.to_string(),
            channel: ReleaseChannel::Dev,
            commit: "deadbeef".to_string(),
            min_supported_version: min_supported_version.unwrap_or("0.1.0").to_string(),
            min_protocol_version: min_protocol_version.unwrap_or(PROTOCOL_VERSION),
            supported_install_owners: vec![
                InstallOwner::Homebrew,
                InstallOwner::HostedInstaller,
                InstallOwner::AppBundle,
            ],
            rollback: ReleaseRollback {
                strategy: "channel_latest_pointer".to_string(),
                immutable_prefix:
                    "https://install.ottto.net/ottto-local-platform/releases/dev/latest"
                        .to_string(),
                latest_manifest_url:
                    "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json"
                        .to_string(),
                preserve_failed_version: true,
            },
            artifacts: vec![ReleaseArtifact {
                kind: "macos_app".to_string(),
                platform: "macos".to_string(),
                arch: "universal".to_string(),
                url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/Ottto-macos-universal.dmg".to_string(),
            }],
        }
    }

    #[test]
    fn release_manifest_deserialization_requires_update_and_rollback_metadata() {
        let mut manifest = json!({
            "schema_version": 1,
            "product": "ottto-local-platform",
            "version": "0.2.0",
            "channel": "dev",
            "commit": "deadbeef",
            "min_supported_version": "0.1.0",
            "min_protocol_version": PROTOCOL_VERSION,
            "supported_install_owners": ["homebrew", "hosted_installer", "app_bundle"],
            "rollback": {
                "strategy": "channel_latest_pointer",
                "immutable_prefix": "https://install.ottto.net/ottto-local-platform/releases/dev/latest",
                "latest_manifest_url": "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json",
                "preserve_failed_version": true
            },
            "artifacts": [{
                "kind": "macos_app",
                "platform": "macos",
                "arch": "universal",
                "url": "https://install.ottto.net/ottto-local-platform/releases/dev/latest/Ottto-macos-universal.dmg"
            }]
        });

        serde_json::from_value::<ReleaseManifest>(manifest.clone()).expect("valid manifest");

        manifest
            .as_object_mut()
            .expect("manifest object")
            .remove("rollback");
        assert!(serde_json::from_value::<ReleaseManifest>(manifest).is_err());
    }

    #[test]
    fn update_state_soft_warns_for_supported_outdated_homebrew_install() {
        let state = update_state_from_manifest(
            release_manifest_for_update("0.2.0", Some("0.1.0"), None),
            "0.1.0".to_string(),
            ReleaseChannel::Dev,
            Some("2026-05-20T00:00:00Z".to_string()),
            Some("deadbeef".to_string()),
            InstallOwner::Homebrew,
        );

        assert_eq!(state.status, UpdateStatus::UpdateAvailable);
        assert_eq!(state.gate, UpdateGate::SoftWarn);
        assert_eq!(state.install_owner, InstallOwner::Homebrew);
        assert_eq!(
            state.update_command.as_deref(),
            Some("brew update && brew upgrade ottto")
        );
        assert!(state
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("newer release manifest version"));
    }

    #[test]
    fn update_state_hard_blocks_below_min_supported_version() {
        let state = update_state_from_manifest(
            release_manifest_for_update("0.2.0", Some("0.1.0"), None),
            "0.0.9".to_string(),
            ReleaseChannel::Dev,
            Some("2026-05-20T00:00:00Z".to_string()),
            Some("deadbeef".to_string()),
            InstallOwner::HostedInstaller,
        );

        assert_eq!(state.status, UpdateStatus::UpdateAvailable);
        assert_eq!(state.gate, UpdateGate::HardBlock);
        assert_eq!(state.install_owner, InstallOwner::HostedInstaller);
        assert_eq!(
            state.update_command.as_deref(),
            Some("curl -fsSL https://ottto.net/install.sh | bash")
        );
        assert!(state
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("minimum supported version"));
    }

    #[test]
    fn update_state_hard_blocks_protocol_incompatible_app_bundle() {
        let state = update_state_from_manifest(
            release_manifest_for_update("0.2.0", Some("0.1.0"), Some(PROTOCOL_VERSION + 1)),
            "0.1.0".to_string(),
            ReleaseChannel::Dev,
            Some("2026-05-20T00:00:00Z".to_string()),
            Some("deadbeef".to_string()),
            InstallOwner::AppBundle,
        );

        assert_eq!(state.status, UpdateStatus::UpdateAvailable);
        assert_eq!(state.gate, UpdateGate::HardBlock);
        assert_eq!(state.install_owner, InstallOwner::AppBundle);
        assert_eq!(state.update_command, None);
        assert!(state
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("requires local protocol"));
    }

    #[test]
    fn update_state_avoids_owner_command_when_manifest_does_not_support_detected_owner() {
        let mut manifest = release_manifest_for_update("0.2.0", Some("0.1.0"), None);
        manifest.supported_install_owners = vec![InstallOwner::HostedInstaller];

        let state = update_state_from_manifest(
            manifest,
            "0.1.0".to_string(),
            ReleaseChannel::Dev,
            Some("2026-05-20T00:00:00Z".to_string()),
            Some("deadbeef".to_string()),
            InstallOwner::Homebrew,
        );

        assert_eq!(state.status, UpdateStatus::UpdateAvailable);
        assert_eq!(state.gate, UpdateGate::SoftWarn);
        assert_eq!(state.install_owner, InstallOwner::Homebrew);
        assert_eq!(state.update_command, None);
        assert!(state
            .update_instructions
            .as_deref()
            .unwrap_or_default()
            .contains("does not advertise an update route"));
    }

    #[test]
    fn update_state_rejects_manifest_without_supported_install_owners() {
        let mut manifest = release_manifest_for_update("0.2.0", Some("0.1.0"), None);
        manifest.supported_install_owners.clear();

        let state = update_state_from_manifest(
            manifest,
            "0.1.0".to_string(),
            ReleaseChannel::Dev,
            Some("2026-05-20T00:00:00Z".to_string()),
            Some("deadbeef".to_string()),
            InstallOwner::Homebrew,
        );

        assert_eq!(state.status, UpdateStatus::Unknown);
        assert_eq!(state.gate, UpdateGate::Unknown);
        assert_eq!(state.update_command, None);
        assert!(state
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("supported install owners"));
    }

    #[test]
    fn install_owner_detection_routes_known_install_paths() {
        assert_eq!(
            install_owner_for_path(Path::new(
                "/opt/homebrew/Cellar/ottto/0.1.0/bin/ottto-service"
            )),
            InstallOwner::Homebrew
        );
        assert_eq!(
            install_owner_for_path(Path::new("/Users/ron/.ottto/bin/ottto-service")),
            InstallOwner::HostedInstaller
        );
        assert_eq!(
            install_owner_for_path(Path::new(
                "/Users/ron/Applications/Ottto.app/Contents/Helpers/ottto-service"
            )),
            InstallOwner::AppBundle
        );
    }

    #[test]
    fn default_release_manifest_url_follows_local_channel() {
        assert_eq!(
            default_release_manifest_url(&ReleaseChannel::Dev),
            "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json"
        );
        assert_eq!(
            default_release_manifest_url(&ReleaseChannel::Preview),
            "https://install.ottto.net/ottto-local-platform/releases/preview/latest/release-manifest.json"
        );
        assert_eq!(
            default_release_manifest_url(&ReleaseChannel::StableCandidate),
            "https://install.ottto.net/ottto-local-platform/releases/stable-candidate/latest/release-manifest.json"
        );
        assert_eq!(
            default_release_manifest_url(&ReleaseChannel::Stable),
            "https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json"
        );
    }

    #[test]
    fn trusted_companion_can_read_status_without_keychain_token() {
        let response = handle_request_with_peer(
            &daemon(),
            LocalControlRequest {
                request_id: "req_app_status".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::CompanionApp),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
            Some(LocalClientPeer::trusted_for_tests()),
        );

        assert!(response.ok, "{response:?}");
        assert_eq!(response.error, None);
    }

    #[test]
    fn companion_without_trusted_peer_is_rejected() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_app_status".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::CompanionApp),
                client_install_owner: None,
                command: LocalControlCommand::Status {
                    refresh_agent_status: false,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalClientNotTrusted
        );
    }

    #[test]
    fn uninstall_plan_is_typed_and_cloud_safe() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_uninstall_plan".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::UninstallPlan,
            },
        );

        assert!(response.ok, "{response:?}");
        let payload = response.payload.expect("payload");
        assert_eq!(
            payload.get("cloud_credentials_untouched"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            payload.get("requires_confirmation"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn uninstall_execute_requires_confirmation() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_uninstall_execute".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::UninstallExecute { confirm: false },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::InvalidRequest
        );
    }

    #[test]
    fn diagnostics_collect_is_local_only_without_upload() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_local_only".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: false,
                    upload_approval: None,
                    api_base_url: None,
                },
            },
        );

        assert!(response.ok, "{response:?}");
        let payload = response.payload.expect("payload");
        assert!(payload
            .get("bundle_id")
            .and_then(|value| value.as_str())
            .is_some_and(|bundle_id| bundle_id.starts_with("diag_")));
        let upload = payload.get("upload").expect("upload report");
        assert_eq!(
            upload.get("status").and_then(|value| value.as_str()),
            Some("local_only")
        );
        assert_eq!(
            upload.get("requested").and_then(|value| value.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn diagnostics_upload_requires_explicit_approval() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_upload_missing_approval".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval: None,
                    api_base_url: None,
                },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error.message.contains("--approve-upload"));
    }

    #[test]
    fn diagnostics_upload_requires_retention_disclosure() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_upload_missing_retention".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval: Some(DiagnosticsUploadApproval {
                        approved: true,
                        retention_disclosure_accepted: false,
                        support_claim: Some("support_123".to_string()),
                    }),
                    api_base_url: None,
                },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error.message.contains("--accept-retention-disclosure"));
    }

    #[test]
    fn diagnostics_upload_requires_login_or_support_claim() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_upload_missing_auth".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval: Some(DiagnosticsUploadApproval {
                        approved: true,
                        retention_disclosure_accepted: true,
                        support_claim: None,
                    }),
                    api_base_url: None,
                },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert!(error.message.contains("Ottto login or --support-claim"));
    }

    #[test]
    fn diagnostics_upload_with_support_claim_posts_redacted_bundle() {
        let captured = Arc::new(Mutex::new(None));
        let api_base_url = diagnostics_upload_server(captured.clone());
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_support_upload".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval: Some(DiagnosticsUploadApproval {
                        approved: true,
                        retention_disclosure_accepted: true,
                        support_claim: Some("support_123".to_string()),
                    }),
                    api_base_url: Some(api_base_url),
                },
            },
        );

        assert!(response.ok, "{response:?}");
        let payload = response.payload.expect("payload");
        let upload = payload.get("upload").expect("upload report");
        assert_eq!(
            upload.get("status").and_then(|value| value.as_str()),
            Some("uploaded")
        );
        assert_eq!(
            upload.get("authorization").and_then(|value| value.as_str()),
            Some("support_claim")
        );
        assert_eq!(
            upload
                .get("support_claim_provided")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            upload.get("upload_id").and_then(|value| value.as_str()),
            Some("diag_upload_123")
        );

        let request = captured
            .lock()
            .expect("captured request lock")
            .clone()
            .expect("request captured");
        assert!(request.starts_with("POST /api/v1/diagnostics/support-bundles HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("x-ottto-support-claim: support_123"));
        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(body.contains("\"retention_disclosure_accepted\":true"));
        assert!(body.contains("\"support_claim_provided\":true"));
        assert!(!body.contains("support_123"));
    }

    #[test]
    fn diagnostics_upload_no_backend_returns_retryable_backend_error() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_diagnostics_no_backend".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::DiagnosticsCollect {
                    upload: true,
                    upload_approval: Some(DiagnosticsUploadApproval {
                        approved: true,
                        retention_disclosure_accepted: true,
                        support_claim: Some("support_123".to_string()),
                    }),
                    api_base_url: Some(unused_loopback_base_url()),
                },
            },
        );

        assert!(!response.ok);
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::BackendUnreachable);
        assert!(error.retryable);
        match error.details.get("endpoint") {
            Some(RedactedValue::String(endpoint)) => {
                assert!(endpoint.ends_with("/api/v1/diagnostics/support-bundles"))
            }
            other => panic!("expected endpoint detail, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn telemetry_control_accepts_fresh_enable_request_without_leaking_key() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("enable");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let install_root = telemetry_key_store_root("enable-install");
        let fake_codex = fake_binary_path(&install_root, "codex");
        let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
        let _path_guard = EnvVarGuard::set_os(
            "PATH",
            fake_codex
                .parent()
                .expect("fake binary parent")
                .as_os_str()
                .to_os_string(),
        );
        let api_base_url = control_token_validation_server_with_marker(200);
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_enable".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::EnableTelemetry,
                    source: SourceKind::Codex,
                    control_token: test_control_token("enable_telemetry", "codex", 300),
                    api_base_url: Some(api_base_url.clone()),
                    key_id: Some("key_123".to_string()),
                    organization_id: Some("org_123".to_string()),
                    otlp_endpoint: Some(api_base_url),
                    ingest_key: Some(SecretString::new("transit_secret_for_tests")),
                },
            },
        );

        assert!(response.ok, "{response:?}");
        let payload = response.payload.expect("payload");
        assert_eq!(
            payload.get("status").and_then(|value| value.as_str()),
            Some("accepted")
        );
        assert_eq!(
            payload
                .get("requires_restart")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert!(!payload.to_string().contains("transit_secret_for_tests"));
        assert_eq!(
            payload
                .get("installation")
                .and_then(|value| value.get("installed"))
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            TelemetryKeyStore::file_only(&store_root)
                .load(&SourceKind::Codex, "key_123")
                .expect("stored key"),
            "transit_secret_for_tests"
        );
        let config =
            fs::read_to_string(install_root.join(".codex/config.toml")).expect("codex config");
        assert!(config.contains("# ottto:start"));
        assert!(config.contains("# ottto:end"));
        assert!(config.contains("otel.environment"));
        assert!(codex_config_has_relay_otel(&config));
        assert!(!config.contains("transit_secret_for_tests"));
    }

    #[test]
    fn verification_marker_body_has_single_magic_metric() {
        let marker = verification_marker_body(
            &SourceKind::Codex,
            Some("77f0dbdf-3b05-47e2-a9cc-23f8d94ffdc4"),
            None,
            "marker_test",
            None,
            None,
        );
        let metrics = marker["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("metrics array");
        assert_eq!(metrics.len(), 1);
        assert_eq!(
            metrics[0]["name"].as_str(),
            Some(VERIFICATION_MARKER_METRIC_NAME)
        );
        let data_points = metrics[0]["sum"]["dataPoints"]
            .as_array()
            .expect("data points array");
        assert_eq!(data_points.len(), 1);
        let attrs = data_points[0]["attributes"]
            .as_array()
            .expect("attributes array");
        assert!(attrs.iter().any(|attr| {
            attr["key"].as_str() == Some(VERIFICATION_MARKER_ATTRIBUTE)
                && attr["value"]["boolValue"].as_bool() == Some(true)
        }));
        assert!(!marker.to_string().contains("input_tokens"));
        assert!(!marker.to_string().contains("output_tokens"));
    }

    #[test]
    fn otlp_metrics_url_normalizes_base_or_signal_endpoint() {
        assert_eq!(
            otlp_metrics_url("https://api.ottto.net").expect("base url"),
            "https://api.ottto.net/v1/metrics"
        );
        assert_eq!(
            otlp_metrics_url("https://api.ottto.net/v1").expect("v1 url"),
            "https://api.ottto.net/v1/metrics"
        );
        assert_eq!(
            otlp_metrics_url("https://api.ottto.net/v1/metrics").expect("metrics url"),
            "https://api.ottto.net/v1/metrics"
        );
        assert!(otlp_metrics_url("https://api.ottto.net.evil").is_err());
        assert!(otlp_metrics_url("http://127.0.0.1.evil/v1/metrics").is_err());
        assert!(otlp_metrics_url("https://api.ottto.net@evil.example/v1/metrics").is_err());
    }

    #[test]
    #[serial]
    fn telemetry_control_disable_removes_stored_key() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("disable");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let install_root = telemetry_key_store_root("disable-install");
        let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
        let config_path = install_root.join(".codex/config.toml");
        patch_codex_config_at(&config_path, &install_root.join("backups")).expect("seed config");
        let store = TelemetryKeyStore::file_only(&store_root);
        store
            .save(
                &SourceKind::Codex,
                "key_disable",
                "transit_secret_for_tests",
            )
            .expect("seed key");

        let api_base_url = control_token_validation_server(200);
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_disable".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::DisableTelemetry,
                    source: SourceKind::Codex,
                    control_token: test_control_token("disable_telemetry", "codex", 300),
                    api_base_url: Some(api_base_url),
                    key_id: Some("key_disable".to_string()),
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(response.ok, "{response:?}");
        let payload = response.payload.expect("payload");
        assert_eq!(
            payload
                .get("requires_restart")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
        assert!(matches!(
            store.load(&SourceKind::Codex, "key_disable"),
            Err(TelemetryKeychainError::Missing)
        ));
        let config = fs::read_to_string(config_path).expect("read config");
        assert!(!config.contains("# ottto:start"));
        assert!(!config.contains("# ottto:end"));
        assert!(!codex_config_has_relay_otel(&config));
    }

    #[test]
    #[serial]
    fn telemetry_control_disable_preserves_key_when_fence_needs_review() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("disable-manual-fence");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let install_root = telemetry_key_store_root("disable-manual-fence-install");
        let _home_guard = EnvVarGuard::set_path("HOME", &install_root);
        let config_path = install_root.join(".codex/config.toml");
        patch_codex_config_at(&config_path, &install_root.join("backups")).expect("seed config");
        let config = fs::read_to_string(&config_path).expect("read seeded config");
        fs::write(&config_path, config.replace("# ottto:end", "")).expect("mangle managed fence");
        let store = TelemetryKeyStore::file_only(&store_root);
        store
            .save(
                &SourceKind::Codex,
                "key_manual_fence",
                "transit_secret_for_tests",
            )
            .expect("seed key");

        let api_base_url = control_token_validation_server(200);
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_disable_manual_fence".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::DisableTelemetry,
                    source: SourceKind::Codex,
                    control_token: test_control_token("disable_telemetry", "codex", 300),
                    api_base_url: Some(api_base_url),
                    key_id: Some("key_manual_fence".to_string()),
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(!response.ok, "{response:?}");
        let error = response.error.expect("error");
        assert_eq!(error.code, CliErrorCode::ManualFenceReviewRequired);
        assert_eq!(
            error.message,
            "Ottto found a manually edited managed fence and needs you to review it."
        );
        assert!(!error.retryable);
        assert!(store.load(&SourceKind::Codex, "key_manual_fence").is_ok());
        let config = fs::read_to_string(config_path).expect("read config");
        assert!(config.contains("# ottto:start"));
        assert!(!config.contains("# ottto:end"));
    }

    #[test]
    #[serial]
    fn telemetry_control_status_returns_indexed_key_id() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("status-key");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let store = TelemetryKeyStore::file_only(&store_root);
        store
            .save(&SourceKind::Codex, "key_status", "transit_secret_for_tests")
            .expect("seed key");

        let api_base_url = control_token_validation_server(200);
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_status".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::Status,
                    source: SourceKind::Codex,
                    control_token: test_control_token("status", "codex", 300),
                    api_base_url: Some(api_base_url),
                    key_id: None,
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(response.ok, "{response:?}");
        assert_eq!(
            response
                .payload
                .expect("payload")
                .get("key_id")
                .and_then(|value| value.as_str()),
            Some("key_status")
        );
    }

    #[test]
    #[serial]
    fn uninstall_sweep_removes_indexed_telemetry_keys() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("uninstall");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let store = TelemetryKeyStore::file_only(&store_root);
        store
            .save(
                &SourceKind::ClaudeCode,
                "key_uninstall",
                "transit_secret_for_tests",
            )
            .expect("seed key");
        let mut result = UninstallExecutionResult {
            status: "uninstalled".to_string(),
            plan: plan_local_uninstall(Path::new("/Users/test")),
            credential_status: "removed_or_absent".to_string(),
            removed_paths: Vec::new(),
            missing_paths: Vec::new(),
            warnings: Vec::new(),
            failed_operations: Vec::new(),
            cloud_credentials_untouched: true,
        };

        sweep_telemetry_keys_for_uninstall(&mut result);

        assert_eq!(result.status, "uninstalled");
        assert!(result.failed_operations.is_empty());
        assert!(result
            .removed_paths
            .contains(&"keychain://ottto-telemetry-key-claude_code/key_uninstall".to_string()));
        assert!(matches!(
            store.load(&SourceKind::ClaudeCode, "key_uninstall"),
            Err(TelemetryKeychainError::Missing)
        ));
    }

    #[test]
    #[serial]
    fn telemetry_control_enable_needs_attention_when_agent_missing() {
        let _guard = lock_backend_test_env();
        let store_root = telemetry_key_store_root("missing-agent");
        let _env_guard = EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &store_root);
        let missing = AgentInstallationDetection {
            source: SourceKind::Codex,
            installed: false,
            version: None,
            config_path: None,
            binary_path: None,
            install_docs_url: Some("https://example.invalid/codex".to_string()),
        };

        let response = telemetry_control_with_detector(
            &daemon(),
            TelemetryControlAction::EnableTelemetry,
            SourceKind::Codex,
            test_control_token("enable_telemetry", "codex", 300),
            Some(control_token_validation_server(200)),
            Some("key_missing".to_string()),
            Some("org_123".to_string()),
            Some("https://api.ottto.net".to_string()),
            Some(SecretString::new("transit_secret_for_tests")),
            &|_| missing.clone(),
        )
        .expect("control result");

        assert_eq!(response.status, ControlResultStatus::NeedsAttention);
        assert!(!response.requires_restart);
        assert_eq!(response.message.code, "agent_not_installed");
        assert_eq!(response.installation, Some(missing));
        assert!(matches!(
            TelemetryKeyStore::file_only(&store_root).load(&SourceKind::Codex, "key_missing"),
            Err(TelemetryKeychainError::Missing)
        ));
    }

    #[test]
    fn telemetry_control_rejects_stale_token() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_stale".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::Status,
                    source: SourceKind::Codex,
                    control_token: test_control_token("status", "codex", -30),
                    api_base_url: None,
                    key_id: None,
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalClientNotTrusted
        );
    }

    #[test]
    fn telemetry_control_rejects_mismatched_action_token() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_mismatch".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::DisableTelemetry,
                    source: SourceKind::Codex,
                    control_token: test_control_token("enable_telemetry", "codex", 300),
                    api_base_url: None,
                    key_id: Some("key_123".to_string()),
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalClientNotTrusted
        );
    }

    #[test]
    #[serial]
    fn telemetry_control_rejects_backend_rejected_token() {
        let _guard = lock_backend_test_env();
        let api_base_url = control_token_validation_server(401);
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_backend_reject".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::Status,
                    source: SourceKind::Codex,
                    control_token: test_control_token("status", "codex", 300),
                    api_base_url: Some(api_base_url),
                    key_id: None,
                    organization_id: None,
                    otlp_endpoint: None,
                    ingest_key: None,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::LocalClientNotTrusted
        );
    }

    #[test]
    fn telemetry_control_requires_enable_materials() {
        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_telemetry_missing_key".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::WebUi),
                client_install_owner: None,
                command: LocalControlCommand::TelemetryControl {
                    action: TelemetryControlAction::EnableTelemetry,
                    source: SourceKind::Codex,
                    control_token: test_control_token("enable_telemetry", "codex", 300),
                    api_base_url: None,
                    key_id: Some("key_123".to_string()),
                    organization_id: Some("org_123".to_string()),
                    otlp_endpoint: Some("https://api.ottto.net".to_string()),
                    ingest_key: None,
                },
            },
        );

        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error").code,
            CliErrorCode::InvalidRequest
        );
    }

    #[test]
    fn pi_smoke_command_runs_non_interactive_prompt_instead_of_help() {
        let command = smoke_command(&SourceKind::Pi);

        assert_eq!(command.program, "pi");
        assert!(command.args.iter().any(|arg| arg == "--print"));
        assert!(command.args.iter().any(|arg| arg == "--no-builtin-tools"));
        assert!(command.args.iter().any(|arg| arg == "--no-context-files"));
        assert!(command.args.iter().any(|arg| arg == SMOKE_PROMPT));
        assert!(!command.args.iter().any(|arg| arg == "--help"));
    }

    #[test]
    fn pi_smoke_command_includes_route_provider_model_and_thinking() {
        let route = PiModelRoute {
            provider: "google-vertex".to_string(),
            model: "gemini-2.5-flash-lite".to_string(),
            thinking_level: Some("high".to_string()),
            classification: crate::agent_status::PiRouteClassification {
                model_provider: Some("google".to_string()),
                billing_provider: Some("google".to_string()),
                billing_channel: Some("google_vertex".to_string()),
                auth_mode: Some("service_account".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("google_cloud_vertex".to_string()),
            },
        };

        let command = pi_smoke_command(Some(&route));

        assert_eq!(command.program, "pi");
        assert!(command
            .args
            .windows(2)
            .any(|args| args[0] == "--provider" && args[1] == "google-vertex"));
        assert!(command
            .args
            .windows(2)
            .any(|args| args[0] == "--model" && args[1] == "gemini-2.5-flash-lite"));
        assert!(command
            .args
            .windows(2)
            .any(|args| args[0] == "--thinking" && args[1] == "high"));
        assert_eq!(command.args.last().map(String::as_str), Some(SMOKE_PROMPT));
    }

    #[test]
    fn pi_session_files_include_nested_workspace_sessions() {
        let root = std::env::temp_dir().join(format!(
            "ottto-pi-session-files-{}-{}",
            std::process::id(),
            current_millis()
        ));
        let nested = root.join("----");
        fs::create_dir_all(&nested).expect("create nested session dir");
        fs::write(nested.join("session.jsonl"), "{}\n").expect("write nested session");
        fs::write(root.join("ignore.txt"), "ignored").expect("write ignored file");

        let files = pi_session_files_in(&root);

        assert_eq!(files.len(), 1);
        assert!(files.contains(&nested.join("session.jsonl")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_route_aggregate_allows_partial_success_as_warning() {
        let route_results = vec![
            SourceRouteVerificationResult {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.4-mini".to_string()),
                model_provider: Some("openai".to_string()),
                billing_provider: Some("openai".to_string()),
                billing_channel: Some("direct_api".to_string()),
                auth_mode: Some("api_key".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("openai_api_key".to_string()),
                account_identifier_hash: None,
                organization_identifier_hash: None,
                credential_fingerprint_hash: Some("credential_hash".to_string()),
                billing_identity_evidence: Some("credential_fingerprint".to_string()),
                billing_identity_confidence: ottto_protocol::AgentStatusConfidence::High,
                status: SourceVerificationStatus::Verified,
                verified: true,
                records_seen: 1,
                last_record_id: Some("record_1".to_string()),
                last_received_at: Some("2026-05-11T10:00:00Z".to_string()),
                smoke_after: Some("2026-05-11T09:59:00Z".to_string()),
                command_found: true,
                command_succeeded: true,
                exit_status: Some(0),
                duration_ms: 12,
                diagnostic: None,
                error_code: None,
                local_session_observed: Some(true),
                message: StableMessage {
                    code: "verified".to_string(),
                    text: "ok".to_string(),
                },
            },
            SourceRouteVerificationResult {
                provider: Some("google-vertex".to_string()),
                model: Some("gemini-2.5-flash-lite".to_string()),
                model_provider: Some("google".to_string()),
                billing_provider: Some("google".to_string()),
                billing_channel: Some("google_vertex".to_string()),
                auth_mode: Some("service_account".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("google_cloud_vertex".to_string()),
                account_identifier_hash: None,
                organization_identifier_hash: None,
                credential_fingerprint_hash: None,
                billing_identity_evidence: None,
                billing_identity_confidence: ottto_protocol::AgentStatusConfidence::Unknown,
                status: SourceVerificationStatus::NoFreshTelemetry,
                verified: false,
                records_seen: 0,
                last_record_id: None,
                last_received_at: None,
                smoke_after: Some("2026-05-11T10:01:00Z".to_string()),
                command_found: true,
                command_succeeded: true,
                exit_status: Some(0),
                duration_ms: 10,
                diagnostic: None,
                error_code: Some("no_fresh_telemetry".to_string()),
                local_session_observed: Some(false),
                message: StableMessage {
                    code: "no_fresh_telemetry".to_string(),
                    text: "missing".to_string(),
                },
            },
        ];

        let result = pi_route_aggregate_result(route_results);

        assert_eq!(result.status, SourceVerificationStatus::Warning);
        assert!(result.verified);
        assert_eq!(result.records_seen, 1);
        assert_eq!(result.message.code, "pi_route_warnings");
    }

    #[test]
    fn claude_smoke_command_places_prompt_after_print_flag() {
        let command = smoke_command(&SourceKind::ClaudeCode);

        assert_eq!(command.program, "claude");
        let print_index = command
            .args
            .iter()
            .position(|arg| arg == "-p")
            .expect("print flag");
        assert_eq!(
            command.args.get(print_index + 1).map(String::as_str),
            Some(SMOKE_PROMPT)
        );
        assert!(command.args.iter().any(|arg| arg == "--disallowedTools"));
    }

    #[test]
    fn command_diagnostics_are_redacted_before_display() {
        let diagnostic = redact_command_diagnostic(
            "Token sk-secret123 is expired at /Users/ron/.aws/sso/cache/file.json account_id=org_123 raw_prompt=show private repo",
        )
        .expect("diagnostic");

        assert!(diagnostic.contains("[REDACTED]"));
        assert!(diagnostic.contains("[path]"));
        assert!(diagnostic.contains("[account_id]"));
        assert!(diagnostic.contains("[prompt]"));
        assert!(!diagnostic.contains("/Users/ron"));
        assert!(!diagnostic.contains("org_123"));
        assert!(!diagnostic.contains("sk-secret123"));
        assert!(!diagnostic.contains("show private repo"));
    }

    #[test]
    fn codex_config_rejects_legacy_direct_ottto_endpoint() {
        let body = r#"
[otel]
log_user_prompt = false

[otel.exporter.otlp-http]
endpoint = "https://api.ottto.net/v1/logs"
protocol = "binary"

[otel.exporter.otlp-http.headers]
X-API-Key = "otel_redacted"
"#;

        assert!(!codex_config_has_relay_otel(body));
    }

    #[test]
    fn patch_codex_config_writes_loopback_relay_without_dropping_user_config() {
        let root =
            std::env::temp_dir().join(format!("ottto-codex-config-test-{}", std::process::id()));
        let path = root.join("config.toml");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        let original = "model = \"gpt-5.4\"\n[profile]\nname = \"work\"\n";
        fs::write(&path, original).expect("write config");

        let backup_root = root.join("backups");
        let result = patch_codex_config_at(&path, &backup_root).expect("patch config");
        let body = fs::read_to_string(&path).expect("read config");
        let document = body.parse::<DocumentMut>().expect("toml config");
        let otel = document
            .get("otel")
            .and_then(Item::as_table)
            .expect("otel table");

        assert!(result.changed);
        assert!(!result.created);
        assert!(result.backup_created);
        let backup_dir = backup_root.join("config-backups/codex");
        assert!(backup_dir.exists());
        assert_eq!(count_backup_files(&backup_dir), 1);
        assert_eq!(
            document
                .get("model")
                .and_then(Item::as_value)
                .and_then(|value| value.as_str()),
            Some("gpt-5.4")
        );
        assert!(body.contains("# ottto:start\notel.environment"));
        assert!(body.contains("# ottto:end\nmodel = \"gpt-5.4\""));
        assert!(codex_config_has_relay_otel(&body));
        assert!(codex_exporter_has_relay(otel, "exporter", "logs"));
        assert!(codex_exporter_has_relay(otel, "trace_exporter", "traces"));
        assert!(codex_exporter_has_relay(
            otel,
            "metrics_exporter",
            "metrics"
        ));
        let second = patch_codex_config_at(&path, &backup_root).expect("patch config again");
        assert!(!second.changed);
        assert!(!second.created);
        assert!(!second.backup_created);
        assert_eq!(fs::read_to_string(&path).expect("read second config"), body);
        assert_eq!(count_backup_files(&backup_dir), 1);
        remove_codex_config_at(&path).expect("remove managed block");
        assert_eq!(
            fs::read_to_string(&path).expect("read restored config"),
            original
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_codex_config_accepts_existing_unfenced_relay_otel_table() {
        let root = std::env::temp_dir().join(format!(
            "ottto-codex-config-inline-test-{}",
            std::process::id()
        ));
        let path = root.join("config.toml");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(
            &path,
            r#"model = "gpt-5.4"

[otel]
environment = "prod"
log_user_prompt = false
exporter = { otlp-http = { endpoint = "http://127.0.0.1:43119/v1/logs", protocol = "binary", headers = { "X-Ottto-Local-Relay" = "codex" } } }
trace_exporter = { otlp-http = { endpoint = "http://127.0.0.1:43119/v1/traces", protocol = "binary", headers = { "X-Ottto-Local-Relay" = "codex" } } }
metrics_exporter = { otlp-http = { endpoint = "http://127.0.0.1:43119/v1/metrics", protocol = "binary", headers = { "X-Ottto-Local-Relay" = "codex" } } }
"#,
        )
        .expect("write config");
        let original = fs::read_to_string(&path).expect("read original config");

        let backup_root = root.join("backups");
        let result = patch_codex_config_at(&path, &backup_root).expect("compatible relay config");
        let body = fs::read_to_string(&path).expect("read config");

        assert!(!result.changed);
        assert!(!result.created);
        assert!(!result.backup_created);
        assert_eq!(body, original);
        assert!(!backup_root.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_codex_config_rewrites_managed_relay_to_active_fallback_endpoint() {
        let root = std::env::temp_dir().join(format!(
            "ottto-codex-config-fallback-test-{}",
            std::process::id()
        ));
        let path = root.join("config.toml");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(
            &path,
            format!(
                "# ottto:start\n{}\n# ottto:end\nmodel = \"gpt-5.4\"\n",
                render_codex_relay_toml_block_for_base(
                    &crate::otlp_relay::default_local_relay_base_url()
                )
            ),
        )
        .expect("write config");

        let backup_root = root.join("backups");
        let fallback = "http://127.0.0.1:44621";
        let result = patch_codex_config_at_with_relay_base(&path, &backup_root, fallback)
            .expect("patch fallback config");
        let body = fs::read_to_string(&path).expect("read config");

        assert!(!result.created);
        assert!(result.backup_created);
        assert!(body.contains("http://127.0.0.1:44621/v1/logs"));
        assert!(!body.contains("http://127.0.0.1:43119/v1/logs"));
        assert!(codex_config_has_relay_otel(&body));
        assert!(codex_config_has_relay_otel_for_base(&body, fallback));
        assert!(!codex_config_has_relay_otel_for_base(
            &body,
            &crate::otlp_relay::default_local_relay_base_url()
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_claude_code_env_writes_fenced_env_and_shell_source_line() {
        let root =
            std::env::temp_dir().join(format!("ottto-claude-env-test-{}", std::process::id()));
        let env_path = root.join(".ottto/claude-telemetry.env");
        let shell_path = root.join(".zshrc");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        let original_shell = "alias ll='ls -la'\n";
        fs::write(&shell_path, original_shell).expect("write shell rc");

        let backup_root = root.join("backups");
        let result = patch_claude_code_env_at(
            &env_path,
            &shell_path,
            &test_machine(),
            &backup_root,
            &crate::otlp_relay::default_local_relay_base_url(),
        )
        .expect("patch env");
        let env_body = fs::read_to_string(&env_path).expect("read env file");
        let shell_body = fs::read_to_string(&shell_path).expect("read shell rc");

        assert!(result.changed);
        assert!(result.created);
        assert!(result.backup_created);
        assert!(env_body.contains("# ottto:start"));
        assert!(env_body.contains("export CLAUDE_CODE_ENABLE_TELEMETRY='1'"));
        assert!(env_body.contains("ottto.machine_id=machine_test"));
        assert!(env_body.contains("# ottto:end"));
        assert!(shell_body.starts_with("# ottto:start"));
        assert!(shell_body.contains(". \"$HOME/.ottto/claude-telemetry.env\""));
        assert!(shell_body.ends_with(original_shell));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&env_path)
                .expect("env metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let backup_dir = backup_root.join("config-backups/claude_code");
        assert_eq!(count_backup_files(&backup_dir), 1);

        let second = patch_claude_code_env_at(
            &env_path,
            &shell_path,
            &test_machine(),
            &backup_root,
            &crate::otlp_relay::default_local_relay_base_url(),
        )
        .expect("patch env again");
        assert!(!second.changed);
        assert!(!second.created);
        assert!(!second.backup_created);
        assert_eq!(
            fs::read_to_string(&env_path).expect("read second env file"),
            env_body
        );
        assert_eq!(
            fs::read_to_string(&shell_path).expect("read second shell rc"),
            shell_body
        );
        assert_eq!(count_backup_files(&backup_dir), 1);

        remove_claude_code_env_at(&env_path, &shell_path).expect("remove env");
        assert!(!env_path.exists());
        assert_eq!(
            fs::read_to_string(&shell_path).expect("read restored shell rc"),
            original_shell
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_claude_code_settings_writes_loopback_relay_without_dropping_env() {
        let root =
            std::env::temp_dir().join(format!("ottto-claude-settings-test-{}", std::process::id()));
        let path = root.join("settings.json");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(
            &path,
            r#"{"env":{"EXISTING":"keep"},"theme":"dark","statusLine":{"type":"command","command":"jq -r '.model.display_name'","padding":1}}"#,
        )
        .expect("write settings");

        let backup_root = root.join("backups");
        let result = patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
            .expect("patch settings");
        let body = fs::read_to_string(&path).expect("read settings");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json settings");
        let env = value
            .get("env")
            .and_then(|value| value.as_object())
            .expect("env object");

        assert!(result.changed);
        assert!(!result.created);
        assert!(result.backup_created);
        let backup_dir = backup_root.join("config-backups/claude_code");
        assert!(backup_dir.exists());
        assert_eq!(count_backup_files(&backup_dir), 1);
        assert_eq!(
            env.get("EXISTING").and_then(|value| value.as_str()),
            Some("keep")
        );
        assert_eq!(
            env.get("CLAUDE_CODE_ENABLE_TELEMETRY")
                .and_then(|value| value.as_str()),
            Some("1")
        );
        assert_eq!(
            env.get("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA")
                .and_then(|value| value.as_str()),
            Some("1")
        );
        assert_eq!(
            env.get("OTEL_TRACES_EXPORTER")
                .and_then(|value| value.as_str()),
            Some("otlp")
        );
        assert_eq!(
            env.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
                .and_then(|value| value.as_str()),
            Some("http://127.0.0.1:43119/v1/logs")
        );
        assert_eq!(
            env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                .and_then(|value| value.as_str()),
            Some("http://127.0.0.1:43119/v1/traces")
        );
        assert!(env
            .get("OTEL_RESOURCE_ATTRIBUTES")
            .and_then(|value| value.as_str())
            .expect("resource attributes")
            .contains("ottto.machine_id=machine_test"));
        assert!(claude_code_settings_has_relay_env(&body));
        assert!(claude_code_settings_has_statusline_helper(&body));
        let statusline = value
            .get("statusLine")
            .and_then(|value| value.as_object())
            .expect("statusLine object");
        assert_eq!(
            statusline.get("type").and_then(|value| value.as_str()),
            Some("command")
        );
        assert_eq!(
            statusline.get("padding").and_then(|value| value.as_i64()),
            Some(1)
        );
        let statusline_command = statusline
            .get("command")
            .and_then(|value| value.as_str())
            .expect("statusLine command");
        assert!(statusline_command.contains("claude-code-statusline.sh"));
        let wrapper = fs::read_to_string(backup_root.join("claude-code-statusline.sh"))
            .expect("read statusLine wrapper");
        assert!(wrapper.contains("claude-code-statusline"));
        assert!(wrapper.contains("ORIGINAL_STATUSLINE="));
        assert!(wrapper.contains("model.display_name"));
        assert_eq!(
            value.get("theme").and_then(|value| value.as_str()),
            Some("dark")
        );

        let second = patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
            .expect("patch settings again");
        assert!(!second.changed);
        assert!(!second.created);
        assert!(!second.backup_created);
        assert_eq!(
            fs::read_to_string(&path).expect("read second settings"),
            body
        );
        assert_eq!(
            fs::read_to_string(backup_root.join("claude-code-statusline.sh"))
                .expect("read second statusLine wrapper"),
            wrapper
        );
        assert_eq!(count_backup_files(&backup_dir), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_claude_code_settings_restores_missing_wrapper_without_settings_backup() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-wrapper-restore-test-{}-{}",
            std::process::id(),
            current_millis()
        ));
        let path = root.join("settings.json");
        let backup_root = root.join("backups");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(
            &path,
            r#"{"statusLine":{"type":"command","command":"jq -r '.model.display_name'"}}"#,
        )
        .expect("write settings");

        patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
            .expect("patch settings");
        let body = fs::read_to_string(&path).expect("read patched settings");
        let backup_dir = backup_root.join("config-backups/claude_code");
        assert_eq!(count_backup_files(&backup_dir), 1);
        fs::remove_file(backup_root.join("claude-code-statusline.sh"))
            .expect("remove statusLine wrapper");

        let restored = patch_claude_code_settings_at(&path, &test_machine(), &backup_root)
            .expect("restore wrapper");
        let wrapper = fs::read_to_string(backup_root.join("claude-code-statusline.sh"))
            .expect("read restored wrapper");

        assert!(restored.changed);
        assert!(!restored.created);
        assert!(!restored.backup_created);
        assert_eq!(
            fs::read_to_string(&path).expect("read settings again"),
            body
        );
        assert_eq!(count_backup_files(&backup_dir), 1);
        assert!(wrapper.contains("ORIGINAL_STATUSLINE=''"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn backup_retention_keeps_newest_n_and_invalid_env_uses_default() {
        let root = std::env::temp_dir().join(format!(
            "ottto-backup-retention-test-{}-{}",
            std::process::id(),
            current_millis()
        ));
        let backup_dir = root.join("config-backups/codex");
        fs::create_dir_all(&backup_dir).expect("create backup dir");
        for timestamp in 1..=5 {
            fs::write(
                backup_dir.join(format!("codex_config_{timestamp}.toml")),
                format!("model = \"gpt-5.{timestamp}\"\n"),
            )
            .expect("write backup");
        }
        fs::write(backup_dir.join("codex_config_bad.toml"), "bad").expect("write bad backup");

        let _retention_guard = EnvVarGuard::set_str(OTTTO_CONFIG_BACKUP_RETENTION_ENV, "3");
        prune_config_backups(&backup_dir, config_backup_retention_limit()).expect("prune backups");
        let files = fs::read_dir(&backup_dir)
            .expect("read backups")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 3);
        assert!(files.contains(&"codex_config_3.toml".to_string()));
        assert!(files.contains(&"codex_config_4.toml".to_string()));
        assert!(files.contains(&"codex_config_5.toml".to_string()));

        drop(_retention_guard);
        let _invalid_guard = EnvVarGuard::set_str(OTTTO_CONFIG_BACKUP_RETENTION_ENV, "nope");
        assert_eq!(
            config_backup_retention_limit(),
            MAX_CONFIG_BACKUPS_PER_SOURCE
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn source_patch_disabled_parses_per_source_truthy_values() {
        let _lock = lock_backend_test_env();
        assert_eq!(source_patch_env_token(&SourceKind::Codex), Some("CODEX"));
        assert_eq!(
            source_patch_env_token(&SourceKind::ClaudeCode),
            Some("CLAUDE_CODE")
        );
        assert_eq!(source_patch_env_token(&SourceKind::Pi), None);
        assert!(!source_patch_disabled(&SourceKind::Codex));

        let _guard = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", " yes ");
        assert!(source_patch_disabled(&SourceKind::Codex));
        assert!(!source_patch_disabled(&SourceKind::ClaudeCode));
        assert!(!source_patch_disabled(&SourceKind::Pi));
    }

    #[test]
    #[serial]
    fn source_patch_disabled_ignores_falsey_values() {
        let _lock = lock_backend_test_env();
        let _guard = EnvVarGuard::set_str("OTTTO_PATCH_CLAUDE_CODE_DISABLED", "false");
        assert!(!source_patch_disabled(&SourceKind::ClaudeCode));
    }

    #[test]
    fn codex_config_state_detects_clean_missing_wrong_and_invalid_without_writes() {
        let root = control_test_root("codex-config-state");
        fs::create_dir_all(&root).expect("create root");
        let missing = root.join("missing.toml");
        let default_base = crate::otlp_relay::default_local_relay_base_url();

        let missing_state =
            codex_config_state_at(&missing, "~/.codex/config.toml", &default_base, false);
        assert!(!missing_state.discovered);
        assert!(missing_state
            .drift
            .iter()
            .any(|drift| drift.key == "codex.config_file"));

        let invalid = root.join("invalid.toml");
        fs::write(&invalid, "[otel\n").expect("write invalid config");
        let invalid_body = fs::read_to_string(&invalid).expect("read invalid config");
        let invalid_state =
            codex_config_state_at(&invalid, "~/.codex/config.toml", &default_base, false);
        assert!(invalid_state.discovered);
        assert!(invalid_state
            .fingerprint
            .as_deref()
            .unwrap_or("")
            .starts_with("sha256:"));
        assert!(invalid_state
            .drift
            .iter()
            .any(|drift| drift.key == "codex.config_toml"));
        assert_eq!(
            fs::read_to_string(&invalid).expect("read invalid again"),
            invalid_body
        );

        let clean = root.join("clean.toml");
        patch_codex_config_at_with_relay_base(&clean, &root.join("backups"), &default_base)
            .expect("seed clean config");
        let clean_body = fs::read_to_string(&clean).expect("read clean config");
        let clean_state =
            codex_config_state_at(&clean, "~/.codex/config.toml", &default_base, false);
        assert!(clean_state.discovered);
        assert!(clean_state.drift.is_empty());
        assert_eq!(
            fs::read_to_string(&clean).expect("read clean again"),
            clean_body
        );

        let fallback_base = "http://127.0.0.1:44621";
        let wrong_relay_state =
            codex_config_state_at(&clean, "~/.codex/config.toml", fallback_base, false);
        assert!(wrong_relay_state
            .drift
            .iter()
            .any(|drift| drift.key.ends_with(".endpoint")));

        fs::write(
            &clean,
            clean_body.replace("protocol = \"binary\"", "protocol = \"grpc\""),
        )
        .expect("write wrong protocol");
        let wrong_protocol_state =
            codex_config_state_at(&clean, "~/.codex/config.toml", &default_base, false);
        assert!(wrong_protocol_state
            .drift
            .iter()
            .any(|drift| drift.key.ends_with(".protocol")));

        fs::write(
            &clean,
            clean_body.replace(
                "\"X-Ottto-Local-Relay\" = \"codex\"",
                "\"X-Ottto-Local-Relay\" = \"wrong\"",
            ),
        )
        .expect("write wrong header");
        let wrong_header_state =
            codex_config_state_at(&clean, "~/.codex/config.toml", &default_base, false);
        assert!(wrong_header_state
            .drift
            .iter()
            .any(|drift| drift.key.ends_with(".headers.X-Ottto-Local-Relay")));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_code_config_state_detects_settings_shape_without_env_fence_dependency() {
        let root = control_test_root("claude-config-state");
        fs::create_dir_all(&root).expect("create root");
        let missing = root.join("settings-missing.json");
        let default_base = crate::otlp_relay::default_local_relay_base_url();

        let missing_state = claude_code_settings_config_state_at(
            &missing,
            "~/.claude/settings.json",
            &test_machine(),
            &default_base,
            false,
        );
        assert!(!missing_state.discovered);
        assert!(missing_state
            .drift
            .iter()
            .any(|drift| drift.key == "claude_code.settings_file"));

        let clean = root.join("settings.json");
        patch_claude_code_settings_at_with_relay_base(
            &clean,
            &test_machine(),
            &root.join("backups"),
            &default_base,
        )
        .expect("seed clean settings");
        let clean_body = fs::read_to_string(&clean).expect("read clean settings");
        let clean_state = claude_code_settings_config_state_at(
            &clean,
            "~/.claude/settings.json",
            &test_machine(),
            &default_base,
            false,
        );
        assert!(clean_state.discovered);
        assert!(clean_state.drift.is_empty());
        assert!(!root.join(".ottto/claude-telemetry.env").exists());
        assert!(!root.join(".zshrc").exists());
        assert_eq!(
            fs::read_to_string(&clean).expect("read clean again"),
            clean_body
        );

        let fallback_base = "http://127.0.0.1:44621";
        let wrong_relay_state = claude_code_settings_config_state_at(
            &clean,
            "~/.claude/settings.json",
            &test_machine(),
            fallback_base,
            false,
        );
        assert!(wrong_relay_state
            .drift
            .iter()
            .any(|drift| drift.key == "env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"));

        let value: serde_json::Value = serde_json::from_str(&clean_body).expect("settings json");
        let env = value.get("env").expect("env");
        fs::write(&clean, serde_json::json!({ "env": env }).to_string())
            .expect("write env-only settings");
        let missing_statusline = claude_code_settings_config_state_at(
            &clean,
            "~/.claude/settings.json",
            &test_machine(),
            &default_base,
            false,
        );
        assert!(missing_statusline
            .drift
            .iter()
            .any(|drift| drift.key == "statusLine.command"));

        fs::write(&clean, "{").expect("write invalid json");
        let invalid_state = claude_code_settings_config_state_at(
            &clean,
            "~/.claude/settings.json",
            &test_machine(),
            &default_base,
            false,
        );
        assert!(invalid_state
            .drift
            .iter()
            .any(|drift| drift.key == "claude_code.settings_json"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_disabled_config_state_reports_no_drift_for_codex_and_claude() {
        let root = control_test_root("patch-disabled-config-state");
        fs::create_dir_all(&root).expect("create root");
        let codex_path = root.join("config.toml");
        let claude_path = root.join("settings.json");
        fs::write(&codex_path, "[otel\n").expect("write invalid codex");
        fs::write(&claude_path, "{").expect("write invalid claude");
        let default_base = crate::otlp_relay::default_local_relay_base_url();

        let codex = codex_config_state_at(&codex_path, "~/.codex/config.toml", &default_base, true);
        let claude = claude_code_settings_config_state_at(
            &claude_path,
            "~/.claude/settings.json",
            &test_machine(),
            &default_base,
            true,
        );

        assert!(codex.discovered);
        assert!(codex.drift.is_empty());
        assert!(claude.discovered);
        assert!(claude.drift.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn verify_repair_repairs_codex_config_before_account_check() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("verify-repair-codex");
        create_control_test_dir(&root.join(".codex"));
        let _home_guard = EnvVarGuard::set_path("HOME", &root);
        let _support_guard =
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
        let config_path = root.join(".codex/config.toml");
        fs::write(
            &config_path,
            r#"[otel]
log_user_prompt = true
"#,
        )
        .expect("write drifted config");

        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_verify_repair_codex".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Verify {
                    source: SourceKind::Codex,
                    repair: true,
                },
            },
        );

        assert!(response.ok, "{response:?}");
        let result: SourceVerificationResult =
            serde_json::from_value(response.payload.expect("payload"))
                .expect("verification result");
        assert_eq!(result.message.code, "account_not_connected");
        assert!(result.config.drift.is_empty());
        let body = fs::read_to_string(&config_path).expect("read repaired config");
        assert!(body.contains("http://127.0.0.1:43119/v1/logs"));
        assert!(body.contains("protocol = \"binary\""));
        assert!(body.contains("otel.log_user_prompt = false"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn verify_patch_disabled_skips_repair_writes() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("verify-patch-disabled");
        create_control_test_dir(&root.join(".codex"));
        let _home_guard = EnvVarGuard::set_path("HOME", &root);
        let _disabled_guard = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
        let config_path = root.join(".codex/config.toml");
        let original = "[otel\n";
        fs::write(&config_path, original).expect("write invalid config");

        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_verify_patch_disabled".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Verify {
                    source: SourceKind::Codex,
                    repair: true,
                },
            },
        );

        assert!(response.ok);
        let result: SourceVerificationResult =
            serde_json::from_value(response.payload.expect("payload"))
                .expect("verification result");
        assert_eq!(result.message.code, "patch_disabled");
        assert!(result.config.drift.is_empty());
        assert_eq!(
            fs::read_to_string(&config_path).expect("read config"),
            original
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn fix_non_dry_run_executes_claude_write_config_repair() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("fix-claude-config");
        create_control_test_dir(&root.join(".claude"));
        let _home_guard = EnvVarGuard::set_path("HOME", &root);
        let _support_guard =
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
        let settings_path = root.join(".claude/settings.json");
        fs::write(&settings_path, r#"{"env":{"EXISTING":"keep"}}"#)
            .expect("write drifted settings");

        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_fix_claude".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Repair {
                    source: SourceKind::ClaudeCode,
                    dry_run: false,
                },
            },
        );

        assert!(response.ok);
        let plan: RepairPlan =
            serde_json::from_value(response.payload.expect("payload")).expect("repair plan");
        assert_eq!(plan.status, RepairPlanStatus::Succeeded);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].action, RepairActionKind::WriteConfig);
        let state = claude_code_settings_config_state_at(
            &settings_path,
            "~/.claude/settings.json",
            &test_machine(),
            &crate::otlp_relay::default_local_relay_base_url(),
            false,
        );
        assert!(state.drift.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn fix_patch_disabled_blocks_claude_repair_writes() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("fix-disabled-claude");
        create_control_test_dir(&root.join(".claude"));
        let _home_guard = EnvVarGuard::set_path("HOME", &root);
        let _disabled_guard = EnvVarGuard::set_str("OTTTO_PATCH_CLAUDE_CODE_DISABLED", "1");
        let settings_path = root.join(".claude/settings.json");
        let original = r#"{"env":{"EXISTING":"keep"}}"#;
        fs::write(&settings_path, original).expect("write settings");

        let response = handle_request(
            &daemon(),
            LocalControlRequest {
                request_id: "req_fix_claude_disabled".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some("token".to_string()),
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Repair {
                    source: SourceKind::ClaudeCode,
                    dry_run: false,
                },
            },
        );

        assert!(response.ok);
        let plan: RepairPlan =
            serde_json::from_value(response.payload.expect("payload")).expect("repair plan");
        assert_eq!(plan.status, RepairPlanStatus::Blocked);
        assert_eq!(plan.authority.message.code, "patch_disabled");
        assert!(plan.actions.is_empty());
        assert_eq!(
            fs::read_to_string(&settings_path).expect("read settings"),
            original
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[serial]
    fn remove_claude_code_env_ignores_patch_disabled_env() {
        let _lock = lock_backend_test_env();
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-env-remove-disabled-test-{}-{}",
            std::process::id(),
            current_millis()
        ));
        let env_path = root.join(".ottto/claude-telemetry.env");
        let shell_path = root.join(".zshrc");
        let backup_root = root.join("backups");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(&shell_path, "alias ll='ls -la'\n").expect("write shell rc");
        patch_claude_code_env_at(
            &env_path,
            &shell_path,
            &test_machine(),
            &backup_root,
            &crate::otlp_relay::default_local_relay_base_url(),
        )
        .expect("seed env");

        let _disabled_guard = EnvVarGuard::set_str("OTTTO_PATCH_CLAUDE_CODE_DISABLED", "1");
        let removed = remove_claude_code_env_at(&env_path, &shell_path).expect("remove env");

        assert!(removed.changed);
        assert!(!env_path.exists());
        assert!(!fs::read_to_string(&shell_path)
            .expect("read shell rc")
            .contains("# ottto:start"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_claude_code_settings_can_target_active_fallback_endpoint() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-settings-fallback-test-{}",
            std::process::id()
        ));
        let path = root.join("settings.json");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(&path, r#"{"env":{"EXISTING":"keep"}}"#).expect("write settings");

        let backup_root = root.join("backups");
        let fallback = "http://127.0.0.1:44621";
        patch_claude_code_settings_at_with_relay_base(
            &path,
            &test_machine(),
            &backup_root,
            fallback,
        )
        .expect("patch settings");
        let body = fs::read_to_string(&path).expect("read settings");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json settings");
        let env = value
            .get("env")
            .and_then(|value| value.as_object())
            .expect("env object");

        assert_eq!(
            env.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
                .and_then(|value| value.as_str()),
            Some("http://127.0.0.1:44621/v1/logs")
        );
        assert!(claude_code_settings_has_relay_env(&body));
        assert!(claude_code_settings_has_relay_env_for_base(&body, fallback));
        assert!(!claude_code_settings_has_relay_env_for_base(
            &body,
            &crate::otlp_relay::default_local_relay_base_url()
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_code_relay_env_rejects_incomplete_legacy_loopback_settings() {
        let body = r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","OTEL_METRICS_EXPORTER":"otlp","OTEL_LOGS_EXPORTER":"otlp","OTEL_EXPORTER_OTLP_PROTOCOL":"http/protobuf","OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:43119/v1/logs","OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://127.0.0.1:43119/v1/metrics","OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code","OTEL_RESOURCE_ATTRIBUTES":"service.name=claude-code"}}"#;

        assert!(!claude_code_settings_has_relay_env(body));
    }

    #[test]
    fn claude_code_statusline_detection_rejects_env_only_setup() {
        let body = r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"1","CLAUDE_CODE_ENHANCED_TELEMETRY_BETA":"1","CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS":"10000","OTEL_METRICS_EXPORTER":"otlp","OTEL_LOGS_EXPORTER":"otlp","OTEL_TRACES_EXPORTER":"otlp","OTEL_EXPORTER_OTLP_PROTOCOL":"http/protobuf","OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:43119/v1/logs","OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://127.0.0.1:43119/v1/metrics","OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":"http://127.0.0.1:43119/v1/traces","OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code","OTEL_RESOURCE_ATTRIBUTES":"service.name=claude-code,ottto.source=claude_code,ottto.machine_id=machine_test"}}"#;

        assert!(claude_code_settings_has_relay_env(body));
        assert!(!claude_code_settings_has_statusline_helper(body));
    }

    #[test]
    fn install_source_action_result_uses_setup_safe_metadata_keys() {
        let result = install_source_action_result(
            "install_session_test",
            "device_test",
            "codex",
            true,
            43119,
            "Codex telemetry setup installed",
            true,
        );
        let object = result.as_object().expect("result object");
        for key in object.keys() {
            let lower = key.to_ascii_lowercase();
            for forbidden in [
                "authorization",
                "bearer",
                "cookie",
                "device_secret",
                "header",
                "key",
                "password",
                "secret",
                "token",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "install action result key should be backend-safe: {key}"
                );
            }
        }
        assert_eq!(
            object
                .get("relay_source")
                .and_then(serde_json::Value::as_str),
            Some("codex")
        );
        assert!(!object.contains_key("relay_source_header"));
        assert!(!object.contains_key("error_code"));
        assert!(!object.contains_key("error_message"));

        let failed = install_source_action_result(
            "install_session_test",
            "device_test",
            "codex",
            false,
            43119,
            "Codex relay unavailable",
            true,
        );
        assert_eq!(
            failed.get("error_code").and_then(serde_json::Value::as_str),
            Some("relay_unavailable")
        );
    }

    #[test]
    fn install_source_patch_disabled_result_uses_setup_safe_metadata_keys() {
        let result = install_source_patch_disabled_result(
            "install_session_test",
            "device_test",
            "codex",
            "Codex telemetry config patching skipped by environment",
        );
        let object = result.as_object().expect("result object");
        for key in object.keys() {
            let lower = key.to_ascii_lowercase();
            for forbidden in [
                "authorization",
                "bearer",
                "cookie",
                "device_secret",
                "header",
                "key",
                "password",
                "secret",
                "token",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "install action result key should be backend-safe: {key}"
                );
            }
        }
        assert_eq!(
            object
                .get("local_changes")
                .and_then(serde_json::Value::as_str),
            Some("patch_disabled")
        );
        assert_eq!(
            object
                .get("config_patched")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn pi_install_source_registers_device_without_config_patch() {
        assert!(source_requires_device_registration(&SourceKind::Pi));
        assert!(!source_requires_config_patch(&SourceKind::Pi));

        let result = install_source_registration_result(
            "install_session_test",
            "device_test",
            "pi",
            "Pi local session import prepared",
        );
        let object = result.as_object().expect("result object");
        for key in object.keys() {
            let lower = key.to_ascii_lowercase();
            for forbidden in [
                "authorization",
                "bearer",
                "cookie",
                "device_secret",
                "header",
                "key",
                "password",
                "secret",
                "token",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "install action result key should be backend-safe: {key}"
                );
            }
        }
        assert_eq!(
            object.get("source").and_then(serde_json::Value::as_str),
            Some("pi")
        );
        assert_eq!(
            object
                .get("local_changes")
                .and_then(serde_json::Value::as_str),
            Some("registered")
        );
        assert_eq!(
            object
                .get("config_patched")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            object
                .get("relay_required")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn smoke_command_failure_maps_to_failed_verification_result() {
        let smoke = SmokeResult {
            command_found: true,
            succeeded: false,
            exit_status: Some(1),
            duration_ms: 12,
            message: "Pi smoke session failed before telemetry could be sent.".to_string(),
            diagnostic: Some("Token is expired.".to_string()),
            error_code: Some("smoke_command_failed".to_string()),
            local_session_observed: Some(false),
        };

        let result = smoke_failure_verification_result(
            SourceKind::Pi,
            &smoke,
            Some("2026-05-06T12:00:00Z".to_string()),
        );

        assert_eq!(result.status, SourceVerificationStatus::Failed);
        assert!(!result.verified);
        assert_eq!(result.message.code, "smoke_command_failed");
        assert_eq!(result.records_seen, 0);
    }

    #[test]
    fn expired_setup_run_token_maps_to_reconnect_required_verification() {
        let error = LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/api/v1/setup-runs/[id]/local-client/verification".to_string(),
            status: Some(401),
            body_excerpt: Some("Setup run companion token expired".to_string()),
        });

        let result = verification_result_for_backend_error(
            SourceKind::Codex,
            Some("2026-05-08T20:00:00Z".to_string()),
            &error,
        );

        assert_eq!(result.status, SourceVerificationStatus::ReconnectRequired);
        assert!(!result.verified);
        assert_eq!(result.message.code, "setup_run_token_expired");
    }

    #[test]
    fn missing_refresh_binding_maps_to_reconnect_required_verification() {
        let result = verification_result_for_backend_error(
            SourceKind::Codex,
            Some("2026-05-08T20:00:00Z".to_string()),
            &LocalApiError::SetupRunConnectionMissing,
        );

        assert_eq!(result.status, SourceVerificationStatus::ReconnectRequired);
        assert!(!result.verified);
        assert_eq!(result.message.code, "setup_run_connection_missing");
        assert!(result.message.text.contains("Open ottto.net/apps"));
    }

    #[test]
    #[serial]
    fn verify_without_local_account_points_to_app_sign_in() {
        let _lock = lock_backend_test_env();
        let root = control_test_root("verify-no-account");
        create_control_test_dir(&root.join(".codex"));
        let _home_guard = EnvVarGuard::set_path("HOME", &root);
        patch_codex_config_at_with_relay_base(
            &root.join(".codex/config.toml"),
            &root.join("support"),
            &crate::otlp_relay::default_local_relay_base_url(),
        )
        .expect("seed clean config");
        let daemon = daemon().with_connection(Some(LocalConnectionBinding {
            setup_run_id: "setup_stale".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            api_base_url: "https://api.ottto.net".to_string(),
        }));

        let result = verify_source(
            &daemon,
            &RequestAuthorization::TrustedCompanionApp,
            SourceKind::Codex,
            false,
        )
        .expect("verification should return actionable account state");

        assert_eq!(result.status, SourceVerificationStatus::AccountNotConnected);
        assert!(!result.verified);
        assert_eq!(result.message.code, "account_not_connected");
        assert!(result.message.text.contains("Use Sign in in the Ottto app"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backend_cli_error_message_omits_endpoint_details() {
        let error = cli_error(LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/api/v1/setup-runs/[id]/local-client/scan-result".to_string(),
            status: Some(401),
            body_excerpt: Some("Setup run expired request_id=req_private".to_string()),
        }));

        assert_eq!(
            error.message,
            "Setup run expired. Open the Ottto app from Ottto to attach an active setup run."
        );
        assert!(!error.message.contains("/api/v1"));
        assert!(!error.message.contains("req_private"));
    }

    #[test]
    fn setup_connection_missing_maps_to_needs_user_action() {
        let error = cli_error(LocalApiError::SetupRunConnectionMissing);

        assert_eq!(error.code, CliErrorCode::NeedsUserAction);
        assert_eq!(error.code.exit_code(), 60);
        assert!(!error.retryable);
        assert!(error.message.contains("Setup needs browser approval"));
    }

    #[test]
    fn setup_timeout_maps_to_timed_out_exit_code() {
        let error = cli_error(LocalApiError::TimedOut(
            "setup wait reached timeout".to_string(),
        ));

        assert_eq!(error.code, CliErrorCode::TimedOut);
        assert_eq!(error.code.exit_code(), 61);
        assert!(error.retryable);
        assert!(error.message.contains("Timed out waiting for setup"));
    }

    fn control_token_validation_server(status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
        let address = listener.local_addr().expect("local address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept validation request");
            read_complete_http_request(&mut stream);
            let (reason, body) = if status == 200 {
                (
                    "OK",
                    r#"{"source":"codex","action":"enable_telemetry","organization_id":"org_123","user_id":"user_123","expires_at":"2026-05-17T00:00:00Z"}"#,
                )
            } else {
                ("Unauthorized", r#"{"detail":"Invalid app control token"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write validation response");
        });
        format!("http://{address}")
    }

    fn control_token_validation_server_with_marker(status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
        let address = listener.local_addr().expect("local address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept validation request");
            read_complete_http_request(&mut stream);
            let (reason, body) = if status == 200 {
                (
                    "OK",
                    r#"{"source":"codex","action":"enable_telemetry","organization_id":"org_123","user_id":"user_123","expires_at":"2026-05-17T00:00:00Z"}"#,
                )
            } else {
                ("Unauthorized", r#"{"detail":"Invalid app control token"}"#)
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write validation response");
            if status != 200 {
                return;
            }

            let (mut marker_stream, _) = listener.accept().expect("accept marker request");
            read_complete_http_request(&mut marker_stream);
            let body = "{}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            marker_stream
                .write_all(response.as_bytes())
                .expect("write marker response");
        });
        format!("http://{address}")
    }

    fn diagnostics_upload_server(captured: Arc<Mutex<Option<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind diagnostics backend");
        let address = listener.local_addr().expect("local address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept diagnostics upload");
            let request = read_complete_http_request(&mut stream);
            *captured.lock().expect("capture diagnostics request") = Some(request);
            let body = r#"{"upload_id":"diag_upload_123","uploaded_at":"2026-05-05T09:30:00Z"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write diagnostics response");
        });
        format!("http://{address}")
    }

    fn unused_loopback_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        format!("http://{address}")
    }

    fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    request.extend_from_slice(&buffer[..bytes_read]);
                    if http_request_complete(&request) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&request).to_string()
    }

    fn http_request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        request.len() >= body_start + content_length
    }

    fn test_control_token(action: &str, source: &str, expires_in_seconds: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64;
        let payload = serde_json::json!({
            "type": "apps_control",
            "source": source,
            "action": action,
            "organization_id": "org_123",
            "exp": now + expires_in_seconds,
        });
        format!(
            "header.{}.signature",
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes())
        )
    }

    fn daemon() -> LocalDaemon {
        LocalDaemon::new(
            test_machine(),
            ControlToken::new("token").expect("token"),
            "2026-05-05T09:20:00Z",
        )
    }

    fn connected_account() -> LocalAccountBinding {
        LocalAccountBinding {
            state: LocalAccountState::Connected,
            user: Some(LocalAccountUser {
                id: "user_test".to_string(),
                email: "test@example.com".to_string(),
                display_name: Some("Test User".to_string()),
            }),
            organization: Some(LocalAccountOrganization {
                id: "org_test".to_string(),
                name: "Test Org".to_string(),
            }),
            connected_at: Some("2026-05-05T09:00:00Z".to_string()),
            last_refreshed_at: Some("2026-05-05T09:20:00Z".to_string()),
            message: None,
        }
    }

    fn test_machine() -> MachineIdentity {
        MachineIdentity {
            machine_id: "machine_test".to_string(),
            installation_id: "install_test".to_string(),
            display_name: "Test Mac".to_string(),
            hostname: "test-mac.local".to_string(),
            os: OperatingSystem::Macos,
            arch: "arm64".to_string(),
            local_platform_version: "0.1.0".to_string(),
            hardware_uuid: None,
        }
    }
}
