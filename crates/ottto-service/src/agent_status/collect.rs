//! Shared status collection dispatch and bounded command execution.
//! Called through the agent-status facade by source collectors.
//! Owns collection plumbing and the existing process capture helpers.

use crate::agent_status::append_codex_credential_read_failed_diagnostic;
use crate::agent_status::codex_workspace_target_evidence_from_id_token;
use crate::agent_status::collect_claude_status_snapshots;
use crate::agent_status::collect_codex_status_snapshots;
use crate::agent_status::collect_pi_status;
use crate::agent_status::mpsc;
use crate::agent_status::read_codex_auth_credentials_at;
use crate::agent_status::resolved_codex_home_command;
use crate::agent_status::thread;
use crate::agent_status::unsupported_account;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentStatusCollection;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeDesktopMetadataCache;
use crate::agent_status::CodexHomeTrust;
use crate::agent_status::CodexWorkspaceTargetEvidence;
use crate::agent_status::Command;
use crate::agent_status::CommandOutput;
use crate::agent_status::Duration;
use crate::agent_status::Instant;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::Read;
use crate::agent_status::SourceKind;
use crate::agent_status::Stdio;
use crate::agent_status::PIPE_DRAIN_TIMEOUT;

pub(crate) fn collect_agent_status_collection(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    collect_agent_status_collection_reusing(
        source,
        captured_at,
        expires_at,
        &mut ClaudeDesktopMetadataCache::default(),
    )
}

/// [`collect_agent_status_collection`] for a caller that keeps Claude Desktop
/// session metadata between its passes.
pub(crate) fn collect_agent_status_collection_reusing(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
    desktop_metadata: &mut ClaudeDesktopMetadataCache,
) -> AgentStatusCollection {
    match source {
        SourceKind::Codex => collect_codex_status_snapshots(captured_at, expires_at),
        SourceKind::ClaudeCode => {
            collect_claude_status_snapshots(captured_at, expires_at, desktop_metadata)
        }
        SourceKind::Pi => {
            single_agent_status_collection(collect_pi_status(captured_at, expires_at))
        }
    }
}

pub(super) fn single_agent_status_collection(
    snapshot: AgentStatusSnapshot,
) -> AgentStatusCollection {
    AgentStatusCollection {
        snapshots: vec![snapshot.clone()],
        source_health_snapshot: snapshot,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
        setup_snapshot_index: Some(0),
    }
}

pub(super) fn append_current_plan_observation(snapshot: &mut AgentStatusSnapshot) {
    let Some(account) = snapshot.account.as_ref() else {
        return;
    };
    let is_current = account.login_state == AgentLoginState::SignedIn
        && matches!(
            account.confidence,
            AgentStatusConfidence::High | AgentStatusConfidence::Medium
        );
    let Some(observation) = plan_observation_from_snapshot_account(snapshot, is_current) else {
        return;
    };
    snapshot.plan_observations.push(observation);
}

/// Describe `snapshot`'s own account as a plan observation, stamped with that
/// snapshot's provenance (capture time, collection method, model provider).
pub(super) fn plan_observation_from_snapshot_account(
    snapshot: &AgentStatusSnapshot,
    is_current: bool,
) -> Option<AgentStatusPlanObservation> {
    let account = snapshot.account.as_ref()?;
    if account.subscription_product.is_none()
        && account.plan_type.is_none()
        && account.account_id.is_none()
        && account.account_identifier_hash.is_none()
        && account.organization_identifier_hash.is_none()
        && account.credential_fingerprint_hash.is_none()
        && account.email.is_none()
        && account.organization_id.is_none()
        && account.organization_label.is_none()
    {
        return None;
    }
    Some(AgentStatusPlanObservation {
        desktop_recent_at: None,
        observed_at: Some(snapshot.captured_at.clone()),
        evidence_method: Some(collection_method_key(&snapshot.collection_method).to_string()),
        source_session_id: None,
        provider: account.provider.clone(),
        billing_provider: account.provider.clone(),
        model_provider: snapshot
            .model
            .as_ref()
            .and_then(|model| model.provider.clone()),
        billing_channel: account.billing_channel.clone(),
        auth_mode: account.auth_method.clone(),
        gateway_provider: None,
        subscription_product: account.subscription_product.clone(),
        plan_type: account.plan_type.clone(),
        account_label: account.email.clone(),
        account_id: account.account_id.clone(),
        organization_label: account.organization_label.clone(),
        organization_id: account.organization_id.clone(),
        account_identifier_hash: account.account_identifier_hash.clone(),
        organization_identifier_hash: account.organization_identifier_hash.clone(),
        superseded_account_identifier_hash: account.superseded_account_identifier_hash.clone(),
        superseded_organization_identifier_hash: account
            .superseded_organization_identifier_hash
            .clone(),
        credential_fingerprint_hash: account.credential_fingerprint_hash.clone(),
        billing_identity_evidence: account.billing_identity_evidence.clone(),
        billing_identity_confidence: account.billing_identity_confidence.clone(),
        confidence: account.confidence.clone(),
        is_current: Some(is_current),
    })
}

/// Most Claude accounts worth describing in one source-health snapshot. Slot
/// capacity is already bounded well below this; the cap only keeps a corrupt
/// registry from growing the payload without limit.
pub(super) const CLAUDE_PLAN_OBSERVATION_ACCOUNT_LIMIT: usize = 20;

/// Carry every collected Claude account's product into the source-health
/// snapshot.
///
/// That snapshot is the default slot's, so on its own it names the product of
/// exactly one account: whichever one the CLI is signed into now. Each
/// registered slot collects its own account, and only that slot's snapshot
/// knows its product. Without this the app still lists the other accounts — a
/// Claude Desktop session bucket supplies the email — but has no product to
/// title them with, so they read as a bare email or as the source's own name
/// ("Claude Code") instead of "Claude Max 20x".
///
/// Only the product observation is added here. Identity, meters and health for
/// those accounts keep flowing through the Claude accounts control surface,
/// which owns them.
pub(super) fn append_registered_claude_plan_observations(
    source_health_snapshot: &mut AgentStatusSnapshot,
    snapshots: &[AgentStatusSnapshot],
) {
    let current_identity = source_health_snapshot
        .account
        .as_ref()
        .and_then(claude_plan_identity_from_account);
    let mut described = source_health_snapshot
        .plan_observations
        .iter()
        .filter(|observation| {
            observation.subscription_product.is_some() || observation.plan_type.is_some()
        })
        .filter_map(claude_plan_identity_from_observation)
        .collect::<BTreeSet<_>>();
    for snapshot in snapshots.iter().take(CLAUDE_PLAN_OBSERVATION_ACCOUNT_LIMIT) {
        let Some(account) = snapshot.account.as_ref() else {
            continue;
        };
        if account.subscription_product.is_none() && account.plan_type.is_none() {
            continue;
        }
        let Some(identity) = claude_plan_identity_from_account(account) else {
            continue;
        };
        if !described.insert(identity.clone()) {
            continue;
        }
        let is_current = current_identity.as_ref() == Some(&identity);
        if let Some(observation) = plan_observation_from_snapshot_account(snapshot, is_current) {
            source_health_snapshot.plan_observations.push(observation);
        }
    }
}

/// The account+organization pair an observation describes. Both halves are
/// required: an account hash alone cannot tell two organizations of the same
/// login apart, which is exactly what a Team seat alongside a personal
/// organization produces.
pub(super) fn claude_plan_identity_from_observation(
    observation: &AgentStatusPlanObservation,
) -> Option<(String, String)> {
    claude_plan_identity(
        observation.account_identifier_hash.as_deref(),
        observation.organization_identifier_hash.as_deref(),
    )
}

pub(super) fn claude_plan_identity_from_account(
    account: &AgentAccountStatus,
) -> Option<(String, String)> {
    claude_plan_identity(
        account.account_identifier_hash.as_deref(),
        account.organization_identifier_hash.as_deref(),
    )
}

pub(super) fn claude_plan_identity(
    account_identifier_hash: Option<&str>,
    organization_identifier_hash: Option<&str>,
) -> Option<(String, String)> {
    let account = account_identifier_hash.filter(|hash| !hash.is_empty())?;
    let organization = organization_identifier_hash.filter(|hash| !hash.is_empty())?;
    Some((account.to_string(), organization.to_string()))
}

pub(super) fn append_codex_workspace_observations_at(
    snapshot: &mut AgentStatusSnapshot,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Vec<CodexWorkspaceTargetEvidence> {
    let credentials = match read_codex_auth_credentials_at(codex_home, home_trust) {
        Ok(Some(credentials)) => credentials,
        Ok(None) => return Vec::new(),
        Err(_) => {
            append_codex_credential_read_failed_diagnostic(snapshot);
            return Vec::new();
        }
    };
    let Some(token) = credentials.id_token.as_deref() else {
        return Vec::new();
    };
    // Only workspace TARGETS come out of the ID token. The token's
    // `organizations[]` claim lists platform.openai.com organizations, which
    // govern API keys; ChatGPT/Codex subscriptions live in chatgpt.com
    // workspaces keyed by `chatgpt_account_id`, and the two id spaces differ
    // even where the names match. A platform organization therefore cannot
    // witness a subscription, so it no longer contributes a plan observation:
    // one carrying a plan name used to be uploaded as
    // `billing_channel: "subscription"` with no account identifier at all,
    // which the backend materialized into its own priced subscription row keyed
    // on the account label -- a plan the operator does not pay for, added to the
    // monthly total. The signed-in workspace's real plan still arrives through
    // the app-server probe, which reads the subscription rather than inferring
    // it.
    codex_workspace_target_evidence_from_id_token(token, &snapshot.captured_at).unwrap_or_default()
}

pub(super) fn collection_method_key(method: &AgentStatusCollectionMethod) -> &'static str {
    match method {
        AgentStatusCollectionMethod::AppServer => "app_server",
        AgentStatusCollectionMethod::CliJson => "cli_json",
        AgentStatusCollectionMethod::CliText => "cli_text",
        AgentStatusCollectionMethod::ConfigFile => "config_file",
        AgentStatusCollectionMethod::StatusLine => "status_line",
        AgentStatusCollectionMethod::CommandProbe => "command_probe",
        AgentStatusCollectionMethod::ManualFallback => "manual_fallback",
        AgentStatusCollectionMethod::Unsupported => "unsupported",
    }
}

pub(super) fn billing_identity_evidence_for(
    account_hash: &Option<String>,
    organization_hash: &Option<String>,
    credential_hash: &Option<String>,
) -> Option<String> {
    if credential_hash.is_some() {
        Some("credential_fingerprint".to_string())
    } else if account_hash.is_some() {
        Some("provider_account_id".to_string())
    } else if organization_hash.is_some() {
        Some("organization_identifier".to_string())
    } else {
        None
    }
}

pub(super) fn base_snapshot(
    source: SourceKind,
    status: AgentStatusState,
    collection_method: AgentStatusCollectionMethod,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    AgentStatusSnapshot {
        source,
        status,
        collection_method,
        captured_at,
        expires_at,
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    }
}

pub(super) fn not_installed_snapshot(
    source: SourceKind,
    binary: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let mut snapshot = base_snapshot(
        source,
        AgentStatusState::NotInstalled,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: None,
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("")
    });
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "agent_cli_not_found",
        AgentDiagnosticSeverity::Warning,
        format!("{binary} was not found on PATH or in known local metadata."),
    ));
    snapshot
}

pub(super) fn run_command_capture(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> CommandOutput {
    run_command_capture_with_exact_env(program, args, timeout)
}

pub(super) fn run_codex_home_command(
    codex_home: &Path,
    args: &[&str],
    timeout: Duration,
    allow_ambient_environment: bool,
) -> CommandOutput {
    let Some(mut command) =
        resolved_codex_home_command(codex_home, args, allow_ambient_environment)
    else {
        return CommandOutput {
            command_found: false,
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_prepared_command_capture(command, timeout)
}

pub(super) fn run_command_capture_with_exact_env(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> CommandOutput {
    let Some(program_path) = crate::command_env::executable_path(program) else {
        return CommandOutput {
            command_found: false,
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    let mut command = Command::new(program_path);
    command.args(args);
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    if program == "pi" && args == ["--list-models"] {
        command.envs(crate::command_env::provider_env());
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_prepared_command_capture(command, timeout)
}

pub(super) fn run_prepared_command_capture(
    mut command: Command,
    timeout: Duration,
) -> CommandOutput {
    let start = Instant::now();
    let mut child = match crate::local_resource_diagnostics::cli_children::spawn(&mut command) {
        Ok(child) => child,
        Err(_) => {
            return CommandOutput {
                command_found: false,
                success: false,
                status_code: None,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
    };

    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: status.success(),
                    status_code: status.code(),
                    stdout,
                    stderr,
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
        }
    }
}

pub(super) fn spawn_pipe_reader<R>(mut pipe: R) -> mpsc::Receiver<String>
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

pub(super) fn collect_pipe_reader(
    reader: Option<mpsc::Receiver<String>>,
    timeout: Duration,
) -> String {
    reader
        .and_then(|receiver| receiver.recv_timeout(timeout).ok())
        .unwrap_or_default()
}

pub(super) fn executable_exists(program: &str) -> bool {
    crate::command_env::executable_path(program).is_some()
}

pub(super) fn default_codex_home() -> PathBuf {
    home_path(".codex")
}

pub(super) fn home_path(relative: &str) -> PathBuf {
    home_dir().join(relative)
}

pub(crate) fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// Local display supplement only: never contributes billing/account evidence.
pub(crate) fn claude_session_registrations() -> crate::claude_session_registrations::Registrations {
    #[cfg(not(test))]
    {
        crate::claude_session_registrations::collect(&home_path(".claude/sessions"))
    }
    // Ordinary unit tests must not acquire the operator's provider state.
    #[cfg(test)]
    crate::claude_session_registrations::Registrations::default()
}
