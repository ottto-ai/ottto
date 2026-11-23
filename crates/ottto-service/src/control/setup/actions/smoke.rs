//! setup actions smoke for local control.

use crate::control::backend_post_json;
use crate::control::current_millis;
use crate::control::detect_agent_installation;
use crate::control::empty_source_config;
use crate::control::json;
use crate::control::mpsc;
use crate::control::no_fresh_telemetry_message;
use crate::control::redact_inline;
use crate::control::source_display_name;
use crate::control::source_slug;
use crate::control::thread;
use crate::control::verification_result_with_config;
use crate::control::verification_status_slug;
use crate::control::Command;
use crate::control::Duration;
use crate::control::Instant;
use crate::control::LocalApiError;
use crate::control::LocalDaemon;
use crate::control::MachineIdentity;
use crate::control::PiModelRoute;
use crate::control::Read;
use crate::control::SetupRunVerificationResponse;
use crate::control::SourceConfigState;
use crate::control::SourceKind;
use crate::control::SourceVerificationResult;
use crate::control::SourceVerificationStatus;
use crate::control::Stdio;
use crate::control::AGENT_CLI_UNAVAILABLE_CODE;
use crate::control::CLAUDE_OAUTH_REAUTH_REQUIRED_CODE;
use crate::control::DEFAULT_API_BASE_URL;
use crate::control::DIRECT_API_BASE_URL;
use crate::control::LEGACY_API_BASE_URL;
use crate::control::PIPE_DRAIN_TIMEOUT;
use crate::control::SMOKE_COMMAND_TIMEOUT;
use crate::control::SMOKE_PROMPT;
use crate::control::SMOKE_USAGE_LIMIT_ERROR_CODE;
use crate::control::SOURCE_NOT_INSTALLED_CODE;
use crate::control::VERIFICATION_MARKER_ATTRIBUTE;
use crate::control::VERIFICATION_MARKER_HEADER;
use crate::control::VERIFICATION_MARKER_METRIC_NAME;

pub(in crate::control) struct SmokeResult {
    pub(in crate::control) command_found: bool,
    pub(in crate::control) succeeded: bool,
    pub(in crate::control) exit_status: Option<i32>,
    pub(in crate::control) duration_ms: u128,
    pub(in crate::control) message: String,
    pub(in crate::control) diagnostic: Option<String>,
    pub(in crate::control) error_code: Option<String>,
    pub(in crate::control) local_session_observed: Option<bool>,
}

/// Code for a Verify smoke asked for a source without a live prompt check.
pub(in crate::control) const NO_LIVE_CHECK_CODE: &str = "no_live_check";

/// Code for a Verify smoke the quiet window held back: starting Claude Code
/// now could refresh, and so sign out, the saved login.
pub(crate) const CLAUDE_LOGIN_REFRESH_PENDING_CODE: &str = "claude_login_refresh_pending";

pub(crate) const CLAUDE_SMOKE_TIMEOUT_MESSAGE: &str =
    "The Claude Code test run timed out before Ottto could check it.";

pub(in crate::control) fn run_verification_smoke_prompt(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<SmokeResult, LocalApiError> {
    if *source != SourceKind::ClaudeCode {
        // Only Claude Code has a live prompt check: Pi runs its own route
        // checks and Codex verifies its local import without a prompt.
        return Ok(SmokeResult {
            command_found: true,
            succeeded: false,
            exit_status: None,
            duration_ms: 0,
            message: format!(
                "Ottto runs no live check for {}.",
                source_display_name(source)
            ),
            diagnostic: None,
            error_code: Some(NO_LIVE_CHECK_CODE.to_string()),
            local_session_observed: None,
        });
    }
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
    Ok(run_claude_smoke_prompt())
}

pub(in crate::control) fn run_claude_smoke_prompt() -> SmokeResult {
    if let Err(refusal) =
        crate::claude_spawn_gate::check_short_claude_run(&ottto_core::ClaudeConfigDirSlot::Default)
    {
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
    let command = claude_smoke_command();
    let mut result = run_bounded_command(
        command.program,
        &command.args,
        SMOKE_COMMAND_TIMEOUT,
        source_display_name(&SourceKind::ClaudeCode),
    );
    record_smoke_prompt(
        crate::provider_calls::Provider::Anthropic,
        crate::provider_calls::CallKind::ClaudeSmokePrompt,
        crate::provider_calls::claude_slot_account_hash(&ottto_core::ClaudeConfigDirSlot::Default),
        &result,
    );
    classify_source_smoke_failure(&SourceKind::ClaudeCode, &mut result);
    result
}

/// One provider-call log line per smoke prompt that started: at least one
/// request carrying the prompt.
pub(in crate::control) fn record_smoke_prompt(
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

pub(in crate::control) struct SmokeCommand {
    pub(in crate::control) program: &'static str,
    pub(in crate::control) args: Vec<String>,
}

/// The Verify prompt for Claude Code, the only source with a live prompt check.
pub(in crate::control) fn claude_smoke_command() -> SmokeCommand {
    SmokeCommand {
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
    }
}

pub(in crate::control) fn pi_smoke_command(route: Option<&PiModelRoute>) -> SmokeCommand {
    let version = detect_agent_installation(&SourceKind::Pi).version;
    pi_smoke_command_with_version(route, version.as_deref())
}

pub(in crate::control) fn pi_smoke_command_with_version(
    route: Option<&PiModelRoute>,
    version: Option<&str>,
) -> SmokeCommand {
    // The check only needs a reply, so it asks for the lowest thinking level
    // whatever the user's default is. Pi turns thinking off where the model
    // allows it and otherwise uses the model's lowest supported level.
    let mut args = vec![
        "--no-builtin-tools",
        "--no-context-files",
        "--print",
        "--thinking",
        "off",
    ]
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

pub(in crate::control) fn pi_route_is_unscoped(route: &PiModelRoute) -> bool {
    route.provider == "default" && route.model == "default"
}

pub(in crate::control) fn pi_route_provider(route: &PiModelRoute) -> Option<String> {
    (!pi_route_is_unscoped(route)).then(|| route.provider.clone())
}

pub(in crate::control) fn pi_route_model(route: &PiModelRoute) -> Option<String> {
    (!pi_route_is_unscoped(route)).then(|| route.model.clone())
}

pub(in crate::control) fn pi_route_label(route: &PiModelRoute) -> String {
    if pi_route_is_unscoped(route) {
        "default route".to_string()
    } else {
        format!("{} / {}", route.provider, route.model)
    }
}

pub(in crate::control) fn run_bounded_command(
    program: &str,
    args: &[String],
    timeout: Duration,
    display_name: &str,
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
                    local_session_observed: None,
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
                    local_session_observed: None,
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
                    local_session_observed: None,
                };
            }
        }
    }
}

pub(in crate::control) fn emit_api_key_verification_marker(
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

pub(in crate::control) fn verification_marker_body(
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

pub(in crate::control) fn otlp_metrics_url(raw_endpoint: &str) -> Result<String, LocalApiError> {
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

pub(in crate::control) fn no_fresh_telemetry_code(
    source: &SourceKind,
    smoke: &SmokeResult,
) -> &'static str {
    if source == &SourceKind::Pi && smoke.local_session_observed == Some(true) {
        "pi_session_created_not_uploaded"
    } else if source == &SourceKind::Pi {
        "pi_no_local_session_created"
    } else {
        "no_fresh_telemetry"
    }
}

pub(in crate::control) fn verification_failure_code(
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

pub(in crate::control) fn verification_failure_message(
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

pub(in crate::control) fn telemetry_disabled_by_admin_message(source: &SourceKind) -> String {
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

pub(in crate::control) fn redact_command_diagnostic(input: &str) -> Option<String> {
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

pub(in crate::control) fn truncate_diagnostic(value: &str) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 280;
    if value.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return value.to_string();
    }
    let mut truncated = value.chars().take(MAX_DIAGNOSTIC_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

pub(in crate::control) fn command_diagnostic_is_usage_limited(diagnostic: Option<&str>) -> bool {
    diagnostic.is_some_and(crate::text_indicates_usage_limited)
}

pub(in crate::control) fn command_diagnostic_requires_claude_reauth(
    diagnostic: Option<&str>,
) -> bool {
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

pub(in crate::control) fn classify_source_smoke_failure(
    source: &SourceKind,
    result: &mut SmokeResult,
) {
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

pub(in crate::control) fn usage_limited_smoke_message(display_name: &str) -> String {
    format!("{display_name} is signed in, but its usage limit is reached. Wait for quota to reset or update usage, then retry Verify.")
}

pub(in crate::control) fn smoke_failure_verification_result(
    source: SourceKind,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    smoke_failure_verification_result_with_config(source, config, smoke, smoke_after)
}

pub(in crate::control) fn smoke_failure_verification_result_with_config(
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
pub(in crate::control) fn source_binary_present(source: &SourceKind) -> bool {
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
pub(in crate::control) fn not_installed_verification_result(
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

pub(in crate::control) fn smoke_result_metadata(smoke: &SmokeResult) -> serde_json::Value {
    json!({
        "command_found": smoke.command_found,
        "exit_status": smoke.exit_status,
        "duration_ms": smoke.duration_ms,
        "diagnostic": smoke.diagnostic.clone(),
        "local_session_observed": smoke.local_session_observed,
    })
}

pub(in crate::control) fn pi_route_summary_metadata(
    result: &SourceVerificationResult,
) -> serde_json::Value {
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
