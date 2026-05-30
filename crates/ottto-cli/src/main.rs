use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use ottto_core::{
    client_control_token, default_socket_path, execute_local_uninstall,
    ingest_claude_statusline_payload, install_owner_for_path, kickstart_macos_launch_agent,
    local_lifecycle_home_dir, request_unix_socket, UninstallExecutionOptions,
    OTTTO_SERVICE_BINARY_NAME, OTTTO_SOCKET_ENV,
};
use ottto_protocol::{
    CliError, CliErrorCode, CliErrorResponse, DiagnosticsUploadApproval, LocalControlCommand,
    LocalControlRequest, LocalControlResponse, RedactedValue, SourceKind,
    LOCAL_CONTROL_PROTOCOL_VERSION,
};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_SETUP_TIMEOUT_SECONDS: u64 = 300;
const SETUP_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(name = "ottto")]
#[command(about = "Ottto local platform CLI for developers, support, CI, and AI agents")]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Override the ottto-service Unix socket path"
    )]
    socket: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Override the local-control token for CLI and agent requests"
    )]
    token: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Do not kickstart the standard per-user ottto-service"
    )]
    no_autostart: bool,
    #[arg(
        long,
        global = true,
        help = "Emit NDJSON progress events and a final event; requires --json"
    )]
    watch: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Show daemon, account, relay, update, and app health")]
    Status(StatusArgs),
    #[command(about = "List apps or refresh app setup status")]
    Apps(AppsArgs),
    #[command(about = "Refresh one source status using the lower-level source noun")]
    AgentStatus(SourceArgs),
    #[command(about = "Connect this Mac through a browser claim")]
    Setup(SetupArgs),
    #[command(about = "Sign in and connect this Mac through a browser claim")]
    Login(SetupArgs),
    #[command(about = "Show the Ottto account connected to this Mac")]
    Account(JsonArgs),
    #[command(about = "Disconnect this Mac from Ottto")]
    Logout(LogoutArgs),
    #[command(about = "Run daemon health checks and print current status")]
    Doctor(JsonArgs),
    #[command(about = "Apply daemon-approved repair for one app")]
    Fix(SourceArgs),
    #[command(about = "Verify one app and publish safe setup status")]
    Verify(VerifyArgs),
    #[command(hide = true)]
    ClaudeCodeStatusline(JsonArgs),
    #[command(about = "Collect local-only or approved support diagnostics")]
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticsCommand,
    },
    #[command(about = "Check owner-aware update state and instructions")]
    Update(UpdateArgs),
    #[command(about = "Remove Ottto local runtime state for this user")]
    Uninstall(JsonArgs),
}

#[derive(Debug, Args)]
struct JsonArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(
        long,
        help = "Refresh Codex, Claude Code, and Pi status before returning"
    )]
    refresh_agent_status: bool,
}

#[derive(Debug, Args)]
struct AppsArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[command(subcommand)]
    command: Option<AppsCommand>,
}

#[derive(Debug, Subcommand)]
enum AppsCommand {
    #[command(about = "Refresh all supported app statuses")]
    Detect(JsonArgs),
    #[command(about = "Refresh and return one app status")]
    Status(AppStatusArgs),
}

#[derive(Debug, Args)]
struct AppStatusArgs {
    #[arg(long, value_enum, help = "App to refresh")]
    app: SourceArg,
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

#[derive(Debug, Clone, Args)]
struct SetupArgs {
    #[arg(long, help = "Browser claim code from the Ottto Apps page")]
    claim_code: Option<String>,
    #[arg(long, help = "Do not open the browser; print the claim URL and code")]
    no_browser: bool,
    #[arg(
        long,
        help = "Return after starting or attaching setup without waiting"
    )]
    no_wait: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = DEFAULT_SETUP_TIMEOUT_SECONDS,
        help = "Seconds to wait for browser approval and setup progress"
    )]
    timeout: u64,
    #[arg(long, hide = true)]
    setup_run_id: Option<String>,
    #[arg(long, hide = true)]
    api_base_url: Option<String>,
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

#[derive(Debug, Args)]
struct LogoutArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(
        long,
        help = "Clear local credentials without first disconnecting this Mac in Ottto"
    )]
    local_only: bool,
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("source_selector")
            .args(["source", "app"])
            .required(true)
            .multiple(false)
    )
)]
struct SourceArgs {
    #[arg(long, value_enum, help = "Source to operate on")]
    source: Option<SourceArg>,
    #[arg(long, value_enum, help = "App to operate on")]
    app: Option<SourceArg>,
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

impl SourceArgs {
    fn selected_source(&self) -> SourceKind {
        self.source
            .or(self.app)
            .expect("clap requires --source or --app")
            .into()
    }
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("source_selector")
            .args(["source", "app"])
            .required(true)
            .multiple(false)
    )
)]
struct VerifyArgs {
    #[arg(long, value_enum, help = "Source to operate on")]
    source: Option<SourceArg>,
    #[arg(long, value_enum, help = "App to operate on")]
    app: Option<SourceArg>,
    #[arg(
        long,
        help = "Repair local telemetry config drift before running verification"
    )]
    repair: bool,
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

impl VerifyArgs {
    fn selected_source(&self) -> SourceKind {
        self.source
            .or(self.app)
            .expect("clap requires --source or --app")
            .into()
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceArg {
    Codex,
    #[value(alias = "claude_code")]
    ClaudeCode,
    Pi,
}

#[derive(Debug, Subcommand)]
enum DiagnosticsCommand {
    #[command(about = "Collect a redacted diagnostics bundle")]
    Collect(DiagnosticsCollectArgs),
}

#[derive(Debug, Args)]
struct UpdateArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[command(subcommand)]
    command: Option<UpdateCommand>,
}

#[derive(Debug, Subcommand)]
enum UpdateCommand {
    #[command(about = "Check the release manifest without applying an update")]
    Check(JsonArgs),
}

#[derive(Debug, Args)]
struct DiagnosticsCollectArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(long, help = "Request backend diagnostics upload after collection")]
    upload: bool,
    #[arg(
        long,
        requires = "upload",
        help = "Confirm diagnostics upload approval"
    )]
    approve_upload: bool,
    #[arg(
        long,
        requires = "upload",
        help = "Accept the support retention disclosure"
    )]
    accept_retention_disclosure: bool,
    #[arg(long, requires = "upload", help = "Support claim authorizing upload")]
    support_claim: Option<String>,
    #[arg(long, hide = true, requires = "upload")]
    api_base_url: Option<String>,
}

#[derive(Debug)]
struct Invocation {
    socket: PathBuf,
    request: LocalControlRequest,
    output_mode: OutputMode,
    auto_start: bool,
}

fn main() {
    let cli = Cli::parse();
    let setup_args = match &cli.command {
        Command::Setup(args) | Command::Login(args) => Some(args.clone()),
        _ => None,
    };
    let output_mode = match output_mode(command_json(&cli.command), cli.watch) {
        Ok(mode) => mode,
        Err(error) => {
            let code = print_error(error, OutputMode::Human, None);
            std::process::exit(code);
        }
    };
    if let Command::ClaudeCodeStatusline(args) = &cli.command {
        let code = run_claude_code_statusline(args.json);
        std::process::exit(code);
    }
    if matches!(cli.command, Command::Uninstall(_)) {
        let code = run_uninstall(output_mode);
        std::process::exit(code);
    }
    let invocation = build_invocation(cli, output_mode);
    let code = if let Some(setup_args) = setup_args {
        run_setup(invocation, setup_args)
    } else {
        run(invocation)
    };
    std::process::exit(code);
}

fn run_claude_code_statusline(json: bool) -> i32 {
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        return print_statusline_error(json, &format!("failed to read stdin: {error}"));
    }
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    match ingest_claude_statusline_payload(&ottto_core::default_support_dir(), &input, observed_at)
    {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "stored": result.stored,
                        "window_count": result.window_count,
                        "reason": result.reason,
                    })
                );
            }
            0
        }
        Err(error) => print_statusline_error(json, &error.to_string()),
    }
}

fn print_statusline_error(json: bool, message: &str) -> i32 {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "stored": false,
                "window_count": 0,
                "error": message,
            })
        );
        return CliErrorCode::Internal.exit_code();
    }
    0
}

fn run(invocation: Invocation) -> i32 {
    print_progress(&invocation.request, invocation.output_mode);
    match request_with_autostart(&invocation, &invocation.request) {
        Ok(response) => print_response(
            response,
            invocation.output_mode,
            Some(&invocation.request.command),
        ),
        Err(error) => print_error(
            error,
            invocation.output_mode,
            Some(invocation.request.request_id.as_str()),
        ),
    }
}

fn request_with_autostart(
    invocation: &Invocation,
    request: &LocalControlRequest,
) -> Result<LocalControlResponse, CliError> {
    match request_unix_socket(&invocation.socket, request) {
        Ok(response) => Ok(response),
        Err(error) if invocation.auto_start => match autostart_and_retry(invocation, request) {
            Ok(response) => Ok(response),
            Err(autostart_error) => Err(daemon_unavailable_error(
                error.to_string(),
                &invocation.socket,
                true,
                Some(autostart_error.to_string()),
            )),
        },
        Err(error) => Err(daemon_unavailable_error(
            error.to_string(),
            &invocation.socket,
            false,
            None,
        )),
    }
}

fn autostart_and_retry(
    invocation: &Invocation,
    request: &LocalControlRequest,
) -> anyhow::Result<LocalControlResponse> {
    kickstart_macos_launch_agent()?;
    let mut last_error: Option<anyhow::Error> = None;
    for _ in 0..60 {
        thread::sleep(Duration::from_millis(500));
        match request_unix_socket(&invocation.socket, request) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("daemon did not accept local requests")))
}

#[derive(Debug, Clone)]
struct BrowserClaimState {
    claim_code: String,
    claim_url: String,
    nonce: String,
    expires_at: Option<String>,
    browser_opened: bool,
    browser_open_error: Option<String>,
}

fn run_setup(invocation: Invocation, args: SetupArgs) -> i32 {
    let started_at = Instant::now();
    let timeout = Duration::from_secs(args.timeout);
    let mut browser_claim: Option<BrowserClaimState> = None;
    let mut browser_claim_completed = false;
    let mut last_setup_payload: Option<serde_json::Value> = None;

    loop {
        if setup_timed_out(started_at, timeout) {
            return print_setup_payload(
                invocation.request.request_id.clone(),
                setup_timeout_payload(browser_claim.as_ref(), last_setup_payload, args.timeout),
                invocation.output_mode,
            );
        }

        if let Some(claim) = browser_claim.as_ref().filter(|_| !browser_claim_completed) {
            match complete_browser_claim(&invocation, claim) {
                SetupAuthCompletion::Completed => {
                    browser_claim_completed = true;
                    if invocation.output_mode == OutputMode::Human {
                        println!("Browser approval received. Continuing setup.");
                    }
                    continue;
                }
                SetupAuthCompletion::Pending => {
                    sleep_for_setup_poll();
                    continue;
                }
                SetupAuthCompletion::Failed(error) => {
                    return print_error(
                        error,
                        invocation.output_mode,
                        Some(invocation.request.request_id.as_str()),
                    );
                }
            }
        }

        let setup_request = request_like(&invocation, setup_command(&args));
        print_progress(&setup_request, invocation.output_mode);
        match request_with_autostart(&invocation, &setup_request) {
            Ok(response) if response.ok => {
                let payload = response.payload.unwrap_or(serde_json::Value::Null);
                let exit_code = setup_payload_exit_code(&payload);
                last_setup_payload = Some(payload.clone());
                if args.no_wait || setup_exit_is_terminal(exit_code) {
                    return print_setup_payload(
                        response.request_id,
                        payload,
                        invocation.output_mode,
                    );
                }
                sleep_for_setup_poll();
            }
            Ok(response) => {
                let error = response
                    .error
                    .unwrap_or_else(|| internal_error("missing daemon error"));
                if error.code == CliErrorCode::NeedsUserAction
                    && args.claim_code.is_none()
                    && browser_claim.is_none()
                {
                    match start_browser_claim(&invocation, &args) {
                        Ok(claim) => {
                            emit_browser_claim_started(
                                &invocation,
                                &claim,
                                !args.no_wait,
                                args.timeout,
                            );
                            if args.no_wait {
                                return print_setup_payload(
                                    invocation.request.request_id.clone(),
                                    setup_waiting_for_browser_payload(&claim, false, args.timeout),
                                    invocation.output_mode,
                                );
                            }
                            browser_claim = Some(claim);
                        }
                        Err(error) => {
                            return print_error(
                                error,
                                invocation.output_mode,
                                Some(response.request_id.as_str()),
                            );
                        }
                    }
                } else {
                    return print_error(
                        error,
                        invocation.output_mode,
                        Some(response.request_id.as_str()),
                    );
                }
            }
            Err(error) => {
                return print_error(
                    error,
                    invocation.output_mode,
                    Some(setup_request.request_id.as_str()),
                );
            }
        }
    }
}

fn request_like(invocation: &Invocation, command: LocalControlCommand) -> LocalControlRequest {
    LocalControlRequest {
        request_id: request_id(),
        protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
        token: invocation.request.token.clone(),
        client_kind: invocation.request.client_kind.clone(),
        client_install_owner: invocation.request.client_install_owner,
        command,
    }
}

fn setup_command(args: &SetupArgs) -> LocalControlCommand {
    LocalControlCommand::Setup {
        sources: Vec::new(),
        claim_code: args.claim_code.clone(),
        setup_run_id: args.setup_run_id.clone(),
        api_base_url: args.api_base_url.clone(),
    }
}

fn setup_timed_out(started_at: Instant, timeout: Duration) -> bool {
    started_at.elapsed() >= timeout
}

fn sleep_for_setup_poll() {
    thread::sleep(SETUP_POLL_INTERVAL);
}

fn setup_exit_is_terminal(exit_code: i32) -> bool {
    matches!(exit_code, 0 | 61 | 70)
}

fn start_browser_claim(
    invocation: &Invocation,
    args: &SetupArgs,
) -> Result<BrowserClaimState, CliError> {
    let request = request_like(invocation, LocalControlCommand::AuthStart);
    print_progress(&request, invocation.output_mode);
    let response = request_with_autostart(invocation, &request)?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| internal_error("missing daemon error")));
    }
    let payload = response.payload.unwrap_or(serde_json::Value::Null);
    let mut claim = browser_claim_from_payload(&payload)?;
    if !args.no_browser {
        match open_browser(&claim.claim_url) {
            Ok(()) => claim.browser_opened = true,
            Err(error) => claim.browser_open_error = Some(error),
        }
    }
    Ok(claim)
}

enum SetupAuthCompletion {
    Completed,
    Pending,
    Failed(CliError),
}

fn complete_browser_claim(
    invocation: &Invocation,
    claim: &BrowserClaimState,
) -> SetupAuthCompletion {
    let request = request_like(
        invocation,
        LocalControlCommand::AuthComplete {
            claim_code: claim.claim_code.clone(),
            nonce: claim.nonce.clone(),
        },
    );
    print_progress(&request, invocation.output_mode);
    match request_with_autostart(invocation, &request) {
        Ok(response) if response.ok => SetupAuthCompletion::Completed,
        Ok(response) => {
            let error = response
                .error
                .unwrap_or_else(|| internal_error("missing daemon error"));
            if pending_browser_claim_error(&error) {
                SetupAuthCompletion::Pending
            } else if duplicate_browser_claim_completion_error(&error) {
                SetupAuthCompletion::Completed
            } else {
                SetupAuthCompletion::Failed(error)
            }
        }
        Err(error) => SetupAuthCompletion::Failed(error),
    }
}

fn pending_browser_claim_error(error: &CliError) -> bool {
    error.details.values().any(|value| match value {
        RedactedValue::String(detail) => {
            let detail = detail.to_ascii_lowercase();
            detail.contains("setup claim session is pending")
                || detail.contains("setup claim is pending")
        }
        _ => false,
    })
}

fn duplicate_browser_claim_completion_error(error: &CliError) -> bool {
    error
        .message
        .to_ascii_lowercase()
        .contains("no pending ottto sign-in claim")
}

fn browser_claim_from_payload(payload: &serde_json::Value) -> Result<BrowserClaimState, CliError> {
    let claim_code = payload
        .get("claim_code")
        .and_then(|value| value.as_str())
        .ok_or_else(|| internal_error("auth_start response missing claim_code"))?;
    let claim_url = payload
        .get("claim_url")
        .and_then(|value| value.as_str())
        .ok_or_else(|| internal_error("auth_start response missing claim_url"))?;
    let nonce = payload
        .get("nonce")
        .and_then(|value| value.as_str())
        .ok_or_else(|| internal_error("auth_start response missing nonce"))?;
    Ok(BrowserClaimState {
        claim_code: claim_code.to_string(),
        claim_url: claim_url.to_string(),
        nonce: nonce.to_string(),
        expires_at: payload
            .get("expires_at")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        browser_opened: false,
        browser_open_error: None,
    })
}

fn emit_browser_claim_started(
    invocation: &Invocation,
    claim: &BrowserClaimState,
    wait_enabled: bool,
    timeout_seconds: u64,
) {
    match invocation.output_mode {
        OutputMode::Human => {
            if claim.browser_opened {
                println!("Opened Ottto in your browser.");
            } else if let Some(error) = &claim.browser_open_error {
                println!(
                    "Could not open the browser automatically: {}",
                    sanitize_for_terminal(error)
                );
            } else {
                println!("Browser auto-open skipped.");
            }
            println!("Open: {}", sanitize_for_terminal(&claim.claim_url));
            println!("Code: {}", sanitize_for_terminal(&claim.claim_code));
            if wait_enabled {
                println!("Waiting for browser approval.");
            }
        }
        OutputMode::Json => {}
        OutputMode::Ndjson => println!(
            "{}",
            compact_json(&browser_claim_progress_event(
                &invocation.request.request_id,
                claim,
                wait_enabled,
                timeout_seconds,
            ))
        ),
    }
}

fn print_setup_payload(
    request_id: impl AsRef<str>,
    payload: serde_json::Value,
    output_mode: OutputMode,
) -> i32 {
    let exit_code = setup_payload_exit_code(&payload);
    match output_mode {
        OutputMode::Human => println!("{}", human_summary(&payload)),
        OutputMode::Json => println!("{}", pretty_json(&payload)),
        OutputMode::Ndjson => println!(
            "{}",
            compact_json(&final_payload_event(
                request_id.as_ref(),
                exit_code,
                payload
            ))
        ),
    }
    exit_code
}

fn setup_waiting_for_browser_payload(
    claim: &BrowserClaimState,
    wait_enabled: bool,
    timeout_seconds: u64,
) -> serde_json::Value {
    serde_json::json!({
        "status": "waiting_for_browser",
        "setup_run_id": null,
        "claim_code_provided": false,
        "claim_code": claim.claim_code,
        "claim_url": claim.claim_url,
        "expires_at": claim.expires_at,
        "browser_opened": claim.browser_opened,
        "browser_open_error": claim.browser_open_error,
        "wait": {
            "enabled": wait_enabled,
            "timeout_seconds": timeout_seconds,
        },
        "source_count": 0,
        "detected_sources": [],
        "next_question": null,
        "next_action": {
            "type": "browser_claim",
            "claim_code": claim.claim_code,
            "claim_url": claim.claim_url,
        },
        "actions": [],
    })
}

fn browser_claim_progress_event(
    request_id: &str,
    claim: &BrowserClaimState,
    wait_enabled: bool,
    timeout_seconds: u64,
) -> serde_json::Value {
    serde_json::json!({
        "event": "progress",
        "stage": "browser_claim_started",
        "request_id": request_id,
        "command": "setup",
        "protocol_version": LOCAL_CONTROL_PROTOCOL_VERSION,
        "claim_code": claim.claim_code,
        "claim_url": claim.claim_url,
        "expires_at": claim.expires_at,
        "browser_opened": claim.browser_opened,
        "browser_open_error": claim.browser_open_error,
        "wait": {
            "enabled": wait_enabled,
            "timeout_seconds": timeout_seconds,
        },
    })
}

fn setup_timeout_payload(
    claim: Option<&BrowserClaimState>,
    last_setup_payload: Option<serde_json::Value>,
    timeout_seconds: u64,
) -> serde_json::Value {
    let mut payload = last_setup_payload
        .or_else(|| {
            claim.map(|claim| setup_waiting_for_browser_payload(claim, true, timeout_seconds))
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "setup_run_id": null,
                "claim_code_provided": false,
                "source_count": 0,
                "detected_sources": [],
                "next_question": null,
                "next_action": null,
                "actions": [],
            })
        });

    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "status".to_string(),
            serde_json::Value::String("timed_out".to_string()),
        );
        object.insert(
            "timeout_seconds".to_string(),
            serde_json::Value::Number(timeout_seconds.into()),
        );
        if let Some(claim) = claim {
            object.insert(
                "claim_code".to_string(),
                serde_json::Value::String(claim.claim_code.clone()),
            );
            object.insert(
                "claim_url".to_string(),
                serde_json::Value::String(claim.claim_url.clone()),
            );
            object.insert(
                "browser_opened".to_string(),
                serde_json::Value::Bool(claim.browser_opened),
            );
            object.insert(
                "browser_open_error".to_string(),
                claim
                    .browser_open_error
                    .clone()
                    .map_or(serde_json::Value::Null, serde_json::Value::String),
            );
        }
    }
    payload
}

/// Returns true only for URLs we trust to hand to the OS browser opener.
///
/// Backend-controlled `claim_url` values are deserialized verbatim from a remote
/// HTTP response, so we accept only `https://<host>` or loopback
/// `http://localhost` / `http://127.0.0.1`. Everything else is rejected and
/// never passed to `open`: custom schemes (`customapp://`, `file://`, `data:`,
/// `javascript:`), an empty string, a value starting with `-` that `open` would
/// treat as a flag, and — critically — host look-alikes that a bare prefix
/// check would wave through (`http://localhost.evil.com`, `http://127.0.0.1.evil`,
/// `http://localhost-evil.com`, `http://localhost@evil.com`). The host is parsed
/// at the real authority boundary so the loopback allowance cannot be spoofed.
fn is_safe_external_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    // Authority = everything before the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // A `@` in the authority is userinfo, which can disguise the real host
    // (`http://localhost@evil.com` actually targets evil.com); reject outright.
    if authority.contains('@') {
        return false;
    }
    // Host is the authority minus an optional `:port`.
    let host = authority.split(':').next().unwrap_or(authority);
    match scheme {
        "https" => !host.is_empty(),
        "http" => host == "localhost" || host == "127.0.0.1",
        _ => false,
    }
}

fn open_browser(url: &str) -> Result<(), String> {
    if !is_safe_external_url(url) {
        return Err(format!(
            "refused to open untrusted claim URL ({}); open it manually if you trust it",
            sanitize_for_terminal(url)
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg(url)
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("open exited with status {status}"))
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("browser auto-open is only supported on macOS".to_string())
    }
}

fn run_uninstall(output_mode: OutputMode) -> i32 {
    let request_id = request_id();
    if output_mode == OutputMode::Ndjson {
        println!(
            "{}",
            compact_json(&progress_event(&request_id, "uninstall"))
        );
    }
    match local_lifecycle_home_dir() {
        Ok(home) => {
            let report = execute_local_uninstall(&home, UninstallExecutionOptions::CLI);
            let payload = serde_json::to_value(&report).expect("payload should serialize");

            let code = if report.failed_operations.is_empty() {
                0
            } else {
                CliErrorCode::Internal.exit_code()
            };

            match output_mode {
                OutputMode::Human if report.failed_operations.is_empty() => {
                    println!("Ottto local platform uninstalled");
                }
                OutputMode::Human => eprintln!("Ottto local platform uninstall incomplete"),
                OutputMode::Json => println!("{}", pretty_json(&payload)),
                OutputMode::Ndjson if report.failed_operations.is_empty() => {
                    println!(
                        "{}",
                        compact_json(&final_payload_event(&request_id, 0, payload))
                    );
                }
                OutputMode::Ndjson => {
                    println!(
                        "{}",
                        compact_json(&final_error_event(
                            &request_id,
                            code,
                            uninstall_incomplete_error(&report),
                        ))
                    );
                }
            }
            code
        }
        Err(error) => print_error(
            internal_error(&error.to_string()),
            output_mode,
            Some(request_id.as_str()),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
    Ndjson,
}

fn output_mode(json: bool, watch: bool) -> Result<OutputMode, CliError> {
    match (json, watch) {
        (true, true) => Ok(OutputMode::Ndjson),
        (true, false) => Ok(OutputMode::Json),
        (false, false) => Ok(OutputMode::Human),
        (false, true) => Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "--watch requires --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        }),
    }
}

fn print_progress(request: &LocalControlRequest, output_mode: OutputMode) {
    if output_mode == OutputMode::Ndjson {
        println!(
            "{}",
            compact_json(&progress_event(
                &request.request_id,
                local_command_name(&request.command),
            ))
        );
    }
}

fn print_response(
    response: LocalControlResponse,
    output_mode: OutputMode,
    command: Option<&LocalControlCommand>,
) -> i32 {
    if response.ok {
        let payload = response.payload.unwrap_or(serde_json::Value::Null);
        let exit_code = payload_exit_code(command, &payload);
        match output_mode {
            OutputMode::Human => println!("{}", human_summary(&payload)),
            OutputMode::Json => println!("{}", pretty_json(&payload)),
            OutputMode::Ndjson => {
                println!(
                    "{}",
                    compact_json(&final_payload_event(
                        &response.request_id,
                        exit_code,
                        payload,
                    ))
                );
            }
        }
        exit_code
    } else {
        print_error(
            response
                .error
                .unwrap_or_else(|| internal_error("missing daemon error")),
            output_mode,
            Some(response.request_id.as_str()),
        )
    }
}

fn print_error(error: CliError, output_mode: OutputMode, request_id: Option<&str>) -> i32 {
    let exit_code = error.code.exit_code();
    match output_mode {
        OutputMode::Human => eprintln!("{}", sanitize_for_terminal(&error.message)),
        OutputMode::Json => println!("{}", pretty_json(&CliErrorResponse { error })),
        OutputMode::Ndjson => println!(
            "{}",
            compact_json(&final_error_event(
                request_id.unwrap_or("req_cli_error"),
                exit_code,
                error,
            ))
        ),
    }
    exit_code
}

fn build_invocation(cli: Cli, output_mode: OutputMode) -> Invocation {
    let socket_overridden = cli.socket.is_some();
    let env_socket_present = std::env::var_os(OTTTO_SOCKET_ENV).is_some();
    let token = cli.token.unwrap_or_else(|| {
        client_control_token().unwrap_or_else(|_| "local-development-control-token".to_string())
    });
    let socket = cli.socket.unwrap_or_else(default_socket_path);
    Invocation {
        socket,
        request: LocalControlRequest {
            request_id: request_id(),
            protocol_version: LOCAL_CONTROL_PROTOCOL_VERSION,
            token: Some(token),
            client_kind: Some(ottto_protocol::LocalClientKind::Cli),
            client_install_owner: std::env::current_exe()
                .ok()
                .as_deref()
                .map(install_owner_for_path)
                .filter(|owner| *owner != ottto_protocol::InstallOwner::Unknown),
            command: local_command(cli.command),
        },
        output_mode,
        auto_start: should_auto_start(socket_overridden, cli.no_autostart, env_socket_present),
    }
}

fn should_auto_start(
    socket_overridden: bool,
    no_autostart: bool,
    env_socket_present: bool,
) -> bool {
    !socket_overridden && !no_autostart && !env_socket_present
}

fn local_command(command: Command) -> LocalControlCommand {
    match command {
        Command::Status(args) => LocalControlCommand::Status {
            refresh_agent_status: args.refresh_agent_status,
        },
        Command::Apps(args) => match args.command {
            None => LocalControlCommand::Status {
                refresh_agent_status: false,
            },
            Some(AppsCommand::Detect(_)) => LocalControlCommand::Status {
                refresh_agent_status: true,
            },
            Some(AppsCommand::Status(args)) => LocalControlCommand::AgentStatusRefresh {
                source: Some(args.app.into()),
            },
        },
        Command::AgentStatus(args) => LocalControlCommand::AgentStatusRefresh {
            source: Some(args.selected_source()),
        },
        Command::ClaudeCodeStatusline(_) => unreachable!("statusLine helper is handled directly"),
        Command::Setup(args) | Command::Login(args) => LocalControlCommand::Setup {
            sources: Vec::new(),
            claim_code: args.claim_code,
            setup_run_id: args.setup_run_id,
            api_base_url: args.api_base_url,
        },
        Command::Account(_) => LocalControlCommand::Account,
        Command::Logout(args) => LocalControlCommand::AuthReset {
            local_only: args.local_only,
        },
        Command::Doctor(_) => LocalControlCommand::Status {
            refresh_agent_status: false,
        },
        Command::Fix(args) => LocalControlCommand::Repair {
            source: args.selected_source(),
            dry_run: false,
        },
        Command::Verify(args) => LocalControlCommand::Verify {
            source: args.selected_source(),
            repair: args.repair,
        },
        Command::Diagnostics {
            command: DiagnosticsCommand::Collect(args),
        } => LocalControlCommand::DiagnosticsCollect {
            upload: args.upload,
            upload_approval: diagnostics_upload_approval(&args),
            api_base_url: args.api_base_url,
        },
        Command::Update(_) => LocalControlCommand::UpdateCheck,
        Command::Uninstall(_) => LocalControlCommand::UninstallExecute { confirm: true },
    }
}

fn diagnostics_upload_approval(args: &DiagnosticsCollectArgs) -> Option<DiagnosticsUploadApproval> {
    if !(args.upload
        || args.approve_upload
        || args.accept_retention_disclosure
        || args.support_claim.is_some())
    {
        return None;
    }
    Some(DiagnosticsUploadApproval {
        approved: args.approve_upload,
        retention_disclosure_accepted: args.accept_retention_disclosure,
        support_claim: args.support_claim.clone(),
    })
}

fn command_json(command: &Command) -> bool {
    match command {
        Command::Status(args) => args.json,
        Command::Apps(args) => match &args.command {
            None => args.json,
            Some(AppsCommand::Detect(args)) => args.json,
            Some(AppsCommand::Status(args)) => args.json,
        },
        Command::Doctor(args) | Command::Uninstall(args) | Command::Account(args) => args.json,
        Command::Setup(args) | Command::Login(args) => args.json,
        Command::Logout(args) => args.json,
        Command::AgentStatus(args) | Command::Fix(args) => args.json,
        Command::Verify(args) => args.json,
        Command::Diagnostics {
            command: DiagnosticsCommand::Collect(args),
        } => args.json,
        Command::Update(args) => match &args.command {
            None => args.json,
            Some(UpdateCommand::Check(args)) => args.json,
        },
        Command::ClaudeCodeStatusline(args) => args.json,
    }
}

fn request_id() -> String {
    format!("req_{}", std::process::id())
}

fn pretty_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("json should serialize")
}

fn compact_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("json should serialize")
}

/// Neutralizes terminal control sequences in daemon/backend-derived strings
/// before they are printed in human output mode.
///
/// Strips C0 control characters (0x00-0x1F) except `\t` and `\n`, the DEL char
/// (0x7F), and C1 control characters (0x80-0x9F). This defeats ANSI/CSI/OSC
/// escape injection (e.g. clearing the screen, setting the window title, or
/// spoofing a success line) while preserving normal printable text, tabs, and
/// newlines so legitimate multi-line messages still render. JSON/NDJSON paths
/// are already safe via serde escaping and must not be routed through this.
fn sanitize_for_terminal(s: &str) -> String {
    // `char::is_control` is true for the C0 range (0x00-0x1F), DEL (0x7F), and
    // the C1 range (0x80-0x9F) — exactly the bytes we want to drop, including
    // ESC (0x1B). Tab and newline are control chars too, so allow them back in.
    s.chars()
        .filter(|&c| c == '\t' || c == '\n' || !c.is_control())
        .collect()
}

fn progress_event(request_id: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "event": "progress",
        "stage": "request_started",
        "request_id": request_id,
        "command": command,
        "protocol_version": LOCAL_CONTROL_PROTOCOL_VERSION,
    })
}

fn final_payload_event(
    request_id: &str,
    exit_code: i32,
    payload: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "event": "final",
        "request_id": request_id,
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "payload": payload,
    })
}

fn final_error_event(request_id: &str, exit_code: i32, error: CliError) -> serde_json::Value {
    serde_json::json!({
        "event": "final",
        "request_id": request_id,
        "ok": false,
        "exit_code": exit_code,
        "error": error,
    })
}

fn local_command_name(command: &LocalControlCommand) -> &'static str {
    match command {
        LocalControlCommand::Status { .. } => "status",
        LocalControlCommand::AuthStatus => "auth_status",
        LocalControlCommand::AgentStatusRefresh { .. } => "agent_status_refresh",
        LocalControlCommand::AuthStart => "auth_start",
        LocalControlCommand::AuthComplete { .. } => "auth_complete",
        LocalControlCommand::AuthReset { .. } => "auth_reset",
        LocalControlCommand::Account => "account",
        LocalControlCommand::Detect { .. } => "detect",
        LocalControlCommand::Setup { .. } => "setup",
        LocalControlCommand::SetupAnswer { .. } => "setup_answer",
        LocalControlCommand::SetupAction { .. } => "setup_action",
        LocalControlCommand::TelemetryControl { .. } => "telemetry_control",
        LocalControlCommand::Repair { .. } => "repair",
        LocalControlCommand::Verify { .. } => "verify",
        LocalControlCommand::RelayStart => "relay_start",
        LocalControlCommand::RelayStop => "relay_stop",
        LocalControlCommand::DiagnosticsCollect { .. } => "diagnostics_collect",
        LocalControlCommand::UpdateCheck => "update_check",
        LocalControlCommand::UninstallPlan => "uninstall_plan",
        LocalControlCommand::UninstallExecute { .. } => "uninstall_execute",
        LocalControlCommand::Uninstall => "uninstall",
    }
}

fn payload_exit_code(command: Option<&LocalControlCommand>, payload: &serde_json::Value) -> i32 {
    match command {
        Some(
            LocalControlCommand::Setup { .. }
            | LocalControlCommand::SetupAnswer { .. }
            | LocalControlCommand::SetupAction { .. },
        ) => setup_payload_exit_code(payload),
        _ => 0,
    }
}

fn setup_payload_exit_code(payload: &serde_json::Value) -> i32 {
    let status = payload
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("succeeded");
    match status {
        "succeeded" | "success" | "completed" | "complete" => 0,
        "timed_out" | "timeout" => CliErrorCode::TimedOut.exit_code(),
        "failed" | "canceled" | "cancelled" => CliErrorCode::Internal.exit_code(),
        _ if payload
            .get("next_question")
            .is_some_and(|value| !value.is_null())
            || payload
                .get("next_action")
                .is_some_and(|value| !value.is_null()) =>
        {
            CliErrorCode::NeedsUserAction.exit_code()
        }
        "pending"
        | "running"
        | "waiting"
        | "waiting_for_approval"
        | "waiting_for_browser"
        | "waiting_for_companion"
        | "waiting_for_user"
        | "needs_action"
        | "action_required" => CliErrorCode::NeedsUserAction.exit_code(),
        _ => 0,
    }
}

/// Builds the human-mode summary line. Every daemon/backend-derived field
/// (message text, daemon, source, account state, status/state) is routed
/// through `sanitize_for_terminal` so a malicious backend cannot inject
/// terminal escape sequences into the TTY.
fn human_summary(payload: &serde_json::Value) -> String {
    if let Some(message) = payload
        .get("message")
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
    {
        return sanitize_for_terminal(message);
    }
    if let Some(daemon) = payload.get("daemon").and_then(|value| value.as_str()) {
        return format!("Ottto local daemon: {}", sanitize_for_terminal(daemon));
    }
    if let Some(source) = payload.get("source").and_then(|value| value.as_str()) {
        return format!(
            "Ottto {}: {}",
            sanitize_for_terminal(source),
            payload_summary(payload)
        );
    }
    if let Some(account) = payload.get("account").and_then(|value| value.as_object()) {
        if let Some(state) = account.get("state").and_then(|value| value.as_str()) {
            return format!("Ottto account: {}", sanitize_for_terminal(state));
        }
    }
    payload_summary(payload)
}

fn payload_summary(payload: &serde_json::Value) -> String {
    sanitize_for_terminal(
        payload
            .get("status")
            .or_else(|| payload.get("state"))
            .and_then(|value| value.as_str())
            .unwrap_or("ok"),
    )
}

fn daemon_unavailable_error(
    message: String,
    socket: &Path,
    autostart_attempted: bool,
    autostart_error: Option<String>,
) -> CliError {
    let mut details = BTreeMap::from([
        (
            "socket".to_string(),
            RedactedValue::String(socket.display().to_string()),
        ),
        (
            "autostart_attempted".to_string(),
            RedactedValue::Bool(autostart_attempted),
        ),
    ]);
    if let Some(error) = autostart_error {
        details.insert("autostart_error".to_string(), RedactedValue::String(error));
    }

    CliError {
        code: CliErrorCode::DaemonUnavailable,
        message: format!(
            "{OTTTO_SERVICE_BINARY_NAME} is unavailable at {}: {message}",
            socket.display()
        ),
        retryable: true,
        details,
    }
}

fn internal_error(message: &str) -> CliError {
    CliError {
        code: CliErrorCode::Internal,
        message: message.to_string(),
        retryable: true,
        details: BTreeMap::new(),
    }
}

fn uninstall_incomplete_error(report: &ottto_protocol::UninstallExecutionResult) -> CliError {
    CliError {
        code: CliErrorCode::Internal,
        message: "Ottto local platform uninstall incomplete".to_string(),
        retryable: true,
        details: BTreeMap::from([
            (
                "status".to_string(),
                RedactedValue::String(report.status.clone()),
            ),
            (
                "failed_operations".to_string(),
                RedactedValue::List(
                    report
                        .failed_operations
                        .iter()
                        .cloned()
                        .map(RedactedValue::String)
                        .collect(),
                ),
            ),
        ]),
    }
}

impl From<SourceArg> for SourceKind {
    fn from(value: SourceArg) -> Self {
        match value {
            SourceArg::Codex => SourceKind::Codex,
            SourceArg::ClaudeCode => SourceKind::ClaudeCode,
            SourceArg::Pi => SourceKind::Pi,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn invocation_from_cli(cli: Cli) -> Invocation {
        let mode = output_mode(command_json(&cli.command), cli.watch).expect("valid output mode");
        build_invocation(cli, mode)
    }

    fn status_response() -> LocalControlResponse {
        serde_json::from_str(include_str!(
            "../../../fixtures/control/status-response.json"
        ))
        .expect("status response fixture parses")
    }

    fn parse_json_output(output: &str) -> serde_json::Value {
        serde_json::from_str(output).expect("output should be one JSON object")
    }

    fn parse_ndjson_output(output: &str) -> Vec<serde_json::Value> {
        output
            .lines()
            .map(|line| serde_json::from_str(line).expect("each NDJSON line parses"))
            .collect()
    }

    fn render_help(args: &[&str]) -> String {
        let mut command = Cli::command();
        let error = command
            .try_get_matches_from_mut(args)
            .expect_err("help should exit before parsing");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        error.to_string()
    }

    fn fake_browser_claim() -> BrowserClaimState {
        BrowserClaimState {
            claim_code: "claim_01HXBROWSER".to_string(),
            claim_url: "https://ottto.net/setup/claim?code=claim_01HXBROWSER&nonce=nonce_123"
                .to_string(),
            nonce: "nonce_123".to_string(),
            expires_at: Some("2026-05-21T12:00:00Z".to_string()),
            browser_opened: false,
            browser_open_error: None,
        }
    }

    fn cli_help_snapshot() -> String {
        let commands: [(&str, &[&str]); 18] = [
            ("ottto --help", &["ottto", "--help"]),
            ("ottto status --help", &["ottto", "status", "--help"]),
            ("ottto apps --help", &["ottto", "apps", "--help"]),
            (
                "ottto apps detect --help",
                &["ottto", "apps", "detect", "--help"],
            ),
            (
                "ottto apps status --help",
                &["ottto", "apps", "status", "--help"],
            ),
            (
                "ottto agent-status --help",
                &["ottto", "agent-status", "--help"],
            ),
            ("ottto setup --help", &["ottto", "setup", "--help"]),
            ("ottto login --help", &["ottto", "login", "--help"]),
            ("ottto account --help", &["ottto", "account", "--help"]),
            ("ottto logout --help", &["ottto", "logout", "--help"]),
            ("ottto doctor --help", &["ottto", "doctor", "--help"]),
            ("ottto fix --help", &["ottto", "fix", "--help"]),
            ("ottto verify --help", &["ottto", "verify", "--help"]),
            (
                "ottto diagnostics --help",
                &["ottto", "diagnostics", "--help"],
            ),
            (
                "ottto diagnostics collect --help",
                &["ottto", "diagnostics", "collect", "--help"],
            ),
            ("ottto update --help", &["ottto", "update", "--help"]),
            (
                "ottto update check --help",
                &["ottto", "update", "check", "--help"],
            ),
            ("ottto uninstall --help", &["ottto", "uninstall", "--help"]),
        ];

        commands
            .iter()
            .map(|(label, args)| format!("### {label}\n{}", render_help(args).trim_end()))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    #[test]
    fn cli_help_matches_frozen_contract() {
        assert_eq!(
            cli_help_snapshot(),
            include_str!("../../../fixtures/cli/help-contract.txt")
        );
    }

    #[test]
    fn watch_requires_json_mode() {
        let cli = Cli::parse_from(["ottto", "status", "--watch"]);
        let error = output_mode(command_json(&cli.command), cli.watch).expect_err("watch invalid");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert_eq!(error.message, "--watch requires --json");
    }

    #[test]
    fn status_json_output_is_single_parseable_object() {
        let output = pretty_json(&status_response().payload.expect("payload"));
        let actual = parse_json_output(&output);
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/status-json-output.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
        assert!(!output.contains("Ottto local daemon"));
    }

    #[test]
    fn status_watch_output_is_parseable_ndjson() {
        let response = status_response();
        let progress = progress_event(&response.request_id, "status");
        let final_event =
            final_payload_event(&response.request_id, 0, response.payload.expect("payload"));
        let output = format!(
            "{}\n{}\n",
            compact_json(&progress),
            compact_json(&final_event)
        );
        let actual = parse_ndjson_output(&output);
        let expected = parse_ndjson_output(include_str!(
            "../../../fixtures/cli/status-watch-output.ndjson"
        ));
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 2);
        assert_eq!(
            actual[0].get("event").and_then(|value| value.as_str()),
            Some("progress")
        );
        assert_eq!(
            actual[1].get("event").and_then(|value| value.as_str()),
            Some("final")
        );
    }

    #[test]
    fn daemon_unavailable_watch_output_is_parseable_ndjson_error() {
        let error = daemon_unavailable_error(
            "connection refused".to_string(),
            &PathBuf::from("/tmp/ottto.sock"),
            false,
            None,
        );
        let request_id = "req_cli_error_fixture";
        let output = format!(
            "{}\n{}\n",
            compact_json(&progress_event(request_id, "status")),
            compact_json(&final_error_event(
                request_id,
                error.code.exit_code(),
                error,
            ))
        );
        let actual = parse_ndjson_output(&output);
        let expected = parse_ndjson_output(include_str!(
            "../../../fixtures/cli/daemon-unavailable-watch-output.ndjson"
        ));
        assert_eq!(actual, expected);
        assert_eq!(
            actual[1].get("ok").and_then(|value| value.as_bool()),
            Some(false)
        );
        assert_eq!(
            actual[1].get("exit_code").and_then(|value| value.as_i64()),
            Some(10)
        );
    }

    #[test]
    fn setup_needs_user_action_output_uses_stable_exit_code() {
        let payload = parse_json_output(include_str!(
            "../../../fixtures/cli/setup-needs-user-action-output.json"
        ));
        assert_eq!(
            payload_exit_code(
                Some(&LocalControlCommand::Setup {
                    sources: Vec::new(),
                    claim_code: None,
                    setup_run_id: None,
                    api_base_url: None,
                }),
                &payload,
            ),
            CliErrorCode::NeedsUserAction.exit_code()
        );
        assert_eq!(
            setup_payload_exit_code(&payload),
            CliErrorCode::NeedsUserAction.exit_code()
        );
    }

    #[test]
    fn setup_timed_out_output_uses_stable_exit_code() {
        let payload = parse_json_output(include_str!(
            "../../../fixtures/cli/setup-timed-out-output.json"
        ));
        assert_eq!(
            payload_exit_code(
                Some(&LocalControlCommand::Setup {
                    sources: Vec::new(),
                    claim_code: None,
                    setup_run_id: None,
                    api_base_url: None,
                }),
                &payload,
            ),
            CliErrorCode::TimedOut.exit_code()
        );
        assert_eq!(
            setup_payload_exit_code(&payload),
            CliErrorCode::TimedOut.exit_code()
        );
    }

    #[test]
    fn setup_browser_claim_output_uses_stable_needs_action_exit_code() {
        let payload = setup_waiting_for_browser_payload(&fake_browser_claim(), false, 300);
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/setup-browser-claim-output.json"
        ))
        .expect("fixture parses");
        assert_eq!(payload, expected);
        assert_eq!(
            setup_payload_exit_code(&payload),
            CliErrorCode::NeedsUserAction.exit_code()
        );
    }

    #[test]
    fn setup_browser_claim_progress_event_is_parseable_ndjson() {
        let event = browser_claim_progress_event("req_setup", &fake_browser_claim(), true, 300);
        let output = format!("{}\n", compact_json(&event));
        let actual = parse_ndjson_output(&output);
        assert_eq!(actual.len(), 1);
        assert_eq!(
            actual[0].get("stage").and_then(|value| value.as_str()),
            Some("browser_claim_started")
        );
        assert_eq!(
            actual[0].get("claim_code").and_then(|value| value.as_str()),
            Some("claim_01HXBROWSER")
        );
    }

    #[test]
    fn setup_timeout_payload_preserves_last_setup_payload() {
        let last_payload = parse_json_output(include_str!(
            "../../../fixtures/cli/setup-needs-user-action-output.json"
        ));
        let payload = setup_timeout_payload(Some(&fake_browser_claim()), Some(last_payload), 30);
        assert_eq!(
            payload.get("status").and_then(|value| value.as_str()),
            Some("timed_out")
        );
        assert_eq!(
            payload.get("setup_run_id").and_then(|value| value.as_str()),
            Some("setup_01HXWAIT")
        );
        assert_eq!(
            setup_payload_exit_code(&payload),
            CliErrorCode::TimedOut.exit_code()
        );
    }

    #[test]
    fn setup_browser_claim_pending_and_duplicate_errors_are_resumable() {
        let pending = CliError {
            code: CliErrorCode::BackendRejected,
            message: "Ottto rejected the local setup request.".to_string(),
            retryable: false,
            details: BTreeMap::from([(
                "body_excerpt".to_string(),
                RedactedValue::String(r#"{"detail":"Setup claim session is pending"}"#.to_string()),
            )]),
        };
        assert!(pending_browser_claim_error(&pending));

        let duplicate = CliError {
            code: CliErrorCode::InvalidRequest,
            message: "no pending Ottto sign-in claim".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        };
        assert!(duplicate_browser_claim_completion_error(&duplicate));
    }

    #[test]
    fn fix_builds_repair_request() {
        let invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Fix(SourceArgs {
                    source: Some(SourceArg::Codex),
                    app: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );

        assert_eq!(invocation.socket, PathBuf::from("/tmp/ottto.sock"));
        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.token.as_deref(), Some("token"));
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Repair {
                source: SourceKind::Codex,
                dry_run: false
            }
        );
        assert!(!invocation.auto_start);
    }

    #[test]
    fn daemon_unavailable_uses_stable_exit_code() {
        let error = daemon_unavailable_error(
            "connection refused".to_string(),
            &PathBuf::from("/x"),
            true,
            Some("launchctl failed".to_string()),
        );
        assert_eq!(error.code.exit_code(), 10);
        assert!(error.retryable);
        assert_eq!(
            error.details.get("autostart_attempted"),
            Some(&RedactedValue::Bool(true))
        );
    }

    #[test]
    fn setup_accepts_claim_code() {
        let invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Setup(SetupArgs {
                    claim_code: Some("claim_123".to_string()),
                    no_browser: false,
                    no_wait: false,
                    timeout: DEFAULT_SETUP_TIMEOUT_SECONDS,
                    setup_run_id: None,
                    api_base_url: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );

        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Setup {
                sources: Vec::new(),
                claim_code: Some("claim_123".to_string()),
                setup_run_id: None,
                api_base_url: None
            }
        );
    }

    #[test]
    fn setup_claim_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Setup(SetupArgs {
                    claim_code: Some("claim_123".to_string()),
                    no_browser: false,
                    no_wait: false,
                    timeout: DEFAULT_SETUP_TIMEOUT_SECONDS,
                    setup_run_id: None,
                    api_base_url: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_setup_claim_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/setup-claim-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn setup_accepts_headless_browser_claim_flags() {
        let cli = Cli::parse_from([
            "ottto",
            "setup",
            "--no-browser",
            "--no-wait",
            "--timeout",
            "30",
            "--json",
        ]);
        let Command::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert!(args.no_browser);
        assert!(args.no_wait);
        assert_eq!(args.timeout, 30);
        assert!(args.claim_code.is_none());
    }

    #[test]
    fn login_reuses_browser_claim_setup_flags() {
        let cli = Cli::parse_from([
            "ottto",
            "login",
            "--no-browser",
            "--no-wait",
            "--timeout",
            "45",
            "--json",
        ]);
        let Command::Login(args) = cli.command else {
            panic!("expected login command");
        };
        assert!(args.no_browser);
        assert!(args.no_wait);
        assert_eq!(args.timeout, 45);
        assert!(args.json);
    }

    #[test]
    fn account_builds_account_request() {
        let cli = Cli::parse_from(["ottto", "account", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.command, LocalControlCommand::Account);
    }

    #[test]
    fn logout_is_cloud_first_by_default() {
        let cli = Cli::parse_from(["ottto", "logout", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AuthReset { local_only: false }
        );
    }

    #[test]
    fn logout_local_only_is_explicit() {
        let cli = Cli::parse_from(["ottto", "logout", "--local-only", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AuthReset { local_only: true }
        );
    }

    #[test]
    fn diagnostics_collect_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Diagnostics {
                    command: DiagnosticsCommand::Collect(DiagnosticsCollectArgs {
                        json: true,
                        upload: false,
                        approve_upload: false,
                        accept_retention_disclosure: false,
                        support_claim: None,
                        api_base_url: None,
                    }),
                },
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_diagnostics_collect_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/diagnostics-collect-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn diagnostics_upload_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Diagnostics {
                    command: DiagnosticsCommand::Collect(DiagnosticsCollectArgs {
                        json: true,
                        upload: true,
                        approve_upload: true,
                        accept_retention_disclosure: true,
                        support_claim: Some("support_123".to_string()),
                        api_base_url: Some("http://127.0.0.1:43199".to_string()),
                    }),
                },
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_diagnostics_upload_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/diagnostics-upload-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn agent_status_builds_refresh_request() {
        let invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::AgentStatus(SourceArgs {
                    source: Some(SourceArg::Codex),
                    app: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentStatusRefresh {
                source: Some(SourceKind::Codex)
            }
        );
    }

    #[test]
    fn verify_accepts_public_app_argument() {
        let cli = Cli::parse_from([
            "ottto",
            "--socket",
            "/tmp/ottto.sock",
            "verify",
            "--app",
            "codex",
            "--json",
        ]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: false
            }
        );
    }

    #[test]
    fn verify_accepts_repair_flag() {
        let cli = Cli::parse_from(["ottto", "verify", "--repair", "--app", "codex", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: true
            }
        );
    }

    #[test]
    fn fix_accepts_public_app_argument() {
        let cli = Cli::parse_from(["ottto", "fix", "--app", "claude-code", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Repair {
                source: SourceKind::ClaudeCode,
                dry_run: false
            }
        );
    }

    #[test]
    fn apps_root_builds_status_request() {
        let cli = Cli::parse_from(["ottto", "--socket", "/tmp/ottto.sock", "apps", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Status {
                refresh_agent_status: false
            }
        );
    }

    #[test]
    fn apps_detect_refreshes_all_agent_statuses() {
        let cli = Cli::parse_from(["ottto", "apps", "detect", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Status {
                refresh_agent_status: true
            }
        );
    }

    #[test]
    fn apps_status_uses_public_app_selector() {
        let cli = Cli::parse_from(["ottto", "apps", "status", "--app", "pi", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentStatusRefresh {
                source: Some(SourceKind::Pi)
            }
        );
    }

    #[test]
    fn update_check_builds_update_request() {
        let cli = Cli::parse_from(["ottto", "update", "check", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.command, LocalControlCommand::UpdateCheck);
    }

    #[test]
    fn update_without_subcommand_checks_update() {
        let cli = Cli::parse_from(["ottto", "update", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.command, LocalControlCommand::UpdateCheck);
    }

    #[test]
    fn watch_mode_builds_ndjson_invocation() {
        let cli = Cli::parse_from(["ottto", "status", "--json", "--watch"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Ndjson);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Status {
                refresh_agent_status: false
            }
        );
    }

    #[test]
    fn autostart_is_disabled_for_overrides() {
        assert!(should_auto_start(false, false, false));
        assert!(!should_auto_start(true, false, false));
        assert!(!should_auto_start(false, true, false));
        assert!(!should_auto_start(false, false, true));
    }

    #[test]
    fn daemon_unavailable_error_matches_baseline_fixture() {
        let error = daemon_unavailable_error(
            "connection refused".to_string(),
            &PathBuf::from("/tmp/ottto.sock"),
            false,
            None,
        );
        let actual =
            serde_json::to_value(&CliErrorResponse { error }).expect("error response serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/daemon-unavailable-error.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn uninstall_builds_confirmed_execute_request_for_daemon_clients() {
        let invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Uninstall(JsonArgs { json: true }),
            },
            OutputMode::Json,
        );

        assert_eq!(
            invocation.request.command,
            LocalControlCommand::UninstallExecute { confirm: true }
        );
    }

    #[test]
    fn is_safe_external_url_accepts_trusted_targets() {
        assert!(is_safe_external_url("https://ottto.net/x"));
        assert!(is_safe_external_url("http://localhost:8765/x"));
        assert!(is_safe_external_url("http://127.0.0.1:5/x"));
    }

    #[test]
    fn is_safe_external_url_rejects_untrusted_targets() {
        assert!(!is_safe_external_url("customscheme://x"));
        assert!(!is_safe_external_url("file:///etc/passwd"));
        assert!(!is_safe_external_url("-e"));
        assert!(!is_safe_external_url("javascript:alert(1)"));
        assert!(!is_safe_external_url(""));
        assert!(!is_safe_external_url("ftp://x"));
        assert!(!is_safe_external_url("http://evil.com"));
    }

    #[test]
    fn is_safe_external_url_rejects_loopback_host_lookalikes() {
        // A bare `starts_with("http://localhost")` check would wave these
        // plain-HTTP attacker hosts through; the authority-boundary parse must
        // reject every one of them.
        assert!(!is_safe_external_url("http://localhost.evil.com/x"));
        assert!(!is_safe_external_url("http://127.0.0.1.evil.com/x"));
        assert!(!is_safe_external_url("http://localhost-evil.com/x"));
        assert!(!is_safe_external_url("http://localhost@evil.com/x"));
        assert!(!is_safe_external_url("http://127.0.0.1@evil.com"));
        assert!(!is_safe_external_url("http://localhost:8765@evil.com/x"));
        // Genuine loopback forms still pass.
        assert!(is_safe_external_url("http://localhost"));
        assert!(is_safe_external_url("http://127.0.0.1/claim"));
    }

    #[test]
    fn open_browser_refuses_untrusted_claim_url() {
        let error = open_browser("customscheme://x").expect_err("untrusted url is rejected");
        assert!(error.contains("untrusted"));
        // The raw (sanitized) URL is surfaced so the user can decide manually.
        assert!(error.contains("customscheme://x"));
    }

    #[test]
    fn sanitize_for_terminal_strips_control_sequences() {
        assert_eq!(sanitize_for_terminal("\x1b[2J"), "[2J");
        assert_eq!(sanitize_for_terminal("\x1b]0;title\x07"), "]0;title");
        assert_eq!(sanitize_for_terminal("\x1b"), "");
        assert_eq!(sanitize_for_terminal("\x07"), "");
        assert_eq!(sanitize_for_terminal("\x7f"), "");
        // C1 control byte (next-line) is also stripped.
        assert_eq!(sanitize_for_terminal("a\u{85}b"), "ab");
    }

    #[test]
    fn sanitize_for_terminal_preserves_printable_text() {
        assert_eq!(
            sanitize_for_terminal("hello\tworld\nok"),
            "hello\tworld\nok"
        );
        assert_eq!(sanitize_for_terminal("café — naïve ✓"), "café — naïve ✓");
    }

    #[test]
    fn sanitize_for_terminal_neutralizes_crafted_claim_code() {
        let claim = BrowserClaimState {
            claim_code: "claim_REAL\x1b[2K\rclaim_FAKE".to_string(),
            ..fake_browser_claim()
        };
        let sanitized = sanitize_for_terminal(&claim.claim_code);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\r'));
        assert_eq!(sanitized, "claim_REAL[2Kclaim_FAKE");
    }
}
