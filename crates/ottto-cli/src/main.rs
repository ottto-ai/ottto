use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use ottto_core::{
    client_control_token, default_socket_path, execute_local_uninstall,
    ingest_claude_statusline_payload, install_owner_for_path, kickstart_macos_launch_agent,
    load_or_create_control_token, local_lifecycle_home_dir, request_unix_socket_with_timeout,
    UninstallExecutionOptions, LOCAL_CONTROL_REFRESH_TIMEOUT, LOCAL_CONTROL_SOCKET_TIMEOUT,
    OTTTO_SERVICE_BINARY_NAME, OTTTO_SOCKET_ENV,
};
use ottto_protocol::{
    AgentContextQuery, AgentCostsQuery, AgentProviderImpactQuery, AgentRecommendationsQuery,
    AgentSessionsQuery, CliError, CliErrorCode, CliErrorResponse, DiagnosticsUploadApproval,
    LocalControlCommand, LocalControlRequest, LocalControlResponse, RedactedValue, SourceKind,
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
    #[command(about = "Print cloud context for AI agents")]
    Context(ContextArgs),
    #[command(about = "Print cloud cost breakdown for AI agents")]
    Costs(CostsArgs),
    #[command(about = "Print cloud sessions for AI agents")]
    Sessions(SessionsArgs),
    #[command(about = "Print Advisor recommendations for AI agents")]
    Recommendations(RecommendationsArgs),
    #[command(about = "Print staff-only provider-impact events for AI agents")]
    ProviderImpact(ProviderImpactArgs),
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

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("source_selector")
            .args(["source", "app"])
            .multiple(false)
    )
)]
struct ContextArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(long, value_name = "DAYS", help = "Number of days to include")]
    days: Option<u16>,
    #[arg(long, value_name = "RANGE", help = "Calendar range preset")]
    range: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window start date"
    )]
    start_date: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window end date"
    )]
    end_date: Option<String>,
    #[arg(long, value_name = "TZ", help = "IANA timezone for calendar windows")]
    timezone: Option<String>,
    #[arg(long, value_name = "SOURCE", help = "Source slug to filter context to")]
    source: Option<String>,
    #[arg(long, value_enum, help = "App/source alias to filter context to")]
    app: Option<SourceArg>,
    #[arg(
        long,
        value_name = "MACHINE_ID",
        help = "Override the local machine filter"
    )]
    machine_id: Option<String>,
    #[arg(
        long,
        value_name = "PROFILE_ID",
        help = "Filter by source plan profile id"
    )]
    source_plan_profile_id: Option<String>,
    #[arg(long, value_name = "TOKENS", help = "Approximate output token budget")]
    max_tokens: Option<u32>,
    #[arg(long, help = "Request account-wide context instead of this Mac")]
    all_machines: bool,
}

impl ContextArgs {
    fn query(&self) -> AgentContextQuery {
        AgentContextQuery {
            days: self.days,
            range: non_empty_option(self.range.as_deref()),
            start_date: non_empty_option(self.start_date.as_deref()),
            end_date: non_empty_option(self.end_date.as_deref()),
            timezone: non_empty_option(self.timezone.as_deref()),
            source: non_empty_option(self.source.as_deref())
                .or_else(|| self.app.map(|source| source.slug().to_string())),
            machine_id: non_empty_option(self.machine_id.as_deref()),
            source_plan_profile_id: non_empty_option(self.source_plan_profile_id.as_deref()),
            max_tokens: self.max_tokens,
            all_machines: self.all_machines,
        }
    }
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("source_selector")
            .args(["source", "app"])
            .multiple(false)
    )
)]
struct CostsArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(long, value_name = "DAYS", help = "Number of days to include")]
    days: Option<u16>,
    #[arg(long, value_name = "RANGE", help = "Calendar range preset")]
    range: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window start date"
    )]
    start_date: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window end date"
    )]
    end_date: Option<String>,
    #[arg(long, value_name = "TZ", help = "IANA timezone for calendar windows")]
    timezone: Option<String>,
    #[arg(long, value_name = "SOURCE", help = "Source slug to filter costs to")]
    source: Option<String>,
    #[arg(long, value_enum, help = "App/source alias to filter costs to")]
    app: Option<SourceArg>,
    #[arg(
        long,
        value_name = "MACHINE_ID",
        help = "Override the local machine filter"
    )]
    machine_id: Option<String>,
    #[arg(
        long,
        value_name = "PROFILE_ID",
        help = "Filter by source plan profile id"
    )]
    source_plan_profile_id: Option<String>,
    #[arg(long, value_name = "BUCKET", help = "Cost bucket such as day or hour")]
    bucket: Option<String>,
    #[arg(
        long,
        value_name = "MODE",
        help = "Breakdown mode such as full or overview"
    )]
    mode: Option<String>,
    #[arg(long, help = "Request account-wide costs instead of this Mac")]
    all_machines: bool,
}

impl CostsArgs {
    fn query(&self) -> AgentCostsQuery {
        AgentCostsQuery {
            days: self.days,
            range: non_empty_option(self.range.as_deref()),
            start_date: non_empty_option(self.start_date.as_deref()),
            end_date: non_empty_option(self.end_date.as_deref()),
            timezone: non_empty_option(self.timezone.as_deref()),
            source: selected_source_slug(self.source.as_deref(), self.app),
            machine_id: non_empty_option(self.machine_id.as_deref()),
            source_plan_profile_id: non_empty_option(self.source_plan_profile_id.as_deref()),
            bucket: non_empty_option(self.bucket.as_deref()),
            mode: non_empty_option(self.mode.as_deref()),
            all_machines: self.all_machines,
        }
    }
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("source_selector")
            .args(["source", "app"])
            .multiple(false)
    )
)]
struct SessionsArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(
        long,
        value_name = "LIMIT",
        help = "Maximum number of sessions to return"
    )]
    limit: Option<u16>,
    #[arg(
        long,
        value_name = "CURSOR",
        help = "Pagination cursor from a prior response"
    )]
    cursor: Option<String>,
    #[arg(long, value_name = "RANGE", help = "Calendar range preset")]
    range: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window start date"
    )]
    start_date: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "Inclusive custom window end date"
    )]
    end_date: Option<String>,
    #[arg(long, value_name = "TZ", help = "IANA timezone for calendar windows")]
    timezone: Option<String>,
    #[arg(
        long,
        value_name = "SOURCE",
        help = "Source slug to filter sessions to"
    )]
    source: Option<String>,
    #[arg(long, value_enum, help = "App/source alias to filter sessions to")]
    app: Option<SourceArg>,
    #[arg(long, value_name = "MODEL", help = "Model name filter")]
    model: Option<String>,
    #[arg(long, value_name = "PROVIDER", help = "Billing provider filter")]
    billing_provider: Option<String>,
    #[arg(long, value_name = "CHANNEL", help = "Billing channel filter")]
    billing_channel: Option<String>,
    #[arg(
        long,
        value_name = "MACHINE_ID",
        help = "Override the local machine filter"
    )]
    machine_id: Option<String>,
    #[arg(
        long,
        value_name = "PROFILE_ID",
        help = "Filter by source plan profile id"
    )]
    source_plan_profile_id: Option<String>,
    #[arg(long, value_name = "USD", help = "Minimum session cost")]
    min_cost: Option<f64>,
    #[arg(long, value_name = "USD", help = "Maximum session cost")]
    max_cost: Option<f64>,
    #[arg(long, value_name = "FIELD", help = "Sort field")]
    sort_by: Option<String>,
    #[arg(long, value_name = "DIR", help = "Sort direction, asc or desc")]
    sort_dir: Option<String>,
    #[arg(long, value_name = "TEXT", help = "Search text")]
    search: Option<String>,
    #[arg(long, help = "Request account-wide sessions instead of this Mac")]
    all_machines: bool,
}

impl SessionsArgs {
    fn query(&self) -> AgentSessionsQuery {
        AgentSessionsQuery {
            limit: self.limit,
            cursor: non_empty_option(self.cursor.as_deref()),
            range: non_empty_option(self.range.as_deref()),
            start_date: non_empty_option(self.start_date.as_deref()),
            end_date: non_empty_option(self.end_date.as_deref()),
            timezone: non_empty_option(self.timezone.as_deref()),
            source: selected_source_slug(self.source.as_deref(), self.app),
            model: non_empty_option(self.model.as_deref()),
            billing_provider: non_empty_option(self.billing_provider.as_deref()),
            billing_channel: non_empty_option(self.billing_channel.as_deref()),
            machine_id: non_empty_option(self.machine_id.as_deref()),
            source_plan_profile_id: non_empty_option(self.source_plan_profile_id.as_deref()),
            min_cost: self.min_cost.map(|value| value.to_string()),
            max_cost: self.max_cost.map(|value| value.to_string()),
            sort_by: non_empty_option(self.sort_by.as_deref()),
            sort_dir: non_empty_option(self.sort_dir.as_deref()),
            search: non_empty_option(self.search.as_deref()),
            all_machines: self.all_machines,
        }
    }
}

#[derive(Debug, Args)]
struct RecommendationsArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
}

impl RecommendationsArgs {
    fn query(&self) -> AgentRecommendationsQuery {
        AgentRecommendationsQuery {}
    }
}

#[derive(Debug, Args)]
struct ProviderImpactArgs {
    #[arg(long, help = "Print one final JSON object and no human summary text")]
    json: bool,
    #[arg(long, value_name = "YYYY-MM-DD", help = "Inclusive event date start")]
    date_from: Option<String>,
    #[arg(long, value_name = "YYYY-MM-DD", help = "Inclusive event date end")]
    date_to: Option<String>,
    #[arg(long, value_name = "PROVIDER", help = "Provider filter")]
    provider: Option<String>,
    #[arg(long, value_name = "APP", help = "Provider app or surface filter")]
    app: Option<String>,
    #[arg(long, value_name = "KIND", help = "Provider-impact kind filter")]
    kind: Option<String>,
    #[arg(long, value_name = "CONFIDENCE", help = "Confidence filter")]
    confidence: Option<String>,
    #[arg(long, value_name = "PRIORITY", help = "Impact priority filter")]
    impact_priority: Option<String>,
    #[arg(long, value_name = "STATUS", help = "Review status filter")]
    status: Option<String>,
    #[arg(long, value_name = "TEXT", help = "Search text")]
    q: Option<String>,
    #[arg(
        long,
        value_name = "LIMIT",
        help = "Maximum number of events to return"
    )]
    limit: Option<u16>,
}

impl ProviderImpactArgs {
    fn query(&self) -> AgentProviderImpactQuery {
        AgentProviderImpactQuery {
            date_from: non_empty_option(self.date_from.as_deref()),
            date_to: non_empty_option(self.date_to.as_deref()),
            provider: non_empty_option(self.provider.as_deref()),
            app: non_empty_option(self.app.as_deref()),
            kind: non_empty_option(self.kind.as_deref()),
            confidence: non_empty_option(self.confidence.as_deref()),
            impact_priority: non_empty_option(self.impact_priority.as_deref()),
            status: non_empty_option(self.status.as_deref()),
            q: non_empty_option(self.q.as_deref()),
            limit: self.limit,
        }
    }
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

impl SourceArg {
    fn slug(self) -> &'static str {
        match self {
            SourceArg::Codex => "codex",
            SourceArg::ClaudeCode => "claude_code",
            SourceArg::Pi => "pi",
        }
    }
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
    if let Err(error) = validate_cli(&cli) {
        let code = print_error(error, OutputMode::Human, None);
        std::process::exit(code);
    }
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

fn validate_cli(cli: &Cli) -> Result<(), CliError> {
    if matches!(&cli.command, Command::Context(args) if !args.json) {
        return Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "ottto context is agent JSON only; pass --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        });
    }
    if matches!(&cli.command, Command::Costs(args) if !args.json) {
        return Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "ottto costs is agent JSON only; pass --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        });
    }
    if matches!(&cli.command, Command::Sessions(args) if !args.json) {
        return Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "ottto sessions is agent JSON only; pass --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        });
    }
    if matches!(&cli.command, Command::Recommendations(args) if !args.json) {
        return Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "ottto recommendations is agent JSON only; pass --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        });
    }
    if matches!(&cli.command, Command::ProviderImpact(args) if !args.json) {
        return Err(CliError {
            code: CliErrorCode::InvalidRequest,
            message: "ottto provider-impact is agent JSON only; pass --json".to_string(),
            retryable: false,
            details: BTreeMap::new(),
        });
    }
    Ok(())
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

/// Commands that can run live smoke, telemetry collect, or backend verification
/// work before replying. They run far longer than ordinary control commands, so
/// they need the wider local-control timeout.
fn is_long_running_command(command: &LocalControlCommand) -> bool {
    matches!(
        command,
        LocalControlCommand::Status {
            refresh_agent_status: true,
        } | LocalControlCommand::AgentStatusRefresh { .. }
            | LocalControlCommand::AgentContext { .. }
            | LocalControlCommand::AgentCosts { .. }
            | LocalControlCommand::AgentSessions { .. }
            | LocalControlCommand::AgentRecommendations { .. }
            | LocalControlCommand::AgentProviderImpact { .. }
            | LocalControlCommand::Setup { .. }
            | LocalControlCommand::SetupAnswer { .. }
            | LocalControlCommand::SetupAction { .. }
            | LocalControlCommand::Verify { .. }
    )
}

/// Read/write timeout for a control-socket round-trip, widened for commands that
/// legitimately stay busy server-side. Plain `status` and ordinary commands keep
/// the tight bound.
fn control_socket_timeout(command: &LocalControlCommand) -> Duration {
    if is_long_running_command(command) {
        LOCAL_CONTROL_REFRESH_TIMEOUT
    } else {
        LOCAL_CONTROL_SOCKET_TIMEOUT
    }
}

fn request_with_autostart(
    invocation: &Invocation,
    request: &LocalControlRequest,
) -> Result<LocalControlResponse, CliError> {
    let timeout = control_socket_timeout(&request.command);
    match request_unix_socket_with_timeout(&invocation.socket, request, timeout) {
        Ok(response) => Ok(response),
        Err(error) => {
            // Only kickstart+retry when the daemon was not accepting
            // connections. A post-connect timeout means the daemon is alive but
            // busy (e.g. a slow multi-source agent-status refresh); restarting
            // it would interrupt healthy in-flight work and not help anyway.
            if invocation.auto_start && error.is_connect_failure() {
                match autostart_and_retry(invocation, request, timeout) {
                    Ok(response) => Ok(response),
                    Err(autostart_error) => Err(daemon_unavailable_error(
                        error.to_string(),
                        &invocation.socket,
                        true,
                        Some(autostart_error.to_string()),
                    )),
                }
            } else {
                Err(daemon_unavailable_error(
                    error.to_string(),
                    &invocation.socket,
                    false,
                    None,
                ))
            }
        }
    }
}

fn autostart_and_retry(
    invocation: &Invocation,
    request: &LocalControlRequest,
    timeout: Duration,
) -> anyhow::Result<LocalControlResponse> {
    kickstart_macos_launch_agent()?;
    let mut last_error: Option<anyhow::Error> = None;
    for _ in 0..60 {
        thread::sleep(Duration::from_millis(500));
        match request_unix_socket_with_timeout(&invocation.socket, request, timeout) {
            Ok(response) => return Ok(response),
            // Keep waiting only while the freshly-kickstarted daemon is still
            // coming up (connect still failing). Once we can connect, a
            // transport error won't be cured by retrying, so surface it now
            // instead of looping up to 30s.
            Err(error) if error.is_connect_failure() => last_error = Some(error.into_anyhow()),
            Err(error) => return Err(error.into_anyhow()),
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
    let mut claim_code_auth_completed = false;
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

        let setup_request =
            request_like(&invocation, setup_command(&args, claim_code_auth_completed));
        print_progress(&setup_request, invocation.output_mode);
        match request_with_autostart(&invocation, &setup_request) {
            Ok(response) if response.ok => {
                let payload = response.payload.unwrap_or(serde_json::Value::Null);
                let exit_code = setup_payload_exit_code(&payload);
                last_setup_payload = Some(payload.clone());
                if args.no_wait
                    || setup_exit_is_terminal(exit_code)
                    || setup_payload_requires_user_decision(&payload)
                {
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
                if setup_error_should_start_browser_claim(&error)
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
                } else if args.claim_code.is_some()
                    && !claim_code_auth_completed
                    && setup_claim_already_claimed_error(&error)
                {
                    let claim_code = args.claim_code.as_deref().expect("claim code is present");
                    match complete_pending_browser_claim(&invocation, claim_code) {
                        SetupAuthCompletion::Completed => {
                            claim_code_auth_completed = true;
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

fn setup_command(args: &SetupArgs, claim_code_auth_completed: bool) -> LocalControlCommand {
    LocalControlCommand::Setup {
        sources: Vec::new(),
        claim_code: if claim_code_auth_completed {
            None
        } else {
            args.claim_code.clone()
        },
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

fn setup_payload_requires_user_decision(payload: &serde_json::Value) -> bool {
    payload
        .get("next_question")
        .is_some_and(|value| !value.is_null())
        || payload
            .get("next_action")
            .is_some_and(|value| !value.is_null())
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

fn complete_pending_browser_claim(
    invocation: &Invocation,
    claim_code: &str,
) -> SetupAuthCompletion {
    let request = request_like(
        invocation,
        LocalControlCommand::AuthCompletePending {
            claim_code: claim_code.to_string(),
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

fn setup_claim_already_claimed_error(error: &CliError) -> bool {
    error.details.values().any(|value| match value {
        RedactedValue::String(detail) => detail
            .to_ascii_lowercase()
            .contains("setup code is claimed"),
        _ => false,
    })
}

fn setup_error_should_start_browser_claim(error: &CliError) -> bool {
    if error.code == CliErrorCode::NeedsUserAction {
        return true;
    }
    if error.code != CliErrorCode::BackendRejected {
        return false;
    }
    let endpoint = error.details.get("endpoint").and_then(|value| match value {
        RedactedValue::String(value) => Some(value.to_ascii_lowercase()),
        _ => None,
    });
    let status = error.details.get("status").and_then(|value| match value {
        RedactedValue::Number(value) => Some(*value),
        _ => None,
    });
    let body = error
        .details
        .get("body_excerpt")
        .and_then(|value| match value {
            RedactedValue::String(value) => Some(value.to_ascii_lowercase()),
            _ => None,
        });
    let setup_run_endpoint = endpoint.as_deref().is_some_and(|value| {
        value.contains("/api/v1/setup-runs/") && value.contains("/local-client/")
    });
    if setup_run_endpoint && matches!(status, Some(401 | 403 | 404 | 410)) {
        return true;
    }
    body.as_deref().is_some_and(|value| {
        value.contains("attach an active setup run")
            || value.contains("setup run companion token expired")
            || value.contains("setup_run_companion_token_expired")
            || value.contains("setup run expired")
            || value.contains("setup_run_expired")
            || value.contains("setup run cancelled")
            || value.contains("setup_run_cancelled")
            || value.contains("setup run missing")
            || value.contains("setup run not found")
    }) || error
        .message
        .to_ascii_lowercase()
        .contains("attach an active setup run")
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
    let payload = setup_payload_with_agent_action(payload);
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
    setup_payload_with_agent_action(serde_json::json!({
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
    }))
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
        object.remove("agent_action");
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
    setup_payload_with_agent_action(payload)
}

fn setup_payload_with_agent_action(mut payload: serde_json::Value) -> serde_json::Value {
    let action = setup_agent_action(&payload);
    if let Some(object) = payload.as_object_mut() {
        object.entry("agent_action".to_string()).or_insert(action);
    }
    payload
}

fn setup_agent_action(payload: &serde_json::Value) -> serde_json::Value {
    let status = payload
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("succeeded");
    let next_action = payload.get("next_action").filter(|value| !value.is_null());
    let next_action_type = next_action
        .and_then(|value| value.get("type"))
        .and_then(|value| value.as_str());
    let next_question = payload
        .get("next_question")
        .filter(|value| !value.is_null());

    let (kind, requires_user, retryable, description) =
        if matches!(status, "succeeded" | "success" | "completed" | "complete") {
            ("none", false, false, "Setup is complete.")
        } else if matches!(status, "timed_out" | "timeout") {
            (
                "retry_setup",
                false,
                true,
                "Setup timed out. Retry setup or check status before taking manual action.",
            )
        } else if matches!(next_action_type, Some("browser_claim"))
            || status == "waiting_for_browser"
        {
            (
                "open_browser_claim",
                true,
                true,
                "Open or share the browser claim URL or code with the user.",
            )
        } else if next_action.is_some() {
            (
                "run_next_action",
                true,
                true,
                "Follow the structured next_action object.",
            )
        } else if next_question.is_some()
            || matches!(
                status,
                "waiting_for_approval" | "waiting_for_user" | "needs_action" | "action_required"
            )
        {
            (
                "answer_setup_question",
                true,
                true,
                "Ask the user to answer the structured next_question prompt.",
            )
        } else if matches!(
            status,
            "pending" | "running" | "waiting" | "waiting_for_companion"
        ) {
            (
                "wait_or_check_status",
                false,
                true,
                "Setup is still running. Wait, poll setup again, or check status.",
            )
        } else if matches!(status, "failed" | "canceled" | "cancelled") {
            (
                "inspect_failure",
                false,
                true,
                "Inspect setup failure details and run doctor before repair.",
            )
        } else {
            (
                "check_status",
                false,
                true,
                "Check status or doctor for the current setup state.",
            )
        };

    serde_json::json!({
        "kind": kind,
        "requires_user": requires_user,
        "retryable": retryable,
        "description": description,
    })
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
    let token = cli.token.unwrap_or_else(default_cli_control_token);
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

fn default_cli_control_token() -> String {
    match client_control_token() {
        Ok(token) => token,
        Err(_) if !cfg!(debug_assertions) => load_or_create_control_token()
            .unwrap_or_else(|_| "local-development-control-token".to_string()),
        Err(_) => "local-development-control-token".to_string(),
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
        Command::Context(args) => LocalControlCommand::AgentContext {
            query: args.query(),
        },
        Command::Costs(args) => LocalControlCommand::AgentCosts {
            query: args.query(),
        },
        Command::Sessions(args) => LocalControlCommand::AgentSessions {
            query: args.query(),
        },
        Command::Recommendations(args) => LocalControlCommand::AgentRecommendations {
            query: args.query(),
        },
        Command::ProviderImpact(args) => LocalControlCommand::AgentProviderImpact {
            query: args.query(),
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
        Command::Context(args) => args.json,
        Command::Costs(args) => args.json,
        Command::Sessions(args) => args.json,
        Command::Recommendations(args) => args.json,
        Command::ProviderImpact(args) => args.json,
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

fn non_empty_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn selected_source_slug(source: Option<&str>, app: Option<SourceArg>) -> Option<String> {
    non_empty_option(source).or_else(|| app.map(|source| source.slug().to_string()))
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
        LocalControlCommand::PersonalMeterLocalSnapshot { .. } => "personal_meter_local_snapshot",
        LocalControlCommand::AgentContext { .. } => "agent_context",
        LocalControlCommand::AgentCosts { .. } => "agent_costs",
        LocalControlCommand::AgentSessions { .. } => "agent_sessions",
        LocalControlCommand::AgentRecommendations { .. } => "agent_recommendations",
        LocalControlCommand::AgentProviderImpact { .. } => "agent_provider_impact",
        LocalControlCommand::AuthStart => "auth_start",
        LocalControlCommand::AuthComplete { .. } => "auth_complete",
        LocalControlCommand::AuthCompletePending { .. } => "auth_complete_pending",
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
    if let Some(schema_version) = payload
        .get("schema_version")
        .and_then(|value| value.as_str())
    {
        if schema_version == "agent_context.v1" {
            return "Ottto context: ok".to_string();
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

    fn assert_request_matches_fixture(invocation: &Invocation, fixture: &str) {
        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(fixture).expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn long_running_commands_get_timeout_exceeding_server_worst_case() {
        // The daemon can refresh/verify across Codex, Claude Code, and Pi. Each
        // source's smoke or collect+upload round-trip can take ~18s in the worst
        // case, so a multi-source operation can run ~54s server-side before the
        // CLI ever sees a byte. The long timeout must clear that summed worst
        // case; a too-tight bound makes healthy work look like a dead daemon.
        const SERVER_WORST_CASE_PER_SOURCE: Duration = Duration::from_secs(18);
        const REFRESHED_SOURCE_COUNT: u32 = 3;
        let summed_worst_case = SERVER_WORST_CASE_PER_SOURCE * REFRESHED_SOURCE_COUNT;

        for command in [
            LocalControlCommand::Status {
                refresh_agent_status: true,
            },
            LocalControlCommand::AgentStatusRefresh { source: None },
            LocalControlCommand::AgentContext {
                query: AgentContextQuery::default(),
            },
            LocalControlCommand::AgentCosts {
                query: AgentCostsQuery::default(),
            },
            LocalControlCommand::AgentSessions {
                query: AgentSessionsQuery::default(),
            },
            LocalControlCommand::AgentRecommendations {
                query: AgentRecommendationsQuery::default(),
            },
            LocalControlCommand::AgentProviderImpact {
                query: AgentProviderImpactQuery::default(),
            },
            LocalControlCommand::Setup {
                sources: Vec::new(),
                claim_code: None,
                setup_run_id: None,
                api_base_url: None,
            },
            LocalControlCommand::SetupAnswer {
                source: SourceKind::Codex,
                answer_type: "retry_source".to_string(),
                api_base_url: None,
            },
            LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: false,
            },
            LocalControlCommand::SetupAction {
                source: SourceKind::Codex,
                action_type: "verify_source".to_string(),
                api_base_url: None,
            },
        ] {
            assert!(
                is_long_running_command(&command),
                "{command:?} should be treated as a long-running command"
            );
            assert!(
                control_socket_timeout(&command) > summed_worst_case,
                "long timeout {:?} must exceed summed server worst case {:?}",
                control_socket_timeout(&command),
                summed_worst_case,
            );
        }

        // Plain status (no refresh) keeps the ordinary bound — under the summed
        // long-running worst case.
        let plain_status = LocalControlCommand::Status {
            refresh_agent_status: false,
        };
        assert!(!is_long_running_command(&plain_status));
        assert_eq!(
            control_socket_timeout(&plain_status),
            LOCAL_CONTROL_SOCKET_TIMEOUT
        );
        assert!(control_socket_timeout(&plain_status) < summed_worst_case);
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
        let commands: [(&str, &[&str]); 23] = [
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
            ("ottto context --help", &["ottto", "context", "--help"]),
            ("ottto costs --help", &["ottto", "costs", "--help"]),
            ("ottto sessions --help", &["ottto", "sessions", "--help"]),
            (
                "ottto recommendations --help",
                &["ottto", "recommendations", "--help"],
            ),
            (
                "ottto provider-impact --help",
                &["ottto", "provider-impact", "--help"],
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
    fn context_requires_json_mode() {
        let cli = Cli::parse_from(["ottto", "context"]);
        let error = validate_cli(&cli).expect_err("context requires json");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "ottto context is agent JSON only; pass --json"
        );
    }

    #[test]
    fn costs_requires_json_mode() {
        let cli = Cli::parse_from(["ottto", "costs"]);
        let error = validate_cli(&cli).expect_err("costs requires json");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert_eq!(error.message, "ottto costs is agent JSON only; pass --json");
    }

    #[test]
    fn sessions_requires_json_mode() {
        let cli = Cli::parse_from(["ottto", "sessions"]);
        let error = validate_cli(&cli).expect_err("sessions requires json");
        assert_eq!(error.code, CliErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "ottto sessions is agent JSON only; pass --json"
        );
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
        assert!(
            setup_payload_requires_user_decision(&payload),
            "watch mode should surface user decisions instead of polling to timeout"
        );
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("answer_setup_question")
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
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("retry_setup")
        );
    }

    #[test]
    fn setup_failed_output_uses_stable_internal_exit_code() {
        let payload = parse_json_output(include_str!(
            "../../../fixtures/cli/setup-failed-output.json"
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
            CliErrorCode::Internal.exit_code()
        );
        assert_eq!(
            setup_payload_exit_code(&payload),
            CliErrorCode::Internal.exit_code()
        );
        assert!(
            !setup_payload_requires_user_decision(&payload),
            "failed setup should surface inspect_failure without asking the user a question"
        );
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("inspect_failure")
        );
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("requires_user"))
                .and_then(|value| value.as_bool()),
            Some(false)
        );
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("retryable"))
                .and_then(|value| value.as_bool()),
            Some(true)
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
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("open_browser_claim")
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
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("retry_setup")
        );
    }

    #[test]
    fn setup_payload_agent_action_is_added_for_daemon_payloads() {
        let payload = serde_json::json!({
            "status": "running",
            "setup_run_id": "setup_running",
            "next_question": null,
            "next_action": null,
        });
        let payload = setup_payload_with_agent_action(payload);
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("wait_or_check_status")
        );

        let payload = serde_json::json!({
            "status": "succeeded",
            "agent_action": {
                "kind": "custom_daemon_action"
            },
        });
        let payload = setup_payload_with_agent_action(payload);
        assert_eq!(
            payload
                .get("agent_action")
                .and_then(|value| value.get("kind"))
                .and_then(|value| value.as_str()),
            Some("custom_daemon_action")
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

        let already_claimed = CliError {
            code: CliErrorCode::BackendRejected,
            message: "Ottto rejected the local setup request.".to_string(),
            retryable: false,
            details: BTreeMap::from([(
                "body_excerpt".to_string(),
                RedactedValue::String(r#"{"detail":"Setup code is claimed."}"#.to_string()),
            )]),
        };
        assert!(setup_claim_already_claimed_error(&already_claimed));
    }

    #[test]
    fn setup_rejected_stale_run_starts_fresh_browser_claim() {
        let rejected = CliError {
            code: CliErrorCode::BackendRejected,
            message: "Ottto rejected the local setup request. Open the Ottto app from Ottto to attach an active setup run.".to_string(),
            retryable: false,
            details: BTreeMap::from([
                (
                    "endpoint".to_string(),
                    RedactedValue::String(
                        "/api/v1/setup-runs/setup_stale/local-client/scan-result".to_string(),
                    ),
                ),
                ("status".to_string(), RedactedValue::Number(401)),
                (
                    "body_excerpt".to_string(),
                    RedactedValue::String(
                        r#"{"detail":"Setup run companion token expired"}"#.to_string(),
                    ),
                ),
            ]),
        };

        assert!(setup_error_should_start_browser_claim(&rejected));

        let unrelated = CliError {
            code: CliErrorCode::BackendRejected,
            message: "Ottto rejected the diagnostics upload.".to_string(),
            retryable: false,
            details: BTreeMap::from([
                (
                    "endpoint".to_string(),
                    RedactedValue::String(
                        "/api/v1/setup-runs/setup_stale/local-client/diagnostics".to_string(),
                    ),
                ),
                ("status".to_string(), RedactedValue::Number(401)),
            ]),
        };
        assert!(
            setup_error_should_start_browser_claim(&unrelated),
            "setup/login owns this helper, so any setup-run local-client auth rejection should start a fresh claim"
        );

        let non_setup = CliError {
            code: CliErrorCode::BackendRejected,
            message: "Ottto rejected the diagnostics upload.".to_string(),
            retryable: false,
            details: BTreeMap::from([(
                "endpoint".to_string(),
                RedactedValue::String("/api/v1/diagnostics/uploads".to_string()),
            )]),
        };
        assert!(!setup_error_should_start_browser_claim(&non_setup));
    }

    #[test]
    fn fix_builds_repair_request() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
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
        invocation.request.request_id = "req_cli_fix_codex_fixture".to_string();

        assert_eq!(invocation.socket, PathBuf::from("/tmp/ottto.sock"));
        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.token.as_deref(), Some("test-token"));
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::Repair {
                source: SourceKind::Codex,
                dry_run: false
            }
        );
        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/fix-codex-request.json"),
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
    fn setup_omits_claim_code_after_claim_auth_completes() {
        let args = SetupArgs {
            claim_code: Some("claim_123".to_string()),
            no_browser: false,
            no_wait: false,
            timeout: DEFAULT_SETUP_TIMEOUT_SECONDS,
            setup_run_id: None,
            api_base_url: None,
            json: true,
        };

        assert_eq!(
            setup_command(&args, false),
            LocalControlCommand::Setup {
                sources: Vec::new(),
                claim_code: Some("claim_123".to_string()),
                setup_run_id: None,
                api_base_url: None
            }
        );
        assert_eq!(
            setup_command(&args, true),
            LocalControlCommand::Setup {
                sources: Vec::new(),
                claim_code: None,
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
    fn setup_headless_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Setup(SetupArgs {
                    claim_code: None,
                    no_browser: true,
                    no_wait: true,
                    timeout: 30,
                    setup_run_id: None,
                    api_base_url: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_setup_headless_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/setup-headless-request.json"
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
    fn login_headless_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Login(SetupArgs {
                    claim_code: None,
                    no_browser: true,
                    no_wait: true,
                    timeout: 45,
                    setup_run_id: None,
                    api_base_url: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_login_headless_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/login-headless-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn account_builds_account_request() {
        let cli = Cli::parse_from(["ottto", "account", "--json"]);
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(invocation.request.command, LocalControlCommand::Account);
    }

    #[test]
    fn account_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Account(JsonArgs { json: true }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_account_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/cli/account-request.json"))
                .expect("fixture parses");
        assert_eq!(actual, expected);
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
    fn logout_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Logout(LogoutArgs {
                    json: true,
                    local_only: false,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_logout_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/cli/logout-request.json"))
                .expect("fixture parses");
        assert_eq!(actual, expected);
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
    fn logout_local_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Logout(LogoutArgs {
                    json: true,
                    local_only: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_logout_local_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/logout-local-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
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
    fn doctor_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Doctor(JsonArgs { json: true }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_doctor_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/cli/doctor-request.json"))
                .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn verify_repair_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Verify(VerifyArgs {
                    source: None,
                    app: Some(SourceArg::Codex),
                    repair: true,
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_verify_repair_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/verify-repair-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn apps_root_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Apps(AppsArgs {
                    command: None,
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_apps_root_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/cli/apps-root-request.json"))
                .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn apps_detect_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Apps(AppsArgs {
                    command: Some(AppsCommand::Detect(JsonArgs { json: true })),
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_apps_detect_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/apps-detect-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
    }

    #[test]
    fn apps_status_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Apps(AppsArgs {
                    command: Some(AppsCommand::Status(AppStatusArgs {
                        app: SourceArg::Pi,
                        json: true,
                    })),
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_apps_status_pi_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/apps-status-pi-request.json"
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
    fn context_builds_agent_context_request() {
        let cli = Cli::parse_from([
            "ottto",
            "context",
            "--json",
            "--days",
            "14",
            "--range",
            "last_7_days",
            "--start-date",
            "2026-06-01",
            "--end-date",
            "2026-06-05",
            "--timezone",
            "America/Los_Angeles",
            "--app",
            "claude-code",
            "--machine-id",
            "otm_test",
            "--source-plan-profile-id",
            "018fe251-b6f3-7cc8-9f82-01a76449d111",
            "--max-tokens",
            "4000",
        ]);
        validate_cli(&cli).expect("context json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentContext {
                query: AgentContextQuery {
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: Some("claude_code".to_string()),
                    machine_id: Some("otm_test".to_string()),
                    source_plan_profile_id: Some(
                        "018fe251-b6f3-7cc8-9f82-01a76449d111".to_string()
                    ),
                    max_tokens: Some(4000),
                    all_machines: false,
                }
            }
        );
    }

    #[test]
    fn context_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Context(ContextArgs {
                    json: true,
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: None,
                    app: Some(SourceArg::ClaudeCode),
                    machine_id: Some("otm_fixture".to_string()),
                    source_plan_profile_id: Some("profile_fixture".to_string()),
                    max_tokens: Some(4000),
                    all_machines: false,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_context_fixture".to_string();

        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/context-request.json"),
        );
    }

    #[test]
    fn context_watch_builds_ndjson_invocation() {
        let cli = Cli::parse_from(["ottto", "context", "--json", "--watch", "--all-machines"]);
        validate_cli(&cli).expect("context watch valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Ndjson);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentContext {
                query: AgentContextQuery {
                    all_machines: true,
                    ..AgentContextQuery::default()
                }
            }
        );
    }

    #[test]
    fn context_accepts_backend_source_slugs() {
        let cli = Cli::parse_from(["ottto", "context", "--json", "--source", "bedrock"]);
        validate_cli(&cli).expect("context json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentContext {
                query: AgentContextQuery {
                    source: Some("bedrock".to_string()),
                    ..AgentContextQuery::default()
                }
            }
        );
    }

    #[test]
    fn costs_builds_agent_costs_request() {
        let cli = Cli::parse_from([
            "ottto",
            "costs",
            "--json",
            "--days",
            "14",
            "--range",
            "last_7_days",
            "--start-date",
            "2026-06-01",
            "--end-date",
            "2026-06-05",
            "--timezone",
            "America/Los_Angeles",
            "--source",
            "vertex",
            "--machine-id",
            "otm_test",
            "--source-plan-profile-id",
            "018fe251-b6f3-7cc8-9f82-01a76449d111",
            "--bucket",
            "day",
            "--mode",
            "full",
        ]);
        validate_cli(&cli).expect("costs json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentCosts {
                query: AgentCostsQuery {
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: Some("vertex".to_string()),
                    machine_id: Some("otm_test".to_string()),
                    source_plan_profile_id: Some(
                        "018fe251-b6f3-7cc8-9f82-01a76449d111".to_string()
                    ),
                    bucket: Some("day".to_string()),
                    mode: Some("full".to_string()),
                    all_machines: false,
                }
            }
        );
    }

    #[test]
    fn costs_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Costs(CostsArgs {
                    json: true,
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: Some("vertex".to_string()),
                    app: None,
                    machine_id: Some("otm_fixture".to_string()),
                    source_plan_profile_id: Some("profile_fixture".to_string()),
                    bucket: Some("day".to_string()),
                    mode: Some("full".to_string()),
                    all_machines: false,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_costs_fixture".to_string();

        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/costs-request.json"),
        );
    }

    #[test]
    fn sessions_builds_agent_sessions_request() {
        let cli = Cli::parse_from([
            "ottto",
            "sessions",
            "--json",
            "--limit",
            "25",
            "--cursor",
            "next_123",
            "--range",
            "today",
            "--start-date",
            "2026-06-01",
            "--end-date",
            "2026-06-05",
            "--timezone",
            "America/Los_Angeles",
            "--app",
            "codex",
            "--model",
            "gpt-5.3-codex",
            "--billing-provider",
            "openai",
            "--billing-channel",
            "subscription",
            "--source-plan-profile-id",
            "018fe251-b6f3-7cc8-9f82-01a76449d111",
            "--min-cost",
            "1.25",
            "--max-cost",
            "7.5",
            "--sort-by",
            "cost",
            "--sort-dir",
            "desc",
            "--search",
            "roadmap",
            "--all-machines",
        ]);
        validate_cli(&cli).expect("sessions json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentSessions {
                query: AgentSessionsQuery {
                    limit: Some(25),
                    cursor: Some("next_123".to_string()),
                    range: Some("today".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: Some("codex".to_string()),
                    model: Some("gpt-5.3-codex".to_string()),
                    billing_provider: Some("openai".to_string()),
                    billing_channel: Some("subscription".to_string()),
                    machine_id: None,
                    source_plan_profile_id: Some(
                        "018fe251-b6f3-7cc8-9f82-01a76449d111".to_string()
                    ),
                    min_cost: Some("1.25".to_string()),
                    max_cost: Some("7.5".to_string()),
                    sort_by: Some("cost".to_string()),
                    sort_dir: Some("desc".to_string()),
                    search: Some("roadmap".to_string()),
                    all_machines: true,
                }
            }
        );
    }

    #[test]
    fn sessions_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Sessions(SessionsArgs {
                    json: true,
                    limit: Some(25),
                    cursor: Some("next_fixture".to_string()),
                    range: Some("today".to_string()),
                    start_date: Some("2026-06-01".to_string()),
                    end_date: Some("2026-06-05".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    source: None,
                    app: Some(SourceArg::Codex),
                    model: Some("gpt-5.3-codex".to_string()),
                    billing_provider: Some("openai".to_string()),
                    billing_channel: Some("subscription".to_string()),
                    machine_id: None,
                    source_plan_profile_id: Some("profile_fixture".to_string()),
                    min_cost: Some(1.25),
                    max_cost: Some(7.5),
                    sort_by: Some("cost".to_string()),
                    sort_dir: Some("desc".to_string()),
                    search: Some("roadmap".to_string()),
                    all_machines: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_sessions_fixture".to_string();

        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/sessions-request.json"),
        );
    }

    #[test]
    fn recommendations_builds_agent_recommendations_request() {
        let cli = Cli::parse_from(["ottto", "recommendations", "--json"]);
        validate_cli(&cli).expect("recommendations json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentRecommendations {
                query: AgentRecommendationsQuery::default()
            }
        );
    }

    #[test]
    fn recommendations_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Recommendations(RecommendationsArgs { json: true }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_recommendations_fixture".to_string();

        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/recommendations-request.json"),
        );
    }

    #[test]
    fn provider_impact_builds_agent_provider_impact_request() {
        let cli = Cli::parse_from([
            "ottto",
            "provider-impact",
            "--json",
            "--date-from",
            "2026-06-01",
            "--date-to",
            "2026-06-08",
            "--provider",
            "openai",
            "--app",
            "codex",
            "--kind",
            "quota",
            "--confidence",
            "high",
            "--impact-priority",
            "critical",
            "--status",
            "verified",
            "--q",
            "subscription",
            "--limit",
            "25",
        ]);
        validate_cli(&cli).expect("provider-impact json valid");
        let invocation = invocation_from_cli(cli);

        assert_eq!(invocation.output_mode, OutputMode::Json);
        assert_eq!(
            invocation.request.command,
            LocalControlCommand::AgentProviderImpact {
                query: AgentProviderImpactQuery {
                    date_from: Some("2026-06-01".to_string()),
                    date_to: Some("2026-06-08".to_string()),
                    provider: Some("openai".to_string()),
                    app: Some("codex".to_string()),
                    kind: Some("quota".to_string()),
                    confidence: Some("high".to_string()),
                    impact_priority: Some("critical".to_string()),
                    status: Some("verified".to_string()),
                    q: Some("subscription".to_string()),
                    limit: Some(25),
                }
            }
        );
    }

    #[test]
    fn provider_impact_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::ProviderImpact(ProviderImpactArgs {
                    json: true,
                    date_from: Some("2026-06-01".to_string()),
                    date_to: Some("2026-06-08".to_string()),
                    provider: Some("openai".to_string()),
                    app: Some("codex".to_string()),
                    kind: Some("quota".to_string()),
                    confidence: Some("high".to_string()),
                    impact_priority: Some("critical".to_string()),
                    status: Some("verified".to_string()),
                    q: Some("subscription".to_string()),
                    limit: Some(25),
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_provider_impact_fixture".to_string();

        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/provider-impact-request.json"),
        );
    }

    #[test]
    fn recommendations_and_provider_impact_require_json() {
        let recommendations = Cli::parse_from(["ottto", "recommendations"]);
        assert_eq!(
            validate_cli(&recommendations).unwrap_err().message,
            "ottto recommendations is agent JSON only; pass --json"
        );

        let provider_impact = Cli::parse_from(["ottto", "provider-impact"]);
        assert_eq!(
            validate_cli(&provider_impact).unwrap_err().message,
            "ottto provider-impact is agent JSON only; pass --json"
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
    fn update_check_request_matches_baseline_fixture() {
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Update(UpdateArgs {
                    command: Some(UpdateCommand::Check(JsonArgs { json: true })),
                    json: true,
                }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_update_check_fixture".to_string();

        let actual = serde_json::to_value(&invocation.request).expect("request serializes");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/cli/update-check-request.json"
        ))
        .expect("fixture parses");
        assert_eq!(actual, expected);
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
        let mut invocation = build_invocation(
            Cli {
                socket: Some(PathBuf::from("/tmp/ottto.sock")),
                token: Some("test-token".to_string()),
                no_autostart: false,
                watch: false,
                command: Command::Uninstall(JsonArgs { json: true }),
            },
            OutputMode::Json,
        );
        invocation.request.request_id = "req_cli_uninstall_fixture".to_string();

        assert_eq!(
            invocation.request.command,
            LocalControlCommand::UninstallExecute { confirm: true }
        );
        assert_request_matches_fixture(
            &invocation,
            include_str!("../../../fixtures/cli/uninstall-request.json"),
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
