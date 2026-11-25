//! Cloud setup orchestration and CLI output.

mod aws;
mod stack;

use self::aws::Aws;
use self::stack::{CleanupReference, Plan, Reconcile};
use crate::{
    compact_json, final_payload_event, pretty_json, sanitize_for_terminal, CloudCommand,
    CloudConnectArgs, CloudStatusArgs, Invocation, OutputMode,
};
use ottto_protocol::{
    cloud_uuid, expected_local_control_protocol_version, CliError, CliErrorCode,
    CloudConnectEnsure, CloudConnectFailure as Failure, CloudConnectSubmit,
    LocalControlCommand as Command,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const SCHEMA: &str = "ottto.cloud_connect.cli.v1";
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) fn run(invocation: Invocation, command: CloudCommand) -> i32 {
    match command {
        CloudCommand::Status(CloudStatusArgs { attempt: None, .. }) => crate::run(invocation),
        CloudCommand::Status(CloudStatusArgs {
            attempt: Some(id), ..
        }) => {
            let deadline = Instant::now() + Duration::from_secs(30);
            let reply = call(&invocation, deadline, |timeout_ms| {
                Command::CloudConnectStatus {
                    attempt_id: Some(id.clone()),
                    timeout_ms,
                }
            });
            let mut result = ResultState {
                attempt_id: Some(id),
                ..ResultState::default()
            };
            match reply {
                Ok(value) => {
                    result.account_id = string(&value, "account_id").map(str::to_owned);
                    result.state = string(&value, "state").map(str::to_owned);
                    result.web_url = web_url(&value);
                    result.cleanup =
                        ended_cleanup(&value, None, Reply::Read, invocation.output_mode);
                    result.finish(
                        &invocation,
                        None,
                        None,
                        Some("Cloud setup status."),
                        Some(&value),
                    )
                }
                Err(error) => result.finish(&invocation, Some(error), None, None, None),
            }
        }
        CloudCommand::Connect(args) => {
            let deadline = Instant::now() + Duration::from_secs(args.timeout);
            let mut result = ResultState {
                source: args.source.slug(),
                ..ResultState::default()
            };
            let error = connect(&invocation, &args, deadline, &mut result).err();
            let resume = error.as_ref().map(|error| {
                let request_id = result
                    .request_id
                    .as_deref()
                    .filter(|_| !ends_attempt(error, result.state.as_deref()));
                let attempt_id = request_id.and(result.attempt_id.as_deref());
                resume(&args, invocation.output_mode, error, request_id, attempt_id)
            });
            result.finish(
                &invocation,
                error,
                resume,
                Some("Amazon Bedrock billing is connected."),
                None,
            )
        }
        CloudCommand::Cancel(args) => {
            let deadline = Instant::now() + CANCEL_TIMEOUT;
            let mut result = ResultState {
                attempt_id: Some(args.attempt.clone()),
                ..ResultState::default()
            };
            let reply = call(&invocation, deadline, |timeout_ms| {
                Command::CloudConnectCancel {
                    attempt_id: args.attempt.clone(),
                    timeout_ms,
                }
            });
            let settled = reply.map(|value| {
                result.account_id = string(&value, "account_id").map(str::to_owned);
                result.state = string(&value, "state").map(str::to_owned);
                result.web_url = web_url(&value);
                result.cleanup =
                    ended_cleanup(&value, None, Reply::Settled, invocation.output_mode);
            });
            match settled {
                Ok(()) => {
                    let message = match result.state.as_deref() {
                        Some("cancelled") => "Cloud setup cancelled.",
                        Some("expired") => "This cloud setup has already expired.",
                        Some("saved") => "This setup has already saved the connection.",
                        _ => "Cloud setup finished.",
                    };
                    result.finish(&invocation, None, None, Some(message), None)
                }
                Err(error) => {
                    let mut argv = vec!["ottto", "cloud", "cancel", "--attempt"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    argv.push(args.attempt);
                    add_output_flags(&mut argv, invocation.output_mode);
                    result.finish(&invocation, Some(error), Some(argv), None, None)
                }
            }
        }
    }
}

#[derive(Default)]
struct ResultState {
    source: &'static str,
    attempt_id: Option<String>,
    account_id: Option<String>,
    state: Option<String>,
    cleanup: Option<Value>,
    browser_url: Option<String>,
    known_stack: Option<String>,
    profile: Option<String>,
    /// The R1 `client_request_id` once sent: a rerun with it reads the same attempt back.
    request_id: Option<String>,
    /// The connections page on the web origin the service paired with this Mac's Ottto API.
    web_url: Option<String>,
}

impl ResultState {
    /// Only a page on the web origin the service paired with this Mac's API; with no such origin
    /// known (an old or unreachable service) the user gets the message alone.
    fn connect_url<'a>(&'a self, action: &str, error: Option<&'a Failure>) -> Option<&'a str> {
        match action {
            "approve_in_browser" => self.browser_url.as_deref(),
            "use_web" => error
                .and_then(|error| error.connect_url.as_deref())
                .or(self.web_url.as_deref()),
            _ => None,
        }
    }

    fn finish(
        self,
        invocation: &Invocation,
        error: Option<Failure>,
        resume: Option<Vec<String>>,
        message: Option<&str>,
        status_payload: Option<&Value>,
    ) -> i32 {
        let exit_code = error.as_ref().map_or(0, exit_code);
        // An unsettled attempt may still save its stack: point at its status, never at a delete.
        let status_argv = error.as_ref().and(self.attempt_id.as_deref()).map(|id| {
            let mut argv: Vec<String> = ["ottto", "cloud", "status", "--attempt", id]
                .into_iter()
                .map(str::to_owned)
                .collect();
            add_output_flags(&mut argv, invocation.output_mode);
            argv
        });
        let action = error
            .as_ref()
            .map_or("none", |error| error.next_action.as_str());
        let message = error.as_ref().map_or_else(
            || message.unwrap_or_default(),
            |error| error.message.as_ref(),
        );
        let connect_url = self.connect_url(action, error.as_ref());
        let payload = json!({
            "schema_version": SCHEMA,
            "status": self.state.as_deref().unwrap_or(if error.is_some() { "failed" } else { "connected" }),
            "source": if self.source.is_empty() { "bedrock" } else { self.source },
            "attempt_id": self.attempt_id,
            "account_id": self.account_id,
            "code": error.as_ref().map(|error| &error.code),
            "reason": error.as_ref().and_then(|error| error.reason.as_ref()),
            "retryable": error.as_ref().is_some_and(|error| error.retryable),
            "retry_after_seconds": error.as_ref().and_then(|error| error.retry_after_seconds),
            "next_action": action,
            "message": message,
            "connect_url": connect_url,
            "resume": resume.map(|argv| json!({"argv": argv})),
            "status_argv": status_argv,
            "stack_id": self.known_stack,
            "cleanup": self.cleanup,
            "attempt": status_payload,
        });
        match invocation.output_mode {
            OutputMode::Json => println!("{}", pretty_json(&payload)),
            OutputMode::Ndjson => println!(
                "{}",
                compact_json(&final_payload_event(
                    &invocation.request.request_id,
                    exit_code,
                    payload,
                ))
            ),
            OutputMode::Human => {
                println!("{}", sanitize_for_terminal(message));
                if let Some(state) = payload["status"]
                    .as_str()
                    .filter(|_| status_payload.is_some())
                {
                    println!("Status       {}", sanitize_for_terminal(state));
                }
                if let Some(id) = &self.attempt_id {
                    println!("Attempt      {}", sanitize_for_terminal(id));
                }
                if let Some(url) = connect_url {
                    println!("{url}");
                }
                if let Some(command) = argv_line(&payload["resume"]["argv"]) {
                    println!("Resume       {command}");
                }
                if let Some(command) = argv_line(&payload["status_argv"]) {
                    println!("Check        {command}");
                }
                if let Some(command) = argv_line(&payload["cleanup"]["argv"]) {
                    println!("Cleanup      {command}");
                } else if let Some(message) = payload["cleanup"]["message"].as_str() {
                    println!("{}", sanitize_for_terminal(message));
                }
                if let Some(command) = argv_line(&payload["cleanup"]["settle_argv"]) {
                    println!("Settle       {command}");
                }
            }
        }
        exit_code
    }
}

fn argv_line(value: &Value) -> Option<String> {
    let argv = value.as_array()?;
    let argv: Option<Vec<_>> = argv.iter().map(Value::as_str).collect();
    Some(argv?.join(" "))
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value[key].as_str()
}

fn call(
    invocation: &Invocation,
    deadline: Instant,
    command: impl Fn(u64) -> Command,
) -> Result<Value, Failure> {
    let remaining = remaining(deadline)?.min(Duration::from_secs(90));
    let mut request = invocation.request.clone();
    request.command = command(remaining.as_millis().try_into().unwrap_or(90_000));
    request.protocol_version = expected_local_control_protocol_version(&request.command);
    let response = crate::request_with_autostart_timeout(invocation, &request, remaining).map_err(
        |error| {
            if Instant::now() >= deadline {
                timed_out()
            } else {
                daemon_failure(error)
            }
        },
    )?;
    if !response.ok {
        return Err(response.error.map_or_else(invalid_server, daemon_failure));
    }
    let mut value = response.payload.ok_or_else(invalid_server)?;
    if let Some(error) = value
        .as_object_mut()
        .and_then(|value| value.remove("cloud_error"))
    {
        let error = serde_json::from_value(error).map_err(|_| invalid_server())?;
        return Err(normalize_error(error));
    }
    Ok(value)
}

fn daemon_unavailable() -> Failure {
    Failure::new(
        "daemon_unavailable",
        "Start the Ottto app and run this command again.",
        "open_app",
    )
}

fn daemon_failure(error: CliError) -> Failure {
    let code = match error.code {
        CliErrorCode::InvalidRequest
            if error
                .message
                .contains("unsupported local control protocol_version")
                || error.message.contains("unknown variant `cloud_connect_") =>
        {
            return Failure::new(
                "service_outdated",
                "Update the Ottto app or connect on the web.",
                "use_web",
            );
        }
        CliErrorCode::InvalidRequest if error.message.contains("connected to Ottto") => {
            return Failure::new("not_paired", "Pair this Mac with Ottto first.", "pair_mac");
        }
        CliErrorCode::DaemonUnavailable => return daemon_unavailable(),
        CliErrorCode::LocalAuthFailed => "local_auth_failed",
        CliErrorCode::LocalClientNotTrusted => "local_client_not_trusted",
        CliErrorCode::PermissionDenied => "permission_denied",
        CliErrorCode::TimedOut => return timed_out(),
        _ => return invalid_server(),
    };
    Failure::new(code, &error.message, "none")
}

fn connect(
    invocation: &Invocation,
    args: &CloudConnectArgs,
    deadline: Instant,
    result: &mut ResultState,
) -> Result<(), Failure> {
    if args.source.slug() != "bedrock" {
        return Err(Failure::new(
            "source_web_only",
            "Connect Google Vertex AI in the Ottto web app.",
            "use_web",
        ));
    }
    if args
        .profile
        .as_deref()
        .is_some_and(|profile| !aws::profile_valid(profile))
    {
        return Err(Failure::new(
            "invalid_argument",
            "Use a valid AWS CLI profile name.",
            "fix_flags",
        ));
    }
    // A rerun with the same request ID and flags reads the same attempt back, whatever happened
    // to the first reply, so a retry never starts a second stack.
    let client_request_id = match &args.request_id {
        Some(id) => id.clone(),
        None => new_request_id()?,
    };
    result.request_id = Some(client_request_id.clone());
    progress(invocation, "checking_ottto", json!({}));
    let features = call(invocation, deadline, |_| Command::CloudStatus {
        source: Some("bedrock".into()),
    })?;
    result.web_url = web_url(&features);
    check_features(&features)?;

    let verbose = args.verbose
        && invocation.output_mode == OutputMode::Human
        && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let aws = Aws::resolve(args.profile.clone(), verbose, deadline)?;
    result.profile = args.profile.clone();
    let mut session = aws.export(deadline)?;
    let account = aws.identity(&session, deadline)?;
    result.account_id = Some(account.clone());
    progress(invocation, "aws_identity", json!({"account_id": account}));

    // A resumed request first reads the attempt it reached. Once that attempt saved or ended, the
    // rerun reports it and never sends the request again: a server that did not record this
    // request against the attempt it resumed would otherwise read it as new.
    if let Some(id) = &args.attempt {
        result.attempt_id = Some(id.clone());
        let attempt = call(invocation, deadline, |timeout_ms| {
            Command::CloudConnectStatus {
                attempt_id: Some(id.clone()),
                timeout_ms,
            }
        })?;
        if matches!(
            attempt["state"].as_str(),
            Some("saved" | "expired" | "cancelled")
        ) {
            return poll(invocation, deadline, result, attempt, id, &account);
        }
    }

    let body = CloudConnectEnsure {
        source: args.source.slug().into(),
        reconnect: args.reconnect,
        restart: args.restart,
        metrics: args.metrics,
        client_request_id,
        observed_aws_account_id: account.clone(),
    };
    let mut attempt = call(invocation, deadline, |timeout_ms| {
        Command::CloudConnectEnsure {
            body: body.clone(),
            timeout_ms,
        }
    })?;
    result.state = string(&attempt, "state").map(str::to_owned);
    result.web_url = web_url(&attempt).or(result.web_url.take());
    if let Some(id) = string(&attempt, "attempt_id").filter(|id| cloud_uuid(id)) {
        result.attempt_id = Some(id.to_owned());
    }
    // The predecessor this request ended on restart is over and never saved, whatever became of
    // the attempt it opened: report it on every reply, a saved readback included.
    if let Some(cleanup) = ended_cleanup(
        &attempt,
        args.profile.as_deref(),
        Reply::Ensure,
        invocation.output_mode,
    ) {
        result.cleanup = Some(cleanup);
    }
    match attempt["state"].as_str() {
        Some("connected" | "saved") => return Ok(()),
        Some("web_open") => {
            return Err(Failure::new(
                "continue_on_web",
                "Continue the open setup in the Ottto web app.",
                "use_web",
            ))
        }
        _ => {}
    }
    let id = string(&attempt, "attempt_id")
        .filter(|id| cloud_uuid(id))
        .ok_or_else(invalid_server)?
        .to_owned();
    result.attempt_id = Some(id.clone());
    if attempt["account_id"] != account {
        return Err(Failure::new(
            "account_mismatch",
            "Sign in to the AWS account for this setup.",
            "restart",
        ));
    }
    progress(
        invocation,
        "attempt_ready",
        json!({"attempt_id": id, "account_id": account}),
    );
    // A failure only a restart fixes is reported before any AWS work.
    if matches!(
        attempt["state"].as_str(),
        Some("cli_pending" | "cli_failed")
    ) && attempt["next_action"] != "restart"
    {
        let methods = attempt["approval_methods"]
            .as_array()
            .filter(|methods| !methods.is_empty())
            .ok_or_else(|| {
                Failure::new(
                    "no_approval_method",
                    "Set up Touch ID or a passkey to approve cloud setup.",
                    "use_web",
                )
            })?;
        if !methods
            .iter()
            .all(|method| method == "mac" || method == "browser")
        {
            return Err(invalid_server());
        }
        let native = methods.iter().any(|method| method == "mac");
        let mut plan: Plan =
            serde_json::from_value(attempt["aws"].take()).map_err(|_| invalid_server())?;
        plan.check(args.metrics)?;
        let plan_lines = plan_lines(&attempt, args.metrics);
        let revision = attempt["input_revision"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or_else(invalid_server)?;
        progress(
            invocation,
            "plan",
            json!({
                "stack_name": plan.stack_name, "account_id": account, "metrics": args.metrics,
                "where": if native { "mac" } else { "browser" }, "plan": plan_lines,
            }),
        );
        if invocation.output_mode == OutputMode::Human {
            println!("Connect Amazon Bedrock billing to Ottto");
            println!("Workspace    {}", plan.workspace());
            println!("AWS account  {}", display_account(&account));
            if let Some(profile) = &args.profile {
                println!("AWS profile  {profile}");
            }
            println!(
                "In AWS       Creates stack {} in us-east-1 with one read-only role.",
                plan.stack_name
            );
            for line in &plan_lines {
                println!("{}", sanitize_for_terminal(line));
            }
            println!(
                "{}",
                if native {
                    "Next, approve saving with Touch ID."
                } else {
                    "Next, approve saving with your browser passkey."
                }
            );
        }
        let stack = Reconcile {
            aws: &aws,
            session: &mut session,
            plan: &plan,
            account: &account,
            deadline,
            known_stack: &mut result.known_stack,
        }
        .run(|| {
            progress(
                invocation,
                "stack_creating",
                json!({"stack_name": plan.stack_name}),
            )
        })?;
        progress(invocation, "stack_ready", json!({"attempt_id": id}));
        let body = CloudConnectSubmit {
            input_revision: revision,
            account_id: account.clone(),
            stack_id: stack,
            request_id: new_request_id()?,
        };
        attempt = call(invocation, deadline, |timeout_ms| {
            Command::CloudConnectSubmit {
                attempt_id: id.clone(),
                body: body.clone(),
                timeout_ms,
            }
        })?;
        progress(invocation, "submitted", json!({"attempt_id": id}));
    }
    poll(invocation, deadline, result, attempt, &id, &account)
}

/// The server's plan lines (access, billing reach and usage), else two fixed lines from an
/// older server.
fn plan_lines(attempt: &Value, metrics: bool) -> Vec<String> {
    let lines: Vec<String> = attempt["plan"]
        .as_array()
        .map(|lines| {
            lines
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if !lines.is_empty() {
        return lines;
    }
    vec![
        "Ottto reads Bedrock cost. AWS billing access cannot be limited to one service.".into(),
        format!(
            "CloudWatch usage numbers are {}.",
            if metrics { "included" } else { "off" }
        ),
    ]
}

fn check_features(status: &Value) -> Result<(), Failure> {
    let agent = status["agent_connect"].as_object().ok_or_else(|| {
        Failure::new(
            "server_unsupported",
            "This Ottto server does not support command-line setup.",
            "use_web",
        )
    })?;
    if agent.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err(Failure::new(
            "cli_connect_disabled",
            "Command-line setup is unavailable for this workspace.",
            "use_web",
        ));
    }
    if status["signer"] != "available" {
        return Err(Failure::new(
            "signer_unavailable",
            "The release Ottto app is required to connect from this Mac.",
            "use_web",
        ));
    }
    if status["agent_connect"]["keys"]["device"] != true {
        let mut error = Failure::new(
            "keys_not_enrolled",
            "Open Ottto Settings and set up command-line connect.",
            "set_up_on_mac",
        );
        error.reason = string(&status["agent_connect"]["keys"], "reason").map(Into::into);
        return Err(error);
    }
    Ok(())
}

fn poll(
    invocation: &Invocation,
    deadline: Instant,
    result: &mut ResultState,
    mut attempt: Value,
    id: &str,
    account: &str,
) -> Result<(), Failure> {
    let mut last_stage = String::new();
    let mut last_approval = Value::Null;
    let mut approved = false;
    loop {
        let state = string(&attempt, "state").ok_or_else(invalid_server)?;
        if attempt["account_id"] != account {
            return Err(Failure::new(
                "account_mismatch",
                "The setup is for a different AWS account.",
                "restart",
            ));
        }
        result.state = Some(state.into());
        let stage = match state {
            "saved" | "connected" => return Ok(()),
            "cli_failed" | "cancelled" | "expired" => {
                // The service's own cancel after a declined approval is a settling write; any
                // other reply here is a read, which may race a save.
                let reply = if state == "cancelled" && attempt["code"] == "approval_declined" {
                    Reply::Settled
                } else {
                    Reply::Read
                };
                let profile = result.profile.as_deref();
                if let Some(cleanup) =
                    ended_cleanup(&attempt, profile, reply, invocation.output_mode)
                {
                    result.cleanup = Some(cleanup);
                }
                let code = string(&attempt, "code").unwrap_or(state);
                let message = string(&attempt, "message")
                    .unwrap_or("Cloud setup ended. Run the command again.");
                let action = if attempt["next_action"] == "restart" {
                    "restart"
                } else {
                    "run_again"
                };
                return Err(normalize_error(Failure::new(code, message, action)));
            }
            "cli_pending" => {
                return Err(Failure::new(
                    "attempt_changed",
                    "The setup changed. Run the command again.",
                    "run_again",
                ))
            }
            "cli_ready" => {
                if !approved && (attempt["approval_accepted"] == true || last_approval.is_object())
                {
                    approved = true;
                    progress(invocation, "approved", json!({"attempt_id": id}));
                }
                if approved {
                    "saving"
                } else {
                    "checking_access"
                }
            }
            "cli_approval" => {
                if attempt["next_action"] == "use_web" {
                    return Err(Failure::new(
                        "no_approval_method",
                        "Approve cloud setup on the Ottto website.",
                        "use_web",
                    ));
                }
                let local = &attempt["local_approval"];
                if local.is_object() && *local != last_approval {
                    last_approval = local.clone();
                    result.browser_url = string(local, "browser_url").map(str::to_owned);
                    progress(invocation, "approval_required", local.clone());
                    if invocation.output_mode == OutputMode::Human {
                        if local["where"] == "mac" {
                            println!(
                                "Approve saving this connection in the Ottto app with Touch ID."
                            );
                        }
                        if let Some(url) = &result.browser_url {
                            println!("Approve with a passkey at {url}");
                        }
                    }
                }
                "approval_required"
            }
            _ => return Err(invalid_server()),
        };
        if stage != last_stage && stage != "approval_required" {
            progress(invocation, stage, json!({"attempt_id": id}));
        }
        last_stage = stage.into();
        let mut delay = POLL_INTERVAL;
        loop {
            if let Err(error) = sleep_until(deadline, delay) {
                return Err(approval_timeout(result, error));
            }
            match call(invocation, deadline, |timeout_ms| {
                Command::CloudConnectPoll {
                    attempt_id: id.into(),
                    observed_aws_account_id: account.into(),
                    timeout_ms,
                }
            }) {
                Ok(value) => {
                    attempt = value;
                    break;
                }
                Err(error) if error.retry_after_seconds.is_some() => {
                    delay =
                        Duration::from_secs(error.retry_after_seconds.unwrap_or(3).clamp(1, 1200));
                }
                Err(error) => return Err(approval_timeout(result, error)),
            }
        }
    }
}

fn approval_timeout(result: &ResultState, error: Failure) -> Failure {
    if error.code == "timed_out"
        && result.state.as_deref() == Some("cli_approval")
        && result.browser_url.is_some()
    {
        return Failure::new(
            "approval_required",
            "Approve saving your connection in the browser.",
            "approve_in_browser",
        );
    }
    error
}

/// How a reply was produced, which decides whether its cleanup material is final.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// R1: may name the predecessor this request ended on restart.
    Ensure,
    /// A cancel write, which settles the attempt under the server's lock first.
    Settled,
    /// A plain read. It can report a lapsed attempt as `expired` while a save is still
    /// committing, so it never yields a delete command.
    Read,
}

/// A delete command or note for a stack only when a settling write says its attempt ended without
/// saving: in an ensure reply, the predecessor it ended on restart (another attempt); in a cancel
/// reply, the attempt itself once `expired` or `cancelled`. A read of an ended attempt points at
/// `ottto cloud cancel`, which settles it and then names the stack if it never saved.
fn ended_cleanup(
    value: &Value,
    profile: Option<&str>,
    reply: Reply,
    mode: OutputMode,
) -> Option<Value> {
    let reference: CleanupReference =
        serde_json::from_value(value["ended_attempt_cleanup"].clone()).ok()?;
    let own = value["attempt_id"].as_str() == Some(reference.attempt_id.as_str());
    let ended = matches!(value["state"].as_str(), Some("expired" | "cancelled"));
    match reply {
        Reply::Ensure if !own => reference.output(profile),
        Reply::Settled if own && ended => reference.output(profile),
        Reply::Read if own && ended && cloud_uuid(&reference.attempt_id) => {
            let mut argv: Vec<String> = ["ottto", "cloud", "cancel", "--attempt"]
                .into_iter()
                .map(str::to_owned)
                .collect();
            argv.push(reference.attempt_id);
            add_output_flags(&mut argv, mode);
            Some(json!({
                "verified": false,
                "message": "To delete this setup's AWS stack, first confirm it ended without saving.",
                "settle_argv": argv,
            }))
        }
        _ => None,
    }
}

/// The connections page the service built from the web origin paired with its Ottto API.
fn web_url(value: &Value) -> Option<String> {
    string(value, "connect_url")
        .filter(|url| url.starts_with("https://"))
        .map(str::to_owned)
}

/// Whether the outcome closed the attempt this request read, so a rerun must ask for a new one.
fn ends_attempt(error: &Failure, state: Option<&str>) -> bool {
    error.next_action == "restart"
        || matches!(state, Some("expired" | "cancelled" | "saved"))
        || matches!(
            error.code.as_str(),
            "expired" | "cancelled" | "approval_declined"
        )
}

fn new_request_id() -> Result<String, Failure> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| Failure::new("internal", "Could not create a request ID.", "none"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn normalize_error(mut error: Failure) -> Failure {
    if error.code == "use_web" {
        if let Some(reason) = &error.reason {
            error.code = reason.to_string();
        }
    }
    let action = match error.code.as_str() {
        "invalid_input" | "invalid_argument" | "aws_profile_invalid" | "reconnect_required" => {
            "fix_flags"
        }
        "not_org_admin" | "support_mode_blocked" => "ask_admin",
        "keys_not_enrolled" => "set_up_on_mac",
        "attempt_bound_elsewhere" | "account_changes_exhausted" => "none",
        "expired" | "cancelled" | "approval_declined" | "attempt_changed" => "run_again",
        "stack_mismatch"
        | "stack_failed"
        | "account_mismatch"
        | "aws_account_changed"
        | "attempt_replaced"
        | "use_restart"
        | "approval_limit_reached"
        | "request_id_reused" => "restart",
        "aws_template_unverified" | "continue_on_web" => "use_web",
        "rate_limited" | "timed_out" | "connect_busy" | "connect_unavailable" => "run_again",
        code if code.ends_with("_limit_reached") => "run_again",
        _ => match error.next_action.as_str() {
            "wait" | "fix_and_resubmit" | "resubmit" => "run_again",
            other => other,
        },
    };
    error.next_action = action.into();
    error
}

fn exit_code(error: &Failure) -> i32 {
    // Codes shared with the local control errors keep their exit codes.
    if let Ok(code) = serde_json::from_value::<CliErrorCode>(json!(error.code)) {
        return code.exit_code();
    }
    match error.code.as_str() {
        "server_unreachable" => 14,
        "server_unavailable" => 16,
        "invalid_server_field" | "device_proof_invalid" | "setup_run_token_invalid" => 17,
        "stack_timeout" | "rate_limited" | "connect_busy" | "connect_unavailable" => 61,
        // Approval attempts end with the attempt: restart instead of waiting.
        "approval_limit_reached" => 60,
        code if code.ends_with("_limit_reached") => 61,
        _ => match error.next_action.as_str() {
            "fix_flags" => 2,
            "ask_admin" | "fix_aws_permissions" => 50,
            _ => 60,
        },
    }
}

pub(super) fn valid_attempt(value: &str) -> Result<String, String> {
    cloud_uuid(value)
        .then(|| value.into())
        .ok_or_else(|| "use the attempt UUID from cloud status".into())
}

pub(super) fn valid_request_id(value: &str) -> Result<String, String> {
    ((1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
    .then(|| value.into())
    .ok_or_else(|| "use the request ID from the resume command".into())
}

/// The rerun command. With `request_id` it repeats the original request exactly (including
/// `--restart`) and names the attempt it reached, so the rerun settles on that attempt. Without
/// it, it asks for a new attempt, restarting when `next_action` says so.
fn resume(
    args: &CloudConnectArgs,
    mode: OutputMode,
    error: &Failure,
    request_id: Option<&str>,
    attempt_id: Option<&str>,
) -> Vec<String> {
    let restart = error.next_action == "restart";
    let mut argv: Vec<String> = ["ottto", "cloud", "connect", "--source", args.source.slug()]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if args.metrics {
        argv.push("--metrics".into());
    }
    if args.reconnect {
        argv.push("--reconnect".into());
    }
    if restart || (args.restart && request_id.is_some()) {
        argv.push("--restart".into());
    }
    if let Some(profile) = args
        .profile
        .as_deref()
        .filter(|name| aws::profile_valid(name))
    {
        argv.push(format!("--profile={profile}"));
    }
    if args.timeout != 1200 {
        argv.extend(["--timeout".into(), args.timeout.to_string()]);
    }
    if args.verbose {
        argv.push("--verbose".into());
    }
    if let Some(id) = request_id.filter(|_| !restart) {
        argv.push(format!("--request-id={id}"));
        // The rerun reads this attempt first and stops if it already saved or ended.
        if let Some(attempt) = attempt_id.or(args.attempt.as_deref()) {
            argv.push(format!("--attempt={attempt}"));
        }
    }
    add_output_flags(&mut argv, mode);
    argv
}

fn add_output_flags(argv: &mut Vec<String>, mode: OutputMode) {
    if mode != OutputMode::Human {
        argv.push("--json".into());
    }
    if mode == OutputMode::Ndjson {
        argv.push("--watch".into());
    }
}

fn progress(invocation: &Invocation, stage: &str, detail: Value) {
    if invocation.output_mode == OutputMode::Ndjson {
        println!(
            "{}",
            compact_json(&json!({
                "event": "progress", "request_id": invocation.request.request_id,
                "schema_version": SCHEMA, "stage": stage, "detail": detail,
            }))
        );
    }
}

fn remaining(deadline: Instant) -> Result<Duration, Failure> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(timed_out());
    }
    Ok(left)
}

fn sleep_until(deadline: Instant, interval: Duration) -> Result<(), Failure> {
    std::thread::sleep(remaining(deadline)?.min(interval));
    remaining(deadline).map(|_| ())
}

fn timed_out() -> Failure {
    Failure::new(
        "timed_out",
        "Cloud setup is still in progress. Run the same command again to resume.",
        "run_again",
    )
}

fn invalid_server() -> Failure {
    Failure::new(
        "invalid_server_field",
        "A cloud setup response contained an invalid field.",
        "none",
    )
}

fn display_account(account: &str) -> String {
    if !ottto_protocol::cloud_account_id(account) {
        return account.to_owned();
    }
    format!("{} {} {}", &account[..4], &account[4..8], &account[8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    fn connect_args(extra: &[&str]) -> CloudConnectArgs {
        let mut argv = vec!["ottto", "cloud", "connect", "--source", "bedrock"];
        argv.extend_from_slice(extra);
        let cli = Cli::try_parse_from(argv).unwrap();
        let crate::Command::Cloud(cloud) = cli.command else {
            panic!("cloud command");
        };
        let CloudCommand::Connect(args) = cloud.command else {
            panic!("connect command");
        };
        args
    }

    #[test]
    fn cloud_resume_repeats_a_sent_request_until_the_attempt_ends() {
        let args = connect_args(&["--metrics", "--reconnect", "--restart", "--profile", "work"]);
        // A lost reply or a wait: the same request and flags read the same attempt back.
        let waiting = timed_out();
        assert!(!ends_attempt(&waiting, Some("cli_approval")));
        let attempt = "00000000-0000-4000-8000-000000000001";
        assert_eq!(
            resume(
                &args,
                OutputMode::Ndjson,
                &waiting,
                Some("req.1"),
                Some(attempt)
            ),
            [
                "ottto",
                "cloud",
                "connect",
                "--source",
                "bedrock",
                "--metrics",
                "--reconnect",
                "--restart",
                "--profile=work",
                "--request-id=req.1",
                "--attempt=00000000-0000-4000-8000-000000000001",
                "--json",
                "--watch",
            ]
        );
        // The rerun parses, and names the attempt again even before its reply arrives.
        let flag = format!("--attempt={attempt}");
        let rerun = connect_args(&["--request-id=req.1", flag.as_str()]);
        assert_eq!(rerun.attempt.as_deref(), Some(attempt));
        assert!(resume(&rerun, OutputMode::Human, &waiting, Some("req.1"), None).contains(&flag));
        // An attempt without its request is refused.
        let argv = [
            "ottto",
            "cloud",
            "connect",
            "--source",
            "bedrock",
            flag.as_str(),
        ];
        assert!(Cli::try_parse_from(argv).is_err());
        // Before any request was sent the flags stay as given.
        assert!(resume(&args, OutputMode::Human, &waiting, None, None)
            .iter()
            .all(|arg| !arg.starts_with("--request-id") && !arg.starts_with("--attempt")));

        // A restart asks for a new attempt.
        let restart = normalize_error(Failure::new("stack_failed", "Failed.", "restart"));
        assert!(ends_attempt(&restart, Some("cli_failed")));
        let argv = resume(&args, OutputMode::Json, &restart, None, Some(attempt));
        assert!(argv.iter().any(|arg| arg == "--restart"));
        assert!(argv.iter().all(|arg| !arg.starts_with("--attempt")));
        assert!(argv.iter().all(|arg| !arg.starts_with("--request-id")));

        // An ended attempt runs again as a new request without --restart.
        let ended = normalize_error(Failure::new("expired", "Expired.", "restart"));
        assert_eq!(ended.next_action, "run_again");
        assert!(ends_attempt(&ended, Some("expired")));
        let argv = resume(&args, OutputMode::Json, &ended, None, None);
        assert!(argv.iter().all(|arg| arg != "--restart"));

        // A resumable failure keeps the request so the stack is reused.
        let failed = normalize_error(Failure::new("access_check_failed", "Failed.", "run_again"));
        assert!(!ends_attempt(&failed, Some("cli_failed")));
    }

    #[test]
    fn exhausted_approvals_restart_instead_of_resuming() {
        let error = normalize_error(Failure::new(
            "approval_limit_reached",
            "Too many approvals.",
            "run_again",
        ));
        assert_eq!(error.next_action, "restart");
        assert_eq!(exit_code(&error), 60);
        let reused = normalize_error(Failure::new("request_id_reused", "Reused.", "none"));
        assert_eq!(reused.next_action, "restart");
        let other = normalize_error(Failure::new("cli_limit_reached", "Later.", "wait"));
        assert_eq!(other.next_action, "run_again");
        assert_eq!(exit_code(&other), 61);
    }

    #[test]
    fn delete_commands_only_name_stacks_a_settling_write_ended_unsaved() {
        let id = "00000000-0000-4000-8000-000000000001";
        let arn = "arn:aws:cloudformation:us-east-1:000000000001:stack/ottto-read-b-abcde234/00000000-0000-0000-0000-000000000001";
        let reply = |state: &str, owner: &str, stack_id: Value| {
            json!({
                "attempt_id": id,
                "state": state,
                "ended_attempt_cleanup": {
                    "attempt_id": owner, "stack_name": "ottto-read-b-abcde234",
                    "account_id": "000000000001", "stack_id": stack_id,
                },
            })
        };
        let cleanup = |value: &Value, kind| ended_cleanup(value, None, kind, OutputMode::Json);
        // A cancel reply settles the attempt first: only then does an ended state name the stack.
        for state in ["cancelled", "expired"] {
            let settled = cleanup(&reply(state, id, json!(arn)), Reply::Settled).unwrap();
            assert_eq!(settled["argv"][4], arn);
        }
        // A failed attempt can still be resumed and saved with this stack.
        assert!(cleanup(&reply("cli_failed", id, json!(arn)), Reply::Settled).is_none());
        assert!(cleanup(&reply("saved", id, json!(arn)), Reply::Settled).is_none());
        // Without an ARN the user gets the stack, account and region only.
        let unknown = cleanup(&reply("expired", id, Value::Null), Reply::Settled).unwrap();
        assert!(unknown.get("argv").is_none());
        // An ensure reply names a predecessor it ended; its own attempt is still open.
        let other = "00000000-0000-4000-8000-000000000002";
        assert!(cleanup(&reply("cli_pending", other, json!(arn)), Reply::Ensure).is_some());
        assert!(cleanup(&reply("saved", other, json!(arn)), Reply::Ensure).is_some());
        assert!(cleanup(&reply("expired", id, json!(arn)), Reply::Ensure).is_none());
        // A read never names a predecessor either.
        assert!(cleanup(&reply("cli_pending", other, json!(arn)), Reply::Read).is_none());
    }

    /// [behaviour] The save that commits just after the attempt lapsed: a read in between reports
    /// `expired` with the stack ARN. It points at the settling cancel, whose reply then reads
    /// `saved`, so no delete command ever names the connected stack.
    #[test]
    fn a_save_racing_expiry_never_gets_a_delete_command() {
        let id = "00000000-0000-4000-8000-000000000001";
        let arn = "arn:aws:cloudformation:us-east-1:000000000001:stack/ottto-read-b-abcde234/00000000-0000-0000-0000-000000000001";
        let material = json!({
            "attempt_id": id, "stack_name": "ottto-read-b-abcde234",
            "account_id": "000000000001", "stack_id": arn,
        });
        let lapsed = json!({"attempt_id": id, "state": "expired", "code": "expired",
            "next_action": "restart", "ended_attempt_cleanup": material});
        for mode in [OutputMode::Human, OutputMode::Ndjson] {
            let read = ended_cleanup(&lapsed, Some("work"), Reply::Read, mode).unwrap();
            assert!(read.get("argv").is_none(), "{read}");
            assert_eq!(read["verified"], false);
            let settle = argv_line(&read["settle_argv"]).unwrap();
            assert!(settle.starts_with(&format!("ottto cloud cancel --attempt {id}")));
            assert_eq!(
                settle.ends_with("--json --watch"),
                mode == OutputMode::Ndjson
            );
        }
        // The worker's save committed before the cancel took the row: no cleanup.
        let saved = json!({"attempt_id": id, "state": "saved", "ended_attempt_cleanup": null});
        assert!(ended_cleanup(&saved, None, Reply::Settled, OutputMode::Human).is_none());
        // Or the cancel persisted the expiry first, and the stack is safe to delete.
        let ended =
            ended_cleanup(&lapsed, Some("work"), Reply::Settled, OutputMode::Human).unwrap();
        assert_eq!(ended["argv"][4], arn);
        // A lapsed attempt asks for a fresh request, never a restart that would end another.
        let error = normalize_error(Failure::new("expired", "Expired.", "restart"));
        assert_eq!(error.next_action, "run_again");
    }

    #[test]
    fn web_links_use_only_the_paired_origin_the_service_sent() {
        let staging = "https://staging.tail21f014.ts.net/connections";
        let mut result = ResultState {
            web_url: web_url(&json!({"connect_url": staging})),
            ..ResultState::default()
        };
        let fallback = Failure::new("signer_unavailable", "Use the web.", "use_web");
        assert_eq!(
            result.connect_url("use_web", Some(&fallback)),
            Some(staging)
        );
        let mut sent = fallback.clone();
        sent.connect_url = Some(staging.into());
        result.web_url = None;
        assert_eq!(result.connect_url("use_web", Some(&sent)), Some(staging));
        // No paired origin known: the message alone, never a production link.
        assert_eq!(result.connect_url("use_web", Some(&fallback)), None);
        assert_eq!(
            web_url(&json!({"connect_url": "http://app.ottto.net"})),
            None
        );
        assert_eq!(result.connect_url("run_again", Some(&sent)), None);
    }

    #[test]
    fn plan_text_comes_from_the_server_with_a_fixed_fallback() {
        let server = json!({"plan": ["Access note.", "Covers all linked accounts.", "Usage."]});
        assert_eq!(
            plan_lines(&server, false),
            ["Access note.", "Covers all linked accounts.", "Usage."]
        );
        let fallback = plan_lines(&json!({"plan": null}), true);
        assert_eq!(fallback.len(), 2);
        assert!(fallback[1].contains("included"));
        assert_eq!(plan_lines(&json!({"plan": []}), false).len(), 2);
    }

    #[test]
    fn cloud_feature_refusals_keep_the_exit_contract() {
        let unsupported = check_features(&json!({})).unwrap_err();
        assert_eq!(unsupported.code, "server_unsupported");
        assert_eq!(exit_code(&unsupported), 60);
        let missing_key = check_features(&json!({
            "signer": "available",
            "agent_connect": {"enabled": true, "keys": {"device": false, "reason": "revoked"}},
        }))
        .unwrap_err();
        assert_eq!(missing_key.next_action, "set_up_on_mac");
        assert_eq!(missing_key.reason.as_deref(), Some("revoked"));
        assert_eq!(exit_code(&timed_out()), 61);
        assert_eq!(exit_code(&invalid_server()), 17);
    }
}
