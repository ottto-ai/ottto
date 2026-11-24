//! Cloud setup orchestration and CLI output.

mod aws;
mod stack;

use self::aws::{Aws, Session};
use self::stack::{cleanup, CleanupReference, Plan, Reconcile};
use crate::{
    compact_json, final_payload_event, pretty_json, sanitize_for_terminal, CloudCommand,
    CloudConnectArgs, CloudStatusArgs, Invocation, OutputMode,
};
use ottto_core::{kickstart_macos_launch_agent, request_unix_socket_with_timeout};
use ottto_protocol::{
    cloud_uuid, expected_local_control_protocol_version, CliError, CliErrorCode,
    CloudConnectEnsure, CloudConnectFailure as Failure, CloudConnectSubmit,
    LocalControlCommand as Command, CLOUD_CONNECT_WEB_URL,
};
use serde_json::{json, Value};
use std::sync::mpsc;
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
                    result.cleanup = cleanup_from(&value, None, deadline);
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
            let resume = error
                .as_ref()
                .map(|error| resume(&args, invocation.output_mode, &error.next_action));
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
            match reply {
                Ok(value) => {
                    result.account_id = string(&value, "account_id").map(str::to_owned);
                    result.state = string(&value, "state").map(str::to_owned);
                    if value["ended_attempt_cleanup"].is_object() {
                        // Cancellation succeeds even when AWS is unavailable or signed into a different account.
                        let identity_deadline =
                            deadline.min(Instant::now() + Duration::from_secs(15));
                        let identity = (|| {
                            let aws = Aws::resolve(None, false, identity_deadline).ok()?;
                            let session = aws.export(identity_deadline).ok()?;
                            let account = aws.identity(&session, identity_deadline).ok()?;
                            Some((aws, session, account))
                        })();
                        let identity = identity
                            .as_ref()
                            .map(|(aws, session, account)| (aws, session, account.as_str()));
                        result.cleanup = cleanup_from(&value, identity, identity_deadline);
                    }
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
}

impl ResultState {
    fn finish(
        self,
        invocation: &Invocation,
        error: Option<Failure>,
        resume: Option<Vec<String>>,
        message: Option<&str>,
        status_payload: Option<&Value>,
    ) -> i32 {
        let exit_code = error.as_ref().map_or(0, exit_code);
        let cleanup = self.cleanup.or_else(|| {
            let account = self.account_id.as_deref()?;
            let arn = self.known_stack.as_deref()?;
            error.as_ref().map(|_| cleanup(account, arn))
        });
        let action = error
            .as_ref()
            .map_or("none", |error| error.next_action.as_str());
        let message = error.as_ref().map_or_else(
            || message.unwrap_or_default(),
            |error| error.message.as_str(),
        );
        let connect_url = if action == "approve_in_browser" {
            self.browser_url.as_deref()
        } else if action == "use_web" {
            Some(CLOUD_CONNECT_WEB_URL)
        } else {
            None
        };
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
            "cleanup": cleanup,
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
                if let Some(id) = self.attempt_id {
                    println!("Attempt      {}", sanitize_for_terminal(&id));
                }
                if let Some(url) = connect_url {
                    println!("{url}");
                }
                if let Some(command) = argv_line(&payload["resume"]["argv"]) {
                    println!("Resume       {command}");
                }
                if let Some(command) = argv_line(&payload["cleanup"]["argv"]) {
                    println!("Cleanup      {command}");
                } else if let Some(message) = payload["cleanup"]["message"].as_str() {
                    println!("{}", sanitize_for_terminal(message));
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
    let mut auto_start = invocation.auto_start;
    let mut booting = false;
    loop {
        let remaining = remaining(deadline)?.min(Duration::from_secs(90));
        let mut request = invocation.request.clone();
        request.command = command(remaining.as_millis().try_into().unwrap_or(90_000));
        request.protocol_version = expected_local_control_protocol_version(&request.command);
        let response =
            match request_unix_socket_with_timeout(&invocation.socket, &request, remaining) {
                Ok(response) => response,
                Err(error) if error.is_connect_failure() && auto_start => {
                    auto_start = false;
                    let (tx, rx) = mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _ = tx.send(kickstart_macos_launch_agent());
                    });
                    match rx.recv_timeout(remaining) {
                        Ok(Ok(())) => booting = true,
                        Err(mpsc::RecvTimeoutError::Timeout) => return Err(timed_out()),
                        _ => return Err(daemon_unavailable()),
                    }
                    continue;
                }
                Err(error) if error.is_connect_failure() && booting => {
                    sleep_until(deadline, Duration::from_millis(500))?;
                    continue;
                }
                Err(error) if error.is_connect_failure() => return Err(daemon_unavailable()),
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    return Err(Failure::new(
                        "server_unreachable",
                        "The Ottto service did not return a response.",
                        "none",
                    ));
                }
            };
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
        return Ok(value);
    }
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
    progress(invocation, "checking_ottto", json!({}));
    let features = call(invocation, deadline, |timeout_ms| {
        Command::CloudConnectStatus {
            attempt_id: None,
            timeout_ms,
        }
    })?;
    check_features(&features)?;

    let verbose = args.verbose
        && invocation.output_mode == OutputMode::Human
        && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let aws = Aws::resolve(args.profile.clone(), verbose, deadline)?;
    let mut session = aws.export(deadline)?;
    let account = aws.identity(&session, deadline)?;
    result.account_id = Some(account.clone());
    progress(invocation, "aws_identity", json!({"account_id": account}));

    let body = CloudConnectEnsure {
        source: args.source.slug().into(),
        reconnect: args.reconnect,
        restart: args.restart,
        metrics: args.metrics,
        client_request_id: new_request_id()?,
        observed_aws_account_id: account.clone(),
    };
    let mut attempt = call(invocation, deadline, |timeout_ms| {
        Command::CloudConnectEnsure {
            body: body.clone(),
            timeout_ms,
        }
    })?;
    result.state = string(&attempt, "state").map(str::to_owned);
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
    if let Some(reference) = cleanup_reference(&attempt)
        && attempt["ended_attempt_cleanup"]["attempt_id"] != id
    {
        result.cleanup = reference.resolve(Some((&aws, &session, &account)), deadline);
    }
    if let Some(error) = attempt
        .as_object_mut()
        .and_then(|attempt| attempt.remove("template_error"))
    {
        return Err(normalize_error(
            serde_json::from_value(error).map_err(|_| invalid_server())?,
        ));
    }
    if matches!(
        attempt["state"].as_str(),
        Some("cli_pending" | "cli_failed")
    ) {
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
        let plan: Plan =
            serde_json::from_value(attempt["aws"].take()).map_err(|_| invalid_server())?;
        plan.check(args.metrics)?;
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
                "where": if native { "mac" } else { "browser" },
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
            println!(
                "Ottto reads Bedrock cost. AWS billing access cannot be limited to one service."
            );
            println!(
                "CloudWatch usage numbers are {}.",
                if args.metrics { "included" } else { "off" }
            );
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
    poll(
        invocation,
        deadline,
        result,
        attempt,
        &id,
        (&aws, &session, &account),
    )
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
        error.reason = string(&status["agent_connect"]["keys"], "reason").map(str::to_owned);
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
    identity: (&Aws, &Session, &str),
) -> Result<(), Failure> {
    let mut last_stage = String::new();
    let mut last_approval = Value::Null;
    let mut approved = false;
    loop {
        let state = string(&attempt, "state").ok_or_else(invalid_server)?;
        if attempt["account_id"] != identity.2 {
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
                if let Some(cleanup) = cleanup_from(&attempt, Some(identity), deadline) {
                    result.cleanup = Some(cleanup);
                }
                let code = string(&attempt, "code").unwrap_or(state);
                let message = string(&attempt, "message")
                    .unwrap_or("Cloud setup ended. Run the command again.");
                return Err(normalize_error(Failure::new(code, message, "run_again")));
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
                    observed_aws_account_id: identity.2.into(),
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

fn cleanup_reference(value: &Value) -> Option<CleanupReference> {
    serde_json::from_value(value["ended_attempt_cleanup"].clone()).ok()
}

fn cleanup_from(
    value: &Value,
    identity: Option<(&Aws, &Session, &str)>,
    deadline: Instant,
) -> Option<Value> {
    cleanup_reference(value)?.resolve(identity, deadline)
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
            error.code.clone_from(reason);
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
        | "use_restart" => "restart",
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
    match error.code.as_str() {
        "internal" => 70,
        "daemon_unavailable" => 10,
        "local_auth_failed" => 11,
        "local_client_not_trusted" => 12,
        "server_unreachable" => 14,
        "server_unavailable" => 16,
        "invalid_server_field" | "device_proof_invalid" | "setup_run_token_invalid" => 17,
        "permission_denied" => 50,
        "timed_out" | "stack_timeout" | "rate_limited" | "connect_busy" | "connect_unavailable" => {
            61
        }
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

fn resume(args: &CloudConnectArgs, mode: OutputMode, next: &str) -> Vec<String> {
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
    if next == "restart" {
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

    #[test]
    fn cloud_resume_keeps_public_options_and_only_restarts_when_needed() {
        let cli = Cli::try_parse_from([
            "ottto",
            "cloud",
            "connect",
            "--source",
            "bedrock",
            "--metrics",
            "--reconnect",
            "--restart",
            "--profile",
            "work",
            "--json",
            "--watch",
        ])
        .unwrap();
        let crate::Command::Cloud(cloud) = cli.command else {
            panic!("cloud command");
        };
        let CloudCommand::Connect(args) = cloud.command else {
            panic!("connect command");
        };
        let argv = resume(&args, OutputMode::Ndjson, "run_again");
        assert_eq!(
            argv,
            [
                "ottto",
                "cloud",
                "connect",
                "--source",
                "bedrock",
                "--metrics",
                "--reconnect",
                "--profile=work",
                "--json",
                "--watch",
            ]
        );
        assert!(resume(&args, OutputMode::Json, "restart")
            .iter()
            .any(|arg| arg == "--restart"));
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
