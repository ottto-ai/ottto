//! Terminal-only one-time handoff. This path never constructs a normal CLI
//! invocation, creates a control token, initializes state or starts a daemon.
use ottto_protocol::{
    CliErrorCode, LocalClientKind, LocalControlCommand, LocalControlRequest, LocalControlResponse,
    SecretString, SessionLaunchConsumeResultV1, SessionLaunchStateV1,
};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[arg(long = "exec", required = true)]
    exec: bool,
    launch_id: String,
    #[arg(value_parser = parse_secret)]
    secret: SecretString,
}

fn parse_secret(value: &str) -> Result<SecretString, String> {
    Ok(SecretString::new(value))
}

fn request(command: LocalControlCommand, token: &str) -> LocalControlRequest {
    LocalControlRequest {
        request_id: super::request_id(),
        protocol_version: ottto_protocol::SESSION_LAUNCH_CONTROL_PROTOCOL_VERSION,
        token: Some(token.into()),
        client_kind: Some(LocalClientKind::Cli),
        client_install_owner: None,
        command,
    }
}

pub(crate) fn run(args: &Args, socket: PathBuf, token: Option<&str>) -> i32 {
    let token = match token
        .map(str::to_owned)
        .map(Ok)
        .unwrap_or_else(ottto_core::client_control_token)
    {
        Ok(token) => token,
        Err(_) => {
            eprintln!("Ottto daemon is unavailable for session launch.");
            return CliErrorCode::DaemonUnavailable.exit_code();
        }
    };
    let command = LocalControlCommand::SessionLaunchConsume {
        schema_version: 1,
        launch_id: args.launch_id.clone(),
        secret: args.secret.clone(),
    };
    let response = match ottto_core::request_unix_socket_with_timeout(
        &socket,
        &request(command, &token),
        std::time::Duration::from_secs(10),
    ) {
        Ok(response) => response,
        Err(_) => {
            eprintln!("Ottto daemon is unavailable for session launch.");
            return CliErrorCode::DaemonUnavailable.exit_code();
        }
    };
    execute(
        response,
        |plan| ottto_core::session_launch::execute_launch_plan(plan),
        |attempt, reason| {
            let command = LocalControlCommand::SessionLaunchReport {
                schema_version: 1,
                launch_id: args.launch_id.clone(),
                attempt_id: attempt,
                reason,
            };
            let _ = ottto_core::request_unix_socket_with_timeout(
                &socket,
                &request(command, &token),
                std::time::Duration::from_secs(3),
            );
        },
    )
}

fn execute(
    response: LocalControlResponse,
    executor: impl FnOnce(
        &ottto_protocol::SessionLaunchExecPlanV1,
    ) -> ottto_protocol::SessionLaunchBlockReasonV1,
    report: impl FnOnce(SecretString, ottto_protocol::SessionLaunchBlockReasonV1),
) -> i32 {
    if !response.ok {
        eprintln!("Ottto refused the session handoff.");
        return response
            .error
            .map(|error| error.code.exit_code())
            .unwrap_or(2);
    }
    let result = response
        .payload
        .and_then(|payload| serde_json::from_value::<SessionLaunchConsumeResultV1>(payload).ok());
    let Some(result) = result else {
        eprintln!("Ottto returned an unsupported session handoff.");
        return 2;
    };
    if result.state != Some(SessionLaunchStateV1::Starting) {
        let reason = result.block.map(|block| block.reason).unwrap_or_default();
        // Typed enum only: never echo a folder, secret, settings value or
        // daemon-supplied message to the terminal.
        eprintln!(
            "Session launch blocked: {}",
            serde_json::to_value(reason)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into())
        );
        return CliErrorCode::NeedsUserAction.exit_code();
    }
    let (Some(plan), Some(attempt)) = (result.plan, result.attempt_id) else {
        return 2;
    };
    let reason = executor(&plan);
    report(attempt, reason);
    eprintln!("Session launch failed before the agent could start.");
    CliErrorCode::NeedsUserAction.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_state_never_executes_and_failure_reports_exact_attempt() {
        let response = |payload| LocalControlResponse {
            request_id: "one".into(),
            ok: true,
            payload: Some(payload),
            error: None,
        };
        assert_eq!(
            execute(
                response(serde_json::json!({"state":"future"})),
                |_| panic!("must not execute"),
                |_, _| panic!("must not report")
            ),
            60
        );
        let code = execute(
            response(serde_json::json!({"state":"starting","plan":{},"attempt_id":"attempt"})),
            |_| ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed,
            |attempt, reason| {
                assert_eq!(attempt.expose_secret(), "attempt");
                assert_eq!(
                    reason,
                    ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed
                );
            },
        );
        assert_eq!(code, 60);
    }
}
