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
        ottto_core::session_launch::execute_launch_plan,
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
    let Some(attempt) = result.attempt_id else {
        return 2;
    };
    let complete = result.plan.as_ref().is_some_and(|plan| {
        plan.program
            .as_ref()
            .is_some_and(|path| std::path::Path::new(path).is_absolute())
            && plan
                .cwd
                .as_ref()
                .is_some_and(|path| std::path::Path::new(path).is_absolute())
            && plan.argv.is_some()
            && plan.cwd_dev.is_some()
            && plan.cwd_ino.is_some()
            && plan.env_unset.is_some()
            && plan.env_set.is_some()
    });
    if !complete {
        report(
            attempt,
            ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed,
        );
        eprintln!("Ottto returned an unsupported session handoff.");
        return 2;
    }
    let plan = result.plan.expect("complete plan checked");
    let reason = executor(&plan);
    report(attempt, reason);
    eprintln!("Session launch failed before the agent could start.");
    CliErrorCode::NeedsUserAction.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_check_is_hidden_requires_exec_and_has_no_autostart_invocation() {
        use clap::{CommandFactory, Parser};
        assert!(!super::super::Cli::command()
            .render_help()
            .to_string()
            .contains("launch-check"));
        assert!(
            super::super::Cli::try_parse_from(["ottto", "launch-check", "id", "secret"]).is_err()
        );
        let args = Args {
            exec: true,
            launch_id: "synthetic-id".into(),
            secret: SecretString::new("synthetic-secret"),
        };
        let missing =
            std::env::temp_dir().join(format!("missing-launch-socket-{}", std::process::id()));
        assert!(!missing.exists());
        assert_eq!(
            run(&args, missing.join("socket"), Some("synthetic-control")),
            10
        );
        assert!(!missing.exists());
        let request = request(
            LocalControlCommand::SessionLaunchConsume {
                schema_version: 1,
                launch_id: args.launch_id,
                secret: args.secret,
            },
            "synthetic-control",
        );
        assert_eq!(request.protocol_version, 28);
        assert_eq!(request.client_kind, Some(LocalClientKind::Cli));
        assert!(!format!("{request:?}").contains("synthetic-secret"));
    }
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
            response(
                serde_json::json!({"state":"starting","plan":{"program":"/agent","argv":[],"cwd":"/project","cwd_dev":1,"cwd_ino":1,"env_unset":[],"env_set":{}},"attempt_id":"attempt"}),
            ),
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
        let code = execute(
            response(
                serde_json::json!({"state":"starting","plan":{},"attempt_id":"malformed-attempt"}),
            ),
            |_| panic!("incomplete plans must not reach the executor"),
            |attempt, reason| {
                assert_eq!(attempt.expose_secret(), "malformed-attempt");
                assert_eq!(
                    reason,
                    ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed
                );
            },
        );
        assert_eq!(code, 2);
    }
}
