//! CLI requests use the setup-run token, but only the app can sign a write.
use super::queue::unix_now;
use super::server::{ServerError, SetupRunServer};
use super::template::{verified_template_url_with_timeout, TemplatePin};
use super::wire::{decode_base64url, encode_base64url, proof_header, request_sha256};
use super::{
    queue_sign_request, sign_queue, signer_available, SignKind, SignOutcome, SignQueueError,
};
use crate::control::backend_http::{
    backend_error_from_ureq, backend_response_unexpected, backend_success,
};
use crate::{LocalApiError, LocalDaemon};
use ottto_protocol::{
    cloud_account_id, cloud_stack_name_from_id, cloud_uuid, CloudConnectFailure as Failure,
    CloudTemplatePin, LocalControlCommand as Command, CLOUD_CONNECT_ATTEMPT_SCHEMA,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const ENSURE_TEMPLATE: &str =
    "/api/v1/setup-runs/{setup_run_id}/local-client/cloud/connect-attempts";
const ATTEMPT_TEMPLATE: &str =
    "/api/v1/setup-runs/{setup_run_id}/local-client/cloud/connect-attempts/{attempt_id}";
const SIGN_WAIT: Duration = Duration::from_secs(20);

pub(in crate::control) fn dispatch(daemon: &LocalDaemon, command: Command) -> Value {
    match dispatch_inner(daemon, command) {
        Ok(value) => value,
        Err(error) => json!({"cloud_error": error}),
    }
}

fn dispatch_inner(daemon: &LocalDaemon, command: Command) -> Result<Value, Failure> {
    let server = SetupRunServer { daemon };
    match command {
        Command::CloudConnectStatus {
            attempt_id,
            timeout_ms,
        } => {
            let deadline = deadline(timeout_ms);
            let Some(id) = attempt_id else {
                let status = daemon
                    .status_for_trusted_client()
                    .map_err(|error| server_failure(ServerError::from_local(&error)))?;
                if status.account.state != ottto_protocol::LocalAccountState::Connected {
                    return Err(server_failure(ServerError::local("not_paired")));
                }
                let mut status = server.agent_call(None, "GET", "status", None, None, deadline)?;
                status.as_object_mut().ok_or_else(invalid_server)?.insert(
                    "signer".into(),
                    json!(if signer_available() {
                        "available"
                    } else {
                        "unavailable"
                    }),
                );
                return Ok(status);
            };
            let mut attempt = server.read_attempt(None, &id, deadline)?;
            remove_approval(&mut attempt);
            Ok(attempt)
        }
        Command::CloudConnectEnsure { body, timeout_ms } => {
            if body.source != "bedrock"
                || !cloud_account_id(&body.observed_aws_account_id)
                || !request_id_valid(&body.client_request_id)
            {
                return Err(invalid_argument());
            }
            let deadline = deadline(timeout_ms);
            let mut attempt =
                server.signed_attempt("POST", "ensure", None, Some(&bytes(&body)), deadline)?;
            remove_approval(&mut attempt);
            if let Some(aws) = attempt.get_mut("aws").filter(|aws| !aws.is_null()) {
                match verify_template(aws, deadline) {
                    Ok(url) => aws["url"] = json!(url),
                    Err(error) => {
                        attempt["aws"] = Value::Null;
                        attempt["template_error"] = json!(error);
                    }
                }
            }
            Ok(attempt)
        }
        Command::CloudConnectSubmit {
            attempt_id,
            body,
            timeout_ms,
        } => {
            if !request_id_valid(&body.request_id)
                || body.input_revision > i32::MAX as u32
                || cloud_stack_name_from_id(&body.stack_id, &body.account_id).is_none()
            {
                return Err(invalid_argument());
            }
            let mut attempt = server.signed_attempt(
                "PATCH",
                "submit",
                Some(&attempt_id),
                Some(&bytes(&body)),
                deadline(timeout_ms),
            )?;
            remove_approval(&mut attempt);
            Ok(attempt)
        }
        Command::CloudConnectPoll {
            attempt_id,
            observed_aws_account_id,
            timeout_ms,
        } => {
            if !cloud_account_id(&observed_aws_account_id) {
                return Err(invalid_argument());
            }
            server.poll(&attempt_id, &observed_aws_account_id, deadline(timeout_ms))
        }
        Command::CloudConnectCancel {
            attempt_id,
            timeout_ms,
        } => server.cancel(&attempt_id, deadline(timeout_ms)),
        _ => unreachable!("only cloud connect control commands are dispatched here"),
    }
}

fn deadline(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms.min(90_000))
}

fn remaining(deadline: Instant) -> Result<Duration, Failure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timeout());
    }
    Ok(remaining)
}

fn timeout() -> Failure {
    Failure::new(
        "timed_out",
        "Cloud setup reached its deadline.",
        "run_again",
    )
}

fn invalid_argument() -> Failure {
    Failure::new(
        "invalid_argument",
        "Invalid cloud setup arguments.",
        "fix_flags",
    )
}

fn invalid_server() -> Failure {
    Failure::new(
        "invalid_server_field",
        "Ottto returned an invalid cloud setup response.",
        "none",
    )
}

fn template_unverified() -> Failure {
    Failure::new(
        "aws_template_unverified",
        "The CloudFormation template could not be verified by this release.",
        "use_web",
    )
}

fn check_pin(pin: &CloudTemplatePin) -> Result<(), Failure> {
    if !pin.is_compiled_pin() {
        return Err(template_unverified());
    }
    Ok(())
}

fn verify_template(aws: &Value, deadline: Instant) -> Result<String, Failure> {
    let pin: CloudTemplatePin =
        serde_json::from_value(aws["template"].clone()).map_err(|_| template_unverified())?;
    check_pin(&pin)?;
    let pin = TemplatePin {
        key: pin.key,
        version_id: pin.version_id,
        sha256: pin.sha256,
    };
    verified_template_url_with_timeout(&pin, remaining(deadline)?)
        .map_err(|_| template_unverified())
}

fn request_id_valid(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn bytes(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("cloud requests contain only serializable fields")
}

fn remove_approval(attempt: &mut Value) {
    if let Some(object) = attempt.as_object_mut() {
        object.remove("approval");
    }
}

fn verify_attempt(attempt: Value, id: Option<&str>) -> Result<Value, Failure> {
    if attempt["schema_version"] != CLOUD_CONNECT_ATTEMPT_SCHEMA
        || attempt["source"] != "bedrock"
        || id.is_some_and(|id| attempt["attempt_id"] != id)
    {
        return Err(invalid_server());
    }
    Ok(attempt)
}

fn queue_failure(error: SignQueueError) -> Failure {
    match error {
        SignQueueError::SignerUnavailable => Failure::new(
            "signer_unavailable",
            "Use the release Ottto app to connect from this Mac.",
            "use_web",
        ),
        SignQueueError::Full | SignQueueError::ApprovalRateLimited => Failure::new(
            "rate_limited",
            "The Mac signer is busy. Try again shortly.",
            "run_again",
        ),
        SignQueueError::AlreadyExpired => Failure::new(
            "expired",
            "The signing request expired. Run the command again.",
            "run_again",
        ),
    }
}

fn server_failure(error: ServerError) -> Failure {
    match error.code.as_str() {
        "not_paired" => Failure::new("not_paired", "Pair this Mac with Ottto first.", "pair_mac"),
        "server_unreachable" => {
            Failure::new("server_unreachable", "Could not reach Ottto.", "none")
        }
        "server_unavailable" => Failure::new(
            "server_unavailable",
            "Ottto is temporarily unavailable.",
            "none",
        ),
        "server_timeout" => timeout(),
        "local_error" => Failure::new(
            "internal",
            "The Ottto service could not run cloud setup.",
            "none",
        ),
        _ if error.status == Some(404) => Failure::new(
            "server_unsupported",
            "This Ottto server does not support command-line setup.",
            "use_web",
        ),
        _ => invalid_server(),
    }
}

impl SetupRunServer<'_> {
    fn agent_call(
        &self,
        run: Option<&str>,
        method: &str,
        resource: &str,
        body: Option<&[u8]>,
        proof: Option<&str>,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        let result = self
            .call_bound(run, |prefix, token| {
                let Ok(timeout) = remaining(deadline) else {
                    return Ok(Err(timeout()));
                };
                let url = format!("{prefix}/{resource}");
                let mut request = crate::retry_tls::credential_agent()
                    .request(method, &url)
                    .set("Accept", "application/json")
                    .set("X-Ottto-Setup-Run-Token", token)
                    .timeout(timeout.min(Duration::from_secs(20)));
                if let Some(proof) = proof {
                    request = request.set("X-Ottto-Device-Proof", proof);
                }
                let result = match body {
                    Some(body) => request
                        .set("Content-Type", "application/json")
                        .send_bytes(body),
                    None => request.call(),
                };
                let response = match result {
                    Ok(response) => backend_success(&url, response)?,
                    Err(ureq::Error::Status(status, response)) => {
                        let value: Value = response.into_json().unwrap_or(Value::Null);
                        if value["code"] == "setup_run_token_invalid" && status == 401 {
                            return Err(LocalApiError::Backend(crate::BackendErrorDetails {
                                kind: crate::BackendErrorKind::Rejected,
                                endpoint: resource.to_string(),
                                status: Some(status),
                                body_excerpt: None,
                                reason_code: Some("setup_run_token_invalid".into()),
                            }));
                        }
                        if let Ok(error) = serde_json::from_value::<Failure>(value) {
                            return Ok(Err(error));
                        }
                        return Ok(Err(server_failure(ServerError {
                            code: if status >= 500 {
                                "server_unavailable"
                            } else {
                                "server_rejected"
                            }
                            .into(),
                            status: Some(status),
                            outcome_unknown: status >= 500,
                        })));
                    }
                    Err(error) => return Err(backend_error_from_ureq(&url, error)),
                };
                response
                    .into_json()
                    .map(Ok)
                    .map_err(|error| backend_response_unexpected(&url, error.to_string()))
            })
            .map_err(server_failure)?;
        result
    }

    fn signed_attempt(
        &self,
        method: &str,
        operation: &str,
        attempt_id: Option<&str>,
        body: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        if attempt_id.is_some_and(|id| !cloud_uuid(id)) {
            return Err(invalid_argument());
        }
        if !signer_available() {
            return Err(queue_failure(SignQueueError::SignerUnavailable));
        }
        let run = self.current_run()?;
        let template = if attempt_id.is_some() {
            ATTEMPT_TEMPLATE
        } else {
            ENSURE_TEMPLATE
        };
        let digest = request_sha256(method, template, body.unwrap_or_default());
        let challenge_body = bytes(&json!({
            "operation": operation, "attempt_id": attempt_id, "request_sha256": digest,
        }));
        let resource = attempt_id.map_or_else(
            || "connect-attempts".into(),
            |id| format!("connect-attempts/{id}"),
        );
        for retry in [false, true] {
            let challenge = self.agent_call(
                Some(&run),
                "POST",
                "device-challenges",
                Some(&challenge_body),
                None,
                deadline,
            )?;
            let challenge_id = challenge["challenge_id"]
                .as_str()
                .ok_or_else(invalid_server)?;
            let encoded = challenge["payload_bytes"]
                .as_str()
                .ok_or_else(invalid_server)?;
            let payload = decode_base64url(encoded).ok_or_else(invalid_server)?;
            let facts: Value = serde_json::from_slice(&payload).map_err(|_| invalid_server())?;
            let expiry = facts["exp"].as_i64().ok_or_else(invalid_server)?;
            if !cloud_uuid(challenge_id)
                || facts["v"] != super::wire::DEVICE_WRITE_VERSION
                || facts["challenge_id"] != challenge_id
                || facts["run_id"] != run
                || facts["operation"] != operation
                || facts["attempt_id"] != json!(attempt_id)
                || facts["request_sha256"] != digest
                || expiry <= unix_now()
                || expiry > unix_now() + 60
            {
                return Err(invalid_server());
            }
            let wait = remaining(deadline)?.min(SIGN_WAIT);
            let request = queue_sign_request(SignKind::DeviceProof, payload, expiry)
                .map_err(queue_failure)?;
            let Some(SignOutcome::Signed(signature)) = sign_queue().wait(
                &request,
                wait.min(deadline.saturating_duration_since(Instant::now())),
            ) else {
                sign_queue().cancel(&request);
                remaining(deadline)?;
                return Err(Failure::new(
                    "mac_app_unavailable",
                    "Open the Ottto app and run the command again.",
                    "open_app",
                ));
            };
            let result = self.agent_call(
                Some(&run),
                method,
                &resource,
                body,
                Some(&proof_header(challenge_id, &signature)),
                deadline,
            );
            match result {
                Ok(value) => return verify_attempt(value, attempt_id),
                Err(error)
                    if !retry
                        && matches!(
                            error.code.as_str(),
                            "device_proof_invalid"
                                | "server_unreachable"
                                | "server_unavailable"
                                | "timed_out"
                        ) =>
                {
                    remaining(deadline)?;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the second send settles the request")
    }

    fn current_run(&self) -> Result<String, Failure> {
        self.daemon
            .connection_for_authorized_client()
            .map_err(|error| server_failure(ServerError::from_local(&error)))?
            .map(|connection| connection.setup_run_id)
            .ok_or_else(|| server_failure(ServerError::local("not_paired")))
    }

    fn read_attempt(
        &self,
        run: Option<&str>,
        id: &str,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        if !cloud_uuid(id) {
            return Err(invalid_argument());
        }
        let value = self.agent_call(
            run,
            "GET",
            &format!("connect-attempts/{id}"),
            None,
            None,
            deadline,
        )?;
        verify_attempt(value, Some(id))
    }

    fn cancel(&self, id: &str, deadline: Instant) -> Result<Value, Failure> {
        let mut attempt = self.signed_attempt("DELETE", "cancel", Some(id), None, deadline)?;
        sign_queue().cancel_attempt(id);
        remove_approval(&mut attempt);
        Ok(attempt)
    }

    fn poll(&self, id: &str, account: &str, deadline: Instant) -> Result<Value, Failure> {
        let run = self.current_run()?;
        let mut attempt = self.read_attempt(Some(&run), id, deadline)?;
        let approval = attempt
            .as_object_mut()
            .and_then(|value| value.remove("approval"));
        if attempt["account_id"]
            .as_str()
            .is_some_and(|bound| bound != account)
        {
            return Err(account_mismatch());
        }
        if attempt["state"] != "cli_approval" {
            sign_queue().cancel_attempt(id);
            return Ok(attempt);
        }
        let Some(approval) = approval.filter(|approval| !approval.is_null()) else {
            return Ok(attempt);
        };
        let approval_id = approval["approval_id"]
            .as_str()
            .filter(|id| cloud_uuid(id))
            .ok_or_else(invalid_server)?;
        let payload = approval["payload_b64"]
            .as_str()
            .and_then(decode_base64url)
            .ok_or_else(invalid_server)?;
        let facts: Value = serde_json::from_slice(&payload).map_err(|_| invalid_server())?;
        if facts["target"]["id"] != account || attempt["account_id"] != account {
            return Err(account_mismatch());
        }
        let sign_by = approval["sign_by"]
            .as_str()
            .and_then(|date| OffsetDateTime::parse(date, &Rfc3339).ok())
            .map(OffsetDateTime::unix_timestamp)
            .ok_or_else(invalid_server)?;
        let operation = facts["operation"].as_str().ok_or_else(invalid_server)?;
        if facts["v"] != "ottto.cloud_connect.approval.v4"
            || facts["aud"] != "app.ottto.net"
            || facts["source"] != "bedrock"
            || facts["attempt_id"] != id
            || facts["approval_id"] != approval_id
            || facts["input_revision"] != attempt["input_revision"]
            || facts["sign_by"] != sign_by
            || !matches!(operation, "connect" | "reconnect" | "replace")
            || !facts.get("replaces").is_some_and(|replaces| {
                if operation == "replace" {
                    replaces.is_object()
                } else {
                    replaces.is_null()
                }
            })
        {
            return Err(invalid_server());
        }
        if sign_by <= unix_now() {
            return Ok(attempt);
        }
        let actions = approval["next_actions"]
            .as_array()
            .ok_or_else(invalid_server)?;
        let browser_path = format!("/connections/cloud-approve?attempt={id}");
        let browser_url = actions
            .iter()
            .any(|action| action == "approve_in_browser")
            .then(|| approval["browser_url"].as_str())
            .flatten()
            .filter(|url| {
                *url == browser_path
                    || url.strip_prefix("https://app.ottto.net") == Some(browser_path.as_str())
            })
            .map(|_| format!("https://app.ottto.net{browser_path}"));
        let native = actions.iter().any(|action| action == "approve_on_mac");
        if native && signer_available() {
            let queued = queue_sign_request(
                SignKind::Approval {
                    attempt_id: id.into(),
                    approval_id: approval_id.into(),
                },
                payload,
                sign_by,
            );
            match queued {
                Ok(request) => match sign_queue().approval_outcome(&request) {
                    Some(SignOutcome::Signed(signature)) => {
                        let body = bytes(
                            &json!({"approval_id": approval_id, "signature": encode_base64url(&signature)}),
                        );
                        let response = self.agent_call(
                            Some(&run),
                            "POST",
                            &format!("connect-attempts/{id}/approval"),
                            Some(&body),
                            None,
                            deadline,
                        );
                        match response {
                            Ok(value) => {
                                let mut value = match verify_attempt(value, Some(id)) {
                                    Ok(attempt) => attempt,
                                    Err(_) => self.read_attempt(Some(&run), id, deadline)?,
                                };
                                remove_approval(&mut value);
                                value["approval_accepted"] = json!(true);
                                return Ok(value);
                            }
                            Err(error)
                                if matches!(
                                    error.code.as_str(),
                                    "approval_superseded"
                                        | "timed_out"
                                        | "server_unreachable"
                                        | "server_unavailable"
                                ) =>
                            {
                                let mut value = self.read_attempt(Some(&run), id, deadline)?;
                                remove_approval(&mut value);
                                return Ok(value);
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Some(SignOutcome::Declined) => {
                        let mut value = self.cancel(id, deadline)?;
                        if value["state"] == "cancelled" {
                            value["code"] = json!("approval_declined");
                        }
                        return Ok(value);
                    }
                    Some(SignOutcome::BiometricUnavailable | SignOutcome::AppUnavailable) => {}
                    Some(SignOutcome::Superseded | SignOutcome::Expired) => return Ok(attempt),
                    None => {
                        attempt["local_approval"] = json!({"where": "mac", "browser_url": browser_url, "approval_id": approval_id});
                        return Ok(attempt);
                    }
                },
                Err(SignQueueError::ApprovalRateLimited | SignQueueError::Full)
                    if browser_url.is_none() =>
                {
                    return Ok(attempt)
                }
                Err(_) => {}
            }
        }
        if let Some(url) = browser_url {
            attempt["local_approval"] =
                json!({"where": "browser", "browser_url": url, "approval_id": approval_id});
            return Ok(attempt);
        }
        Err(Failure::new(
            "mac_app_required",
            "Approve cloud setup in the Ottto web app.",
            "use_web",
        ))
    }
}

fn account_mismatch() -> Failure {
    Failure::new(
        "account_mismatch",
        "The approval is for a different AWS account.",
        "restart",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_pin_falls_back_to_web_before_any_template_fetch() {
        let pin = CloudTemplatePin {
            key: "aws/different.yaml".into(),
            version_id: "other".into(),
            sha256: "a".repeat(64),
        };
        let error = check_pin(&pin).unwrap_err();
        assert_eq!(error.code, "aws_template_unverified");
        assert_eq!(error.next_action, "use_web");
    }
}
