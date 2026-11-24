//! CLI requests use the setup-run token, but only the app can sign a write.
use super::queue::unix_now;
use super::server::{claim_origin_pair, BoundRun, DeviceChallenge, ServerError, SetupRunServer};
use super::wire::{
    checked_challenge, decode_base64url, encode_base64url, proof_header, request_sha256,
    ChallengeRequest,
};
use super::{
    queue_sign_request, sign_queue, signer_available, SignKind, SignOutcome, SignQueueError,
};
use crate::control::backend_http::{
    backend_error_from_ureq, backend_response_unexpected, backend_send_raw, backend_success,
};
use crate::{LocalApiError, LocalDaemon};
use ottto_protocol::{
    cloud_account_id, cloud_stack_name_from_id, cloud_uuid, CloudConnectFailure as Failure,
    LocalControlCommand as Command, CLOUD_CONNECT_ATTEMPT_SCHEMA,
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
/// One server call's longest wait inside the command deadline.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

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
            // Feature status is the existing `cloud_status` command; this reads one attempt.
            let id = attempt_id.ok_or_else(invalid_argument)?;
            let mut attempt = server.read_attempt(None, &id, deadline(timeout_ms))?;
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
            let run = server.bound_run().map_err(server_failure)?;
            let mut attempt = server.signed_attempt(
                &run,
                "POST",
                "ensure",
                None,
                Some(&bytes(&body)),
                deadline,
            )?;
            // The CLI checks `aws.template` against its compiled pin before any AWS write.
            remove_approval(&mut attempt);
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
            let run = server.bound_run().map_err(server_failure)?;
            let mut attempt = server.signed_attempt(
                &run,
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
        } => {
            let run = server.bound_run().map_err(server_failure)?;
            server.cancel(&run, &attempt_id, deadline(timeout_ms))
        }
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
        run: Option<&BoundRun>,
        method: &str,
        resource: &str,
        body: Option<&[u8]>,
        proof: Option<&str>,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.call_bound(run, |prefix, token| {
            let Ok(timeout) = remaining(deadline) else {
                return Ok(Err(timeout()));
            };
            let url = format!("{prefix}/{resource}");
            let mut headers = vec![("X-Ottto-Setup-Run-Token", token)];
            headers.extend(proof.map(|proof| ("X-Ottto-Device-Proof", proof)));
            let response =
                match backend_send_raw(method, &url, body, &headers, timeout.min(CALL_TIMEOUT))
                    .map_err(|error| *error)
                {
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
        .map_err(server_failure)?
    }

    fn signed_attempt(
        &self,
        run: &BoundRun,
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
        let template = if attempt_id.is_some() {
            ATTEMPT_TEMPLATE
        } else {
            ENSURE_TEMPLATE
        };
        let digest = request_sha256(method, template, body.unwrap_or_default());
        let request = ChallengeRequest {
            operation,
            attempt_id,
            request_sha256: &digest,
        };
        let challenge_body = bytes(&request);
        let resource = attempt_id.map_or_else(
            || "connect-attempts".into(),
            |id| format!("connect-attempts/{id}"),
        );
        for retry in [false, true] {
            let challenge: DeviceChallenge = serde_json::from_value(self.agent_call(
                Some(run),
                "POST",
                "device-challenges",
                Some(&challenge_body),
                None,
                deadline,
            )?)
            .map_err(|_| invalid_server())?;
            let checked = checked_challenge(
                &challenge.challenge_id,
                &challenge.payload_bytes,
                &request,
                &run.id,
                &run.organization_id,
                unix_now(),
            )
            .ok_or_else(invalid_server)?;
            let payload = decode_base64url(&checked.payload_b64).ok_or_else(invalid_server)?;
            let wait = remaining(deadline)?.min(SIGN_WAIT);
            let queued = queue_sign_request(SignKind::DeviceProof, payload, checked.expires_at)
                .map_err(queue_failure)?;
            let Some(SignOutcome::Signed(signature)) = sign_queue().wait(
                &queued,
                wait.min(deadline.saturating_duration_since(Instant::now())),
            ) else {
                sign_queue().cancel(&queued);
                remaining(deadline)?;
                return Err(Failure::new(
                    "mac_app_unavailable",
                    "Open the Ottto app and run the command again.",
                    "open_app",
                ));
            };
            let result = self.agent_call(
                Some(run),
                method,
                &resource,
                body,
                Some(&proof_header(&checked.challenge_id, &signature)),
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

    fn read_attempt(
        &self,
        run: Option<&BoundRun>,
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

    fn cancel(&self, run: &BoundRun, id: &str, deadline: Instant) -> Result<Value, Failure> {
        let mut attempt = self.signed_attempt(run, "DELETE", "cancel", Some(id), None, deadline)?;
        sign_queue().cancel_attempt(id);
        remove_approval(&mut attempt);
        Ok(attempt)
    }

    fn poll(&self, id: &str, account: &str, deadline: Instant) -> Result<Value, Failure> {
        let run = self.bound_run().map_err(server_failure)?;
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
            || facts["org_id"] != run.organization_id
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
        let browser_url = actions
            .iter()
            .any(|action| action == "approve_in_browser")
            .then(|| approval["browser_url"].as_str())
            .flatten()
            .and_then(|offered| approval_browser_url(&run.api_base_url, id, offered));
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
            if let Ok(request) = queued {
                match sign_queue().approval_outcome(&request) {
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
                                        | "approval_conflict"
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
                        let mut value = self.cancel(&run, id, deadline)?;
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
                }
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

/// The browser approval link for attempt `id`: the server's link only when it is the approval
/// page on the web origin paired with this run's API (or that page's path), rebuilt from the
/// compiled origin.
pub(super) fn approval_browser_url(api_base_url: &str, id: &str, offered: &str) -> Option<String> {
    let (_, web) = claim_origin_pair(api_base_url)?;
    let path = format!("/connections/cloud-approve?attempt={id}");
    (offered == path || offered.strip_prefix(web) == Some(path.as_str()))
        .then(|| format!("{web}{path}"))
}

fn account_mismatch() -> Failure {
    Failure::new(
        "account_mismatch",
        "The approval is for a different AWS account.",
        "restart",
    )
}
