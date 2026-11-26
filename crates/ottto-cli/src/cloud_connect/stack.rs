//! Typed CloudFormation plans, stack reconciliation and cleanup output.

use super::aws::{access_denied, Aws, Session};
use super::{invalid_server, sleep_until, Failure};
use ottto_protocol::{
    cloud_account_id, cloud_stack_id, cloud_stack_name, CloudTemplatePin, TemplatePin,
    TemplatePinId, CLOUD_CONNECT_REGION,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
pub(super) struct Plan {
    pub(super) stack_name: String,
    region: String,
    template: CloudTemplatePin,
    /// Built locally from the compiled pin once `check` accepts the server's template metadata.
    #[serde(skip)]
    url: String,
    parameters: Parameters,
    capabilities: Vec<String>,
    client_request_token: String,
    expected_outputs: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Parameters {
    external_id: String,
    role_name: String,
    ottto_workspace: String,
    metrics: String,
}

impl Plan {
    pub(super) fn workspace(&self) -> &str {
        &self.parameters.ottto_workspace
    }

    /// Checks every server value before any AWS write. The template must be the one this release
    /// compiled in; its URL is built from that pin, never taken from the server.
    pub(super) fn check(&mut self, metrics: bool) -> Result<(), Failure> {
        let pin = TemplatePinId::BedrockCliReadRoleV1;
        self.url = pin
            .matches_metadata(
                &self.template.key,
                &self.template.version_id,
                &self.template.sha256,
            )
            .then(|| pin.pin().and_then(TemplatePin::url))
            .flatten()
            .ok_or_else(|| {
                Failure::new(
                    "aws_template_unverified",
                    "Use Ottto on the web to connect with a verified template.",
                    "use_web",
                )
            })?;
        let (prefix, variant, metric_value) = if metrics {
            ("ottto-read-m-", "cli_metrics", "true")
        } else {
            ("ottto-read-b-", "cli_billing", "false")
        };
        let parameters = &self.parameters;
        let token = self.client_request_token.as_bytes();
        if self.region != CLOUD_CONNECT_REGION
            || !cloud_stack_name(&self.stack_name)
            || !self.stack_name.starts_with(prefix)
            || self.capabilities != ["CAPABILITY_NAMED_IAM"]
            || !(1..=128).contains(&token.len())
            || !token[0].is_ascii_alphanumeric()
            || !token
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            || self.expected_outputs.len() != 1
            || self
                .expected_outputs
                .get("OtttoGrantVariant")
                .is_none_or(|output| output != variant)
            || parameters.role_name != self.stack_name
            || parameters.metrics != metric_value
            || parameters.ottto_workspace.len() > 128
            || !parameters
                .ottto_workspace
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || !(2..=1224).contains(&parameters.external_id.len())
            || !parameters
                .external_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@:/_-".contains(&byte))
        {
            return Err(invalid_server());
        }
        Ok(())
    }

    fn parameter_values(&self) -> [(&'static str, &str); 4] {
        [
            ("ExternalId", &self.parameters.external_id),
            ("RoleName", &self.parameters.role_name),
            ("OtttoWorkspace", &self.parameters.ottto_workspace),
            ("Metrics", &self.parameters.metrics),
        ]
    }

    fn parameters_arg(&self) -> String {
        let parameters = self
            .parameter_values()
            .map(|(key, value)| json!({"ParameterKey": key, "ParameterValue": value}));
        serde_json::to_string(&parameters).expect("parameters serialize to JSON")
    }

    fn parameters_match(&self, stack: &Stack) -> bool {
        stack.parameters.len() == 4
            && self.parameter_values().iter().all(|(key, value)| {
                stack.parameters.iter().any(|parameter| {
                    parameter.parameter_key.as_str() == *key
                        && (parameter.parameter_value.as_str() == *value
                            || (*key == "ExternalId" && parameter.parameter_value == "****"))
                })
            })
    }

    fn outputs_match(&self, stack: &Stack) -> bool {
        stack
            .outputs
            .iter()
            .filter(|output| output.output_key == "OtttoGrantVariant")
            .map(|output| &output.output_value)
            .eq(self.expected_outputs.get("OtttoGrantVariant"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Stack {
    stack_id: String,
    stack_name: String,
    stack_status: String,
    #[serde(default)]
    parameters: Vec<Parameter>,
    #[serde(default)]
    outputs: Vec<StackOutput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Parameter {
    parameter_key: String,
    parameter_value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StackOutput {
    output_key: String,
    output_value: String,
}

fn describe(
    aws: &Aws,
    session: &Session,
    selector: &str,
    deadline: Instant,
) -> Result<Option<Stack>, Failure> {
    let output = aws.cloudformation(
        session,
        &["describe-stacks", "--stack-name", selector],
        deadline,
    )?;
    if !output.status.success() {
        let error = output.error();
        if error.contains("ValidationError")
            && error.contains(&format!("Stack with id {selector} does not exist"))
        {
            return Ok(None);
        }
    }
    let mut reply = aws.json(output)?;
    let stacks = reply["Stacks"].as_array_mut().ok_or_else(invalid_server)?;
    if stacks.len() != 1 {
        return Err(invalid_server());
    }
    serde_json::from_value(stacks[0].take())
        .map(Some)
        .map_err(|_| invalid_server())
}

pub(super) struct Reconcile<'a> {
    pub(super) aws: &'a Aws,
    pub(super) session: &'a mut Session,
    pub(super) plan: &'a Plan,
    pub(super) account: &'a str,
    pub(super) deadline: Instant,
    pub(super) known_stack: &'a mut Option<String>,
}

impl Reconcile<'_> {
    pub(super) fn run(&mut self, creating: impl FnOnce()) -> Result<String, Failure> {
        let stack_deadline = self.deadline.min(Instant::now() + Duration::from_secs(600));
        let mut stack = describe(
            self.aws,
            self.session,
            &self.plan.stack_name,
            stack_deadline,
        )?;
        if stack.is_none() {
            if self.session.expires_soon() {
                let refreshed = self.aws.export(stack_deadline)?;
                if self.aws.identity(&refreshed, stack_deadline)? != self.account {
                    return Err(Failure::new(
                        "aws_account_changed",
                        "The refreshed credentials are for a different AWS account.",
                        "restart",
                    ));
                }
                if refreshed.expires_soon() {
                    return Err(Failure::new(
                        "aws_not_signed_in",
                        "Get AWS credentials valid for at least five minutes.",
                        "fix_aws_sign_in",
                    ));
                }
                *self.session = refreshed;
            }
            creating();
            let selector = self.create(stack_deadline)?;
            // Recover from a lost create reply or CloudFormation's eventual consistency.
            loop {
                stack = describe(self.aws, self.session, &selector, stack_deadline)?;
                if stack.is_some() {
                    break;
                }
                self.wait(stack_deadline)?;
            }
        }
        while let Some(current) = stack {
            if current.stack_name != self.plan.stack_name
                || !cloud_stack_id(&current.stack_id, self.account, &self.plan.stack_name)
                || self
                    .known_stack
                    .as_ref()
                    .is_some_and(|known| known != &current.stack_id)
            {
                return Err(mismatch());
            }
            if !self.plan.parameters_match(&current) {
                return Err(mismatch());
            }
            *self.known_stack = Some(current.stack_id.clone());
            match current.stack_status.as_str() {
                "CREATE_COMPLETE" | "UPDATE_COMPLETE" => {
                    if !self.plan.outputs_match(&current) {
                        return Err(mismatch());
                    }
                    return Ok(current.stack_id);
                }
                "CREATE_IN_PROGRESS" => {
                    self.wait(stack_deadline)?;
                    stack = describe(self.aws, self.session, &current.stack_id, stack_deadline)?;
                }
                _ => return Err(self.stack_failure(&current.stack_id, stack_deadline)),
            }
        }
        Err(Failure::new(
            "stack_failed",
            "The CloudFormation stack is no longer available.",
            "restart",
        ))
    }

    fn create(&mut self, deadline: Instant) -> Result<String, Failure> {
        let name = &self.plan.stack_name;
        let parameters = self.plan.parameters_arg();
        let output = self.aws.cloudformation(
            self.session,
            &[
                "create-stack",
                "--stack-name",
                name,
                "--template-url",
                &self.plan.url,
                "--parameters",
                &parameters,
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "--client-request-token",
                &self.plan.client_request_token,
            ],
            deadline,
        );
        let output = match output {
            // The request token remains deterministic for the whole attempt.
            Err(error) if error.code == "timed_out" && Instant::now() < deadline => {
                return Ok(name.clone())
            }
            result => result?,
        };
        if !output.status.success() {
            let error = output.error();
            if error.contains("AlreadyExistsException") || error.contains("TokenAlreadyExists") {
                return Ok(name.clone());
            }
        }
        let parsed = self.aws.json(output)?;
        let arn = parsed["StackId"]
            .as_str()
            .filter(|arn| cloud_stack_id(arn, self.account, name))
            .ok_or_else(mismatch)?;
        *self.known_stack = Some(arn.to_owned());
        Ok(arn.to_owned())
    }

    fn wait(&self, deadline: Instant) -> Result<(), Failure> {
        sleep_until(deadline, Duration::from_secs(5)).map_err(|error| {
            if deadline < self.deadline {
                Failure::new(
                    "stack_timeout",
                    "CloudFormation is still creating the stack. Run again to resume.",
                    "run_again",
                )
            } else {
                error
            }
        })
    }

    fn stack_failure(&self, arn: &str, deadline: Instant) -> Failure {
        let events = self
            .aws
            .cloudformation(
                self.session,
                &[
                    "describe-stack-events",
                    "--stack-name",
                    arn,
                    "--no-paginate",
                ],
                deadline,
            )
            .and_then(|output| self.aws.json(output))
            .ok();
        let denied = events.is_some_and(|value| {
            value["StackEvents"]
                .as_array()
                .and_then(|events| {
                    events.iter().find(|event| {
                        event["ResourceStatus"]
                            .as_str()
                            .is_some_and(|status| status.ends_with("_FAILED"))
                    })
                })
                .and_then(|event| event["ResourceStatusReason"].as_str())
                .is_some_and(|reason| {
                    reason.contains("AccessDenied") || reason.contains("not authorized")
                })
        });
        if denied {
            access_denied()
        } else {
            Failure::new(
                "stack_failed",
                "CloudFormation could not create the stack.",
                "restart",
            )
        }
    }
}

fn mismatch() -> Failure {
    Failure::new(
        "stack_mismatch",
        "The existing CloudFormation stack does not match this setup.",
        "restart",
    )
}

/// The server's reference to a stack an attempt may have created.
#[derive(Deserialize)]
pub(super) struct CleanupReference {
    pub(super) attempt_id: String,
    pub(super) stack_name: String,
    pub(super) account_id: String,
    pub(super) stack_id: Option<String>,
}

impl CleanupReference {
    /// What to tell the user about the stack of an attempt the server ended without saving. The
    /// delete command names the full ARN the server checked, so it fails safely under another
    /// account's profile. Without an ARN the user gets the name, account and region only.
    pub(super) fn output(&self, profile: Option<&str>) -> Option<Value> {
        if !cloud_account_id(&self.account_id) || !cloud_stack_name(&self.stack_name) {
            return None;
        }
        let arn = self
            .stack_id
            .as_deref()
            .filter(|arn| cloud_stack_id(arn, &self.account_id, &self.stack_name));
        Some(match arn {
            Some(arn) => cleanup(&self.account_id, arn, profile),
            None => json!({
                "stack_name": self.stack_name,
                "account_id": self.account_id,
                "region": CLOUD_CONNECT_REGION,
                "verified": false,
                "message": format!(
                    "If stack {} exists in {} of AWS account {}, you can delete it.",
                    self.stack_name,
                    CLOUD_CONNECT_REGION,
                    super::display_account(&self.account_id),
                ),
            }),
        })
    }
}

pub(super) fn cleanup(account: &str, arn: &str, profile: Option<&str>) -> Value {
    let mut argv: Vec<String> = [
        "aws",
        "cloudformation",
        "delete-stack",
        "--stack-name",
        arn,
        "--region",
        CLOUD_CONNECT_REGION,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if let Some(profile) = profile {
        argv.push(format!("--profile={profile}"));
    }
    json!({
        "stack_id": arn, "account_id": account, "region": CLOUD_CONNECT_REGION,
        "verified": true, "argv": argv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_names_the_server_arn_or_only_describes_the_stack() {
        let arn = "arn:aws:cloudformation:us-east-1:000000000001:stack/ottto-read-b-abcde234/00000000-0000-0000-0000-000000000001";
        let mut reference = CleanupReference {
            attempt_id: "00000000-0000-4000-8000-000000000001".into(),
            stack_name: "ottto-read-b-abcde234".into(),
            account_id: "000000000001".into(),
            stack_id: Some(arn.into()),
        };
        let known = reference.output(Some("billing")).unwrap();
        assert_eq!(known["verified"], true);
        assert_eq!(known["argv"][4], arn);
        assert_eq!(known["argv"][7], "--profile=billing");

        reference.stack_id = None;
        let unknown = reference.output(None).unwrap();
        assert_eq!(unknown["verified"], false);
        assert!(unknown.get("argv").is_none());
        assert_eq!(unknown["stack_name"], "ottto-read-b-abcde234");

        // An ARN in another account is never offered for deletion.
        reference.stack_id = Some(arn.replace("000000000001:stack", "000000000002:stack"));
        assert!(reference.output(None).unwrap().get("argv").is_none());
    }
}
