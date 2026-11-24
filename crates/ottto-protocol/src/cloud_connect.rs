use serde::{Deserialize, Serialize};

pub const CLOUD_CONNECT_CONTROL_PROTOCOL_VERSION: u16 = 29;
pub const CLOUD_CONNECT_ATTEMPT_SCHEMA: &str = "cloud_connect_agent.v4";
pub const CLOUD_CONNECT_REGION: &str = "us-east-1";
pub const CLOUD_CONNECT_WEB_URL: &str = "https://app.ottto.net/connections";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudConnectEnsure {
    pub source: String,
    pub reconnect: bool,
    pub restart: bool,
    pub metrics: bool,
    pub client_request_id: String,
    pub observed_aws_account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudConnectSubmit {
    pub input_revision: u32,
    pub account_id: String,
    pub stack_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudTemplatePin {
    pub key: String,
    pub version_id: String,
    pub sha256: String,
}

/// Filled in after publication of the immutable CLI template. An unset pin
/// matches no server response, including one carrying these placeholder values.
pub const CLOUD_CLI_TEMPLATE_PIN: Option<(&str, &str, &str)> = None;

impl CloudTemplatePin {
    pub fn is_compiled_pin(&self) -> bool {
        CLOUD_CLI_TEMPLATE_PIN
            == Some((
                self.key.as_str(),
                self.version_id.as_str(),
                self.sha256.as_str(),
            ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudConnectFailure {
    pub code: String,
    pub message: String,
    pub next_action: String,
    #[serde(default)]
    pub retryable: bool,
    pub reason: Option<String>,
    pub connect_url: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl CloudConnectFailure {
    pub fn new(code: &str, message: &str, next_action: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            next_action: next_action.into(),
            retryable: false,
            reason: None,
            connect_url: None,
            retry_after_seconds: None,
        }
    }
}

pub fn cloud_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub fn cloud_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub fn cloud_stack_name(value: &str) -> bool {
    value
        .strip_prefix("ottto-read-b-")
        .or_else(|| value.strip_prefix("ottto-read-m-"))
        .is_some_and(|suffix| {
            suffix.len() == 8
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        })
}

pub fn cloud_stack_id(value: &str, account: &str, name: &str) -> bool {
    cloud_account_id(account)
        && cloud_stack_name(name)
        && value
            .strip_prefix(&format!(
                "arn:aws:cloudformation:{CLOUD_CONNECT_REGION}:{account}:stack/{name}/"
            ))
            .is_some_and(cloud_uuid)
}

pub fn cloud_stack_name_from_id<'a>(value: &'a str, account: &str) -> Option<&'a str> {
    let rest = value.strip_prefix(&format!(
        "arn:aws:cloudformation:{CLOUD_CONNECT_REGION}:{account}:stack/"
    ))?;
    let (name, _) = rest.split_once('/')?;
    cloud_stack_id(value, account, name).then_some(name)
}
