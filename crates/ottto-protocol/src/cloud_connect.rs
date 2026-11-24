//! CLI control requests and shared cloud-connect wire validation.

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
#[serde(deny_unknown_fields)]
pub struct CloudTemplatePin {
    pub key: String,
    pub version_id: String,
    pub sha256: String,
}

/// A template chosen by the local cloud connect flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplatePinId {
    BedrockCliReadRoleV1,
}

/// Add the immutable object version and its digest after the template is published.
/// An absent pin keeps CLI setup disabled for that template.
const TEMPLATE_PINS: &[(TemplatePinId, TemplatePin)] = &[];

/// One published template object version and the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplatePin {
    pub key: &'static str,
    pub version_id: &'static str,
    pub sha256: &'static str,
}

impl TemplatePinId {
    /// The immutable object metadata compiled for this flow.
    pub fn pin(self) -> Option<&'static TemplatePin> {
        TEMPLATE_PINS
            .iter()
            .find_map(|(id, pin)| (*id == self).then_some(pin))
    }

    /// Checks server metadata against the locally selected pin.
    pub fn matches_metadata(self, key: &str, version_id: &str, sha256: &str) -> bool {
        self.pin().is_some_and(|pin| {
            pin.key == key && pin.version_id == version_id && pin.sha256 == sha256
        })
    }
}

impl CloudTemplatePin {
    pub fn is_compiled_pin(&self) -> bool {
        TemplatePinId::BedrockCliReadRoleV1.matches_metadata(
            &self.key,
            &self.version_id,
            &self.sha256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudConnectFailure {
    pub code: String,
    pub message: Box<str>,
    pub next_action: String,
    #[serde(default)]
    pub retryable: bool,
    pub reason: Option<Box<str>>,
    pub connect_url: Option<Box<str>>,
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
