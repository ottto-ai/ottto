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

/// The public bucket Ottto's CloudFormation templates are published to (Object Lock, immutable
/// object versions). CloudFormation reads the pinned version from here.
pub const TEMPLATE_ORIGIN: &str =
    "https://ottto-cloud-connect-templates.s3.us-east-1.amazonaws.com";

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

impl TemplatePin {
    /// `TEMPLATE_ORIGIN/<key>?versionId=<version_id>`, for a key under `aws/` ending `.yaml`, a
    /// URL-safe version id and a lowercase hex SHA-256, so no pin value can change the host, path
    /// or query. `None` for any other shape.
    pub fn url(&self) -> Option<String> {
        let key_ok = self.key.starts_with("aws/")
            && self.key.ends_with(".yaml")
            && self.key.len() <= 128
            && !self.key.contains("..")
            && !self.key.contains("//")
            && self.key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"/-_.".contains(&byte)
            });
        let version_ok = !self.version_id.is_empty()
            && self.version_id.len() <= 1024
            && self
                .version_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        let sha256_ok = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        (key_ok && version_ok && sha256_ok).then(|| {
            format!(
                "{TEMPLATE_ORIGIN}/{}?versionId={}",
                self.key, self.version_id
            )
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(key: &'static str, version_id: &'static str, sha256: &'static str) -> TemplatePin {
        TemplatePin {
            key,
            version_id,
            sha256,
        }
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn template_url_is_built_only_from_a_well_formed_pin() {
        assert_eq!(
            pin("aws/bedrock-cli-read-role-v1.yaml", "v1.A_b-c", SHA).url(),
            Some(format!(
                "{TEMPLATE_ORIGIN}/aws/bedrock-cli-read-role-v1.yaml?versionId=v1.A_b-c"
            )),
        );
        for bad in [
            pin("gcp/role.yaml", "v1", SHA),
            pin("aws/role.json", "v1", SHA),
            pin("aws/../role.yaml", "v1", SHA),
            pin("aws//role.yaml", "v1", SHA),
            pin("aws/Role.yaml", "v1", SHA),
            pin("aws/role.yaml", "", SHA),
            pin("aws/role.yaml", "v1&x=y", SHA),
            pin("aws/role.yaml", "v1", "ABCDEF"),
            pin("aws/role.yaml", "v1", "0123456789abcdef"),
        ] {
            assert_eq!(bad.url(), None, "{bad:?}");
        }
        for (_, compiled) in TEMPLATE_PINS {
            assert!(compiled.url().is_some(), "{compiled:?}");
        }
    }
}
