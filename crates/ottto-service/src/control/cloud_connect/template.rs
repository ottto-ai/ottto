//! CloudFormation template verification against a build-time table of published object versions
//! and digests.

use ottto_protocol::TemplatePin;
pub use ottto_protocol::TemplatePinId;
use std::io::Read as _;
use std::time::Duration;

/// The public bucket Ottto's CloudFormation templates are published to (Object Lock, immutable
/// versions).
const TEMPLATE_ORIGIN: &str = "https://ottto-cloud-connect-templates.s3.us-east-1.amazonaws.com";

/// CloudFormation reads at most 1 MB of template from S3.
const MAX_TEMPLATE_BYTES: u64 = 1024 * 1024;

const TEMPLATE_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateError {
    /// The pin is absent or its key, version or digest has the wrong shape.
    InvalidPin,
    /// The object could not be read.
    Unreachable,
    /// The served bytes do not hash to the pinned digest, or are too large.
    DigestMismatch,
}

/// The compiled template URL for `id`, once the served bytes hash to its compiled digest.
pub fn verified_template_url(id: TemplatePinId) -> Result<String, TemplateError> {
    verified_template_url_with_timeout(id, TEMPLATE_FETCH_TIMEOUT)
}

pub(super) fn verified_template_url_with_timeout(
    id: TemplatePinId,
    timeout: Duration,
) -> Result<String, TemplateError> {
    let pin = id.pin().ok_or(TemplateError::InvalidPin)?;
    let url = template_url(pin)?;
    let response = crate::retry_tls::credential_agent()
        .get(&url)
        .timeout(timeout.min(TEMPLATE_FETCH_TIMEOUT))
        .call()
        .map_err(|_| TemplateError::Unreachable)?;
    if response.status() != 200 {
        return Err(TemplateError::Unreachable);
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_TEMPLATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TemplateError::Unreachable)?;
    template_bytes_match(pin, &bytes)?;
    Ok(url)
}

/// `TEMPLATE_ORIGIN/<key>?versionId=<version_id>`, for a key under `aws/` ending `.yaml` and a
/// URL-safe version id, so neither can change the host, path or query.
pub(super) fn template_url(pin: &TemplatePin) -> Result<String, TemplateError> {
    let key_ok = pin.key.starts_with("aws/")
        && pin.key.ends_with(".yaml")
        && pin.key.len() <= 128
        && !pin.key.contains("..")
        && !pin.key.contains("//")
        && pin.key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"/-_.".contains(&byte)
        });
    let version_ok = !pin.version_id.is_empty()
        && pin.version_id.len() <= 1024
        && pin
            .version_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if !key_ok || !version_ok || !crate::hex::is_sha256_lower(pin.sha256) {
        return Err(TemplateError::InvalidPin);
    }
    Ok(format!(
        "{TEMPLATE_ORIGIN}/{}?versionId={}",
        pin.key, pin.version_id
    ))
}

pub(super) fn template_bytes_match(pin: &TemplatePin, bytes: &[u8]) -> Result<(), TemplateError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_TEMPLATE_BYTES)
        || crate::hex::sha256_lower(bytes) != pin.sha256
    {
        return Err(TemplateError::DigestMismatch);
    }
    Ok(())
}
