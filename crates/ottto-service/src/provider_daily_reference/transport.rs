//! Upload transport: sends one batch over the relay-device channel and
//! classifies why an upload did not land.

use super::{SOURCE, UPLOAD_TIMEOUT};
use crate::hex::is_uuid;
use anyhow::Result;
use ottto_core::LocalDeviceBinding;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Upload transport
// ---------------------------------------------------------------------------

/// Why an upload did not land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// The backend refused this build or this principal. Expected until a
    /// reviewed server change admits the shipped collector version, so it is
    /// never counted against the provider circuit breaker.
    NotAdmitted(u16),
    /// The declared consent epoch is behind the server's. Only re-consent can
    /// fix it, so the collector stops rather than retrying.
    GrantEpochConflict,
    /// The current opaque account is durably excluded by the owner. This is a
    /// terminal privacy state, not a transient upload failure.
    AccountExcluded,
    /// Contract rejection: the batch is not acceptable as shaped.
    ContractRejected(u16),
    /// Everything else. Retried on the next cycle.
    Unavailable(String),
}

impl UploadError {
    pub(super) fn category(&self) -> &'static str {
        match self {
            UploadError::NotAdmitted(_) => "collector_not_admitted",
            UploadError::GrantEpochConflict => "grant_epoch_conflict",
            UploadError::AccountExcluded => "account_excluded",
            UploadError::ContractRejected(_) => "contract_rejected",
            UploadError::Unavailable(_) => "upload_unavailable",
        }
    }
}

/// Send one batch to the backend. Defaults fail closed.
pub trait DailyReferenceTransport {
    fn is_configured(&self) -> bool {
        false
    }

    fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
        Err(UploadError::Unavailable(
            "codex daily aggregates transport is not configured".to_string(),
        ))
    }
}

/// Transport that exists only so a cycle can run inert before the relay
/// credentials are available.
pub struct DeferredTransport;

impl DailyReferenceTransport for DeferredTransport {}

/// Relay-device transport over the existing snapshot upload channel.
pub struct RelayTransport {
    client: crate::snapshot_client::SnapshotApiClient,
    device: LocalDeviceBinding,
    device_secret: String,
}

impl RelayTransport {
    pub fn new(
        api_base_url: impl Into<String>,
        device: LocalDeviceBinding,
        device_secret: String,
    ) -> Self {
        Self {
            client: crate::snapshot_client::SnapshotApiClient::new(api_base_url),
            device,
            device_secret,
        }
    }

    fn token(&self) -> Result<String, UploadError> {
        self.client
            .issue_relay_token_with_timeout(
                &self.device,
                &self.device_secret,
                crate::snapshots::SnapshotSource::Codex,
                UPLOAD_TIMEOUT,
            )
            .map_err(|error| UploadError::Unavailable(format!("relay token unavailable: {error}")))
    }
}

impl DailyReferenceTransport for RelayTransport {
    fn is_configured(&self) -> bool {
        !self.device_secret.is_empty()
            && is_uuid(&self.device.device_id)
            && self.device.sources.iter().any(|source| source == SOURCE)
    }

    fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
        let token = self.token()?;
        match self
            .client
            .upload_provider_daily_reference_batch_with_timeout(&token, batch, UPLOAD_TIMEOUT)
        {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                let mapped = map_upload_error(&error);
                // A relay token can simply have expired. Refresh once and
                // replay the identical body before concluding the build is not
                // admitted.
                if matches!(mapped, UploadError::NotAdmitted(401)) {
                    let token = self.token()?;
                    return self
                        .client
                        .upload_provider_daily_reference_batch_with_timeout(
                            &token,
                            batch,
                            UPLOAD_TIMEOUT,
                        )
                        .map_err(|error| map_upload_error(&error));
                }
                Err(mapped)
            }
        }
    }
}

pub(super) fn map_upload_error(error: &anyhow::Error) -> UploadError {
    if let Some(rejected) =
        error.downcast_ref::<crate::snapshot_client::ProviderDailyReferenceUploadRejected>()
    {
        return UploadError::NotAdmitted(rejected.status);
    }
    if let Some(rejected) =
        error.downcast_ref::<crate::snapshot_client::ProviderDailyReferenceContractRejected>()
    {
        return match rejected.reason {
            crate::snapshot_client::ProviderDailyReferenceContractRejection::AccountExcluded => {
                UploadError::AccountExcluded
            }
            crate::snapshot_client::ProviderDailyReferenceContractRejection::GrantEpochConflict => {
                UploadError::GrantEpochConflict
            }
            crate::snapshot_client::ProviderDailyReferenceContractRejection::Other => {
                UploadError::ContractRejected(rejected.status)
            }
        };
    }
    UploadError::Unavailable(error.to_string())
}
