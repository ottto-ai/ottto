//! diagnostics for local control.

use crate::control::api_url_with_base;
use crate::control::backend_post_json;
use crate::control::current_rfc3339_timestamp;
use crate::control::diagnostics_local_only_upload_report;
use crate::control::status_for;
use crate::control::to_value;
use crate::control::validated_api_base_url;
use crate::control::ControlTokenStore;
use crate::control::DiagnosticsBundle;
use crate::control::DiagnosticsRetentionDisclosure;
use crate::control::DiagnosticsUploadApproval;
use crate::control::DiagnosticsUploadApprovalSummary;
use crate::control::DiagnosticsUploadAuthorization;
use crate::control::DiagnosticsUploadBody;
use crate::control::DiagnosticsUploadClient;
use crate::control::DiagnosticsUploadReport;
use crate::control::DiagnosticsUploadResponse;
use crate::control::DiagnosticsUploadStatus;
use crate::control::KeychainSecretStore;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalDaemon;
use crate::control::RedactedValue;
use crate::control::RequestAuthorization;
use crate::control::DIAGNOSTICS_RETENTION_DISCLOSURE;
use crate::control::OTTTO_SETUP_RUN_TOKEN_ACCOUNT;
use crate::control::PROTOCOL_VERSION;

pub(super) fn diagnostics_collect(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    upload: bool,
    upload_approval: Option<DiagnosticsUploadApproval>,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    let mut bundle = match authorization {
        RequestAuthorization::Token(token) => daemon.diagnostics_stub(token)?,
        RequestAuthorization::TrustedCompanionApp => {
            daemon.diagnostics_stub_for_trusted_client()?
        }
        RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
            return Err(LocalApiError::LocalClientNotTrusted)
        }
    };

    if !upload {
        bundle.upload = diagnostics_local_only_upload_report();
        return to_value(bundle);
    }

    let approval = upload_approval.ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "diagnostics upload requires --approve-upload and --accept-retention-disclosure"
                .to_string(),
        )
    })?;
    validate_diagnostics_upload_approval(&approval)?;
    let upload_authorization = diagnostics_upload_authorization(daemon, authorization, &approval)?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        upload_authorization
            .connection_api_base_url()
            .map(String::as_str)
    }))?;

    bundle.upload = upload_diagnostics_bundle(&api_base_url, &bundle, &upload_authorization)?;
    to_value(bundle)
}

fn validate_diagnostics_upload_approval(
    approval: &DiagnosticsUploadApproval,
) -> Result<(), LocalApiError> {
    if !approval.approved {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires --approve-upload".to_string(),
        ));
    }
    if !approval.retention_disclosure_accepted {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires --accept-retention-disclosure".to_string(),
        ));
    }
    normalize_support_claim(approval.support_claim.as_deref())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticsUploadAuth {
    ConnectedAccount {
        setup_run_id: String,
        setup_run_token: String,
        api_base_url: String,
    },
    SupportClaim {
        claim: String,
    },
}

impl DiagnosticsUploadAuth {
    fn authorization_kind(&self) -> DiagnosticsUploadAuthorization {
        match self {
            DiagnosticsUploadAuth::ConnectedAccount { .. } => {
                DiagnosticsUploadAuthorization::ConnectedAccount
            }
            DiagnosticsUploadAuth::SupportClaim { .. } => {
                DiagnosticsUploadAuthorization::SupportClaim
            }
        }
    }

    fn connection_api_base_url(&self) -> Option<&String> {
        match self {
            DiagnosticsUploadAuth::ConnectedAccount { api_base_url, .. } => Some(api_base_url),
            DiagnosticsUploadAuth::SupportClaim { .. } => None,
        }
    }

    fn support_claim_provided(&self) -> bool {
        matches!(self, DiagnosticsUploadAuth::SupportClaim { .. })
    }
}

fn diagnostics_upload_authorization(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    approval: &DiagnosticsUploadApproval,
) -> Result<DiagnosticsUploadAuth, LocalApiError> {
    if let Some(claim) = normalize_support_claim(approval.support_claim.as_deref())? {
        return Ok(DiagnosticsUploadAuth::SupportClaim { claim });
    }

    let status = status_for(daemon, authorization)?;
    if status.account.state != LocalAccountState::Connected {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics upload requires an Ottto login or --support-claim".to_string(),
        ));
    }

    let connection = daemon
        .connection_for_authorized_client()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    Ok(DiagnosticsUploadAuth::ConnectedAccount {
        setup_run_id: connection.setup_run_id,
        setup_run_token,
        api_base_url: connection.api_base_url,
    })
}

fn normalize_support_claim(raw: Option<&str>) -> Result<Option<String>, LocalApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics support claim cannot be empty".to_string(),
        ));
    }
    if value.len() > 128 || value.chars().any(char::is_control) {
        return Err(LocalApiError::InvalidRequest(
            "diagnostics support claim is invalid".to_string(),
        ));
    }
    Ok(Some(value.to_string()))
}

fn upload_diagnostics_bundle(
    api_base_url: &str,
    bundle: &DiagnosticsBundle,
    authorization: &DiagnosticsUploadAuth,
) -> Result<DiagnosticsUploadReport, LocalApiError> {
    let url = diagnostics_upload_url(api_base_url, authorization);
    let body = DiagnosticsUploadBody {
        bundle,
        approval: DiagnosticsUploadApprovalSummary {
            approved: true,
            retention_disclosure_accepted: true,
            retention_disclosure: DIAGNOSTICS_RETENTION_DISCLOSURE,
            authorization: authorization.authorization_kind(),
            support_claim_provided: authorization.support_claim_provided(),
        },
        client: DiagnosticsUploadClient {
            protocol_version: PROTOCOL_VERSION,
            local_platform_version: bundle
                .section_item("versions", "daemon_version")
                .and_then(redacted_string)
                .unwrap_or_else(|| "unknown".to_string()),
            machine_id: bundle.machine_id.clone(),
        },
    };

    let response: DiagnosticsUploadResponse = match authorization {
        DiagnosticsUploadAuth::ConnectedAccount {
            setup_run_token, ..
        } => backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)]),
        DiagnosticsUploadAuth::SupportClaim { claim } => {
            backend_post_json(&url, &body, &[("X-Ottto-Support-Claim", claim)])
        }
    }?;

    Ok(DiagnosticsUploadReport {
        requested: true,
        status: DiagnosticsUploadStatus::Uploaded,
        approval_required: true,
        approved: true,
        retention: DiagnosticsRetentionDisclosure {
            accepted: true,
            text: DIAGNOSTICS_RETENTION_DISCLOSURE.to_string(),
        },
        authorization: authorization.authorization_kind(),
        support_claim_provided: authorization.support_claim_provided(),
        upload_id: response.upload_id,
        uploaded_at: Some(
            response
                .uploaded_at
                .unwrap_or_else(current_rfc3339_timestamp),
        ),
    })
}

fn diagnostics_upload_url(api_base_url: &str, authorization: &DiagnosticsUploadAuth) -> String {
    match authorization {
        DiagnosticsUploadAuth::ConnectedAccount { setup_run_id, .. } => api_url_with_base(
            api_base_url,
            &format!("/api/v1/setup-runs/{setup_run_id}/local-client/diagnostics"),
        ),
        DiagnosticsUploadAuth::SupportClaim { .. } => {
            api_url_with_base(api_base_url, "/api/v1/diagnostics/support-bundles")
        }
    }
}

trait DiagnosticsBundleExt {
    fn section_item(&self, section: &str, key: &str) -> Option<&RedactedValue>;
}

impl DiagnosticsBundleExt for DiagnosticsBundle {
    fn section_item(&self, section: &str, key: &str) -> Option<&RedactedValue> {
        self.sections
            .iter()
            .find(|candidate| candidate.name == section)
            .and_then(|candidate| candidate.items.get(key))
    }
}

fn redacted_string(value: &RedactedValue) -> Option<String> {
    match value {
        RedactedValue::String(value) => Some(value.clone()),
        _ => None,
    }
}
