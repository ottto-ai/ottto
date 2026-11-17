//! auth for local control.

use crate::control::api_url_with_base;
use crate::control::backend_post_json;
use crate::control::control_token_validation_base_url;
use crate::control::lock_setup_run_binding;
use crate::control::require_identity_mutation_reservation;
use crate::control::source_slug;
#[cfg(test)]
use crate::control::tests;
use crate::control::BackendControlTokenClaims;
use crate::control::BackendControlTokenValidationRequest;
use crate::control::BackendControlTokenValidationResponse;
use crate::control::FileAccountStore;
use crate::control::FileDeviceStore;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalDaemon;
use crate::control::LocalDeviceBinding;
use crate::control::MutexGuard;
use crate::control::OrStatePoisoned;
use crate::control::ProviderDailyReferenceBackendGrantResponseV1;
use crate::control::ProviderDailyReferenceControlAction;
use crate::control::RequestAuthorization;
use crate::control::SecretString;
use crate::control::Serialize;
use crate::control::SourceKind;
use crate::control::SystemTime;
use crate::control::TelemetryControlAction;
use crate::control::UNIX_EPOCH;
use crate::control::URL_SAFE_NO_PAD;
use base64::Engine as _;

pub(super) fn require_authorized_local_client(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<(), LocalApiError> {
    // Internal verification reaches the state check with its own authority.
    if !matches!(authorization, RequestAuthorization::DaemonInternal) {
        require_local_caller(daemon, authorization)?;
    }
    daemon.require_usable_state()
}

pub(super) fn require_local_caller(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<(), LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => daemon.control_token.authorize(token),
        RequestAuthorization::TrustedCompanionApp => Ok(()),
        RequestAuthorization::DaemonInternal | RequestAuthorization::Untrusted => {
            Err(LocalApiError::LocalClientNotTrusted)
        }
    }
}

/// Only the token-authenticated CLI owns the exec plan and its report.
pub(super) fn require_cli_token(
    is_cli: bool,
    authorization: &RequestAuthorization,
) -> Result<(), LocalApiError> {
    if is_cli && matches!(authorization, RequestAuthorization::Token(_)) {
        Ok(())
    } else {
        Err(LocalApiError::Unauthorized)
    }
}

pub(super) fn require_non_empty_field(
    value: Option<&str>,
    field: &str,
) -> Result<(), LocalApiError> {
    if value.is_some_and(|candidate| !candidate.trim().is_empty()) {
        return Ok(());
    }
    Err(LocalApiError::InvalidRequest(format!(
        "{field} is required for telemetry control"
    )))
}

pub(super) fn validate_control_token_with_backend(
    api_base_url: &str,
    token: &str,
    action: &TelemetryControlAction,
    source: &SourceKind,
) -> Result<BackendControlTokenClaims, LocalApiError> {
    validate_control_token_with_backend_for(
        api_base_url,
        token,
        action_slug(action),
        source_slug(source),
    )
}

fn validate_control_token_with_backend_for(
    api_base_url: &str,
    token: &str,
    action: &str,
    source: &str,
) -> Result<BackendControlTokenClaims, LocalApiError> {
    let url = api_url_with_base(api_base_url, "/api/v1/apps/control-token/validate");
    let request = BackendControlTokenValidationRequest {
        token: token.to_string(),
        source: source.to_string(),
        action: action.to_string(),
    };
    match backend_post_json::<BackendControlTokenValidationResponse>(&url, &request, &[]) {
        Ok(response) => Ok(BackendControlTokenClaims {
            organization_id: response
                .organization_id
                .filter(|value| !value.trim().is_empty()),
            user_id: response.user_id.filter(|value| !value.trim().is_empty()),
            device_id: response.device_id.filter(|value| !value.trim().is_empty()),
            key_id: response.key_id,
            token_id: response.token_id.filter(|value| !value.trim().is_empty()),
        }),
        Err(LocalApiError::Backend(details)) if matches!(details.status, Some(401) | Some(403)) => {
            Err(LocalApiError::LocalClientNotTrusted)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn validate_control_token_fresh(
    token: &str,
    action: &TelemetryControlAction,
    source: &SourceKind,
) -> Result<(), LocalApiError> {
    validate_control_token_fresh_for(token, action_slug(action), source_slug(source)).map(|_| ())
}

fn validate_control_token_fresh_for(
    token: &str,
    action: &str,
    source: &str,
) -> Result<u64, LocalApiError> {
    if token.trim().is_empty() {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let payload = decode_control_token_payload(token)?;
    if payload.get("type").and_then(|value| value.as_str()) != Some("apps_control") {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("source").and_then(|value| value.as_str()) != Some(source) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    if payload.get("action").and_then(|value| value.as_str()) != Some(action) {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let exp = payload
        .get("exp")
        .and_then(|value| value.as_u64())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_secs();
    if exp <= now {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    Ok(exp)
}

/// A Codex control token proven fresh, backend-valid and bound to the
/// connected local account and Codex device.
struct CodexControlTokenAuthority {
    /// Keeps account/device authority stable through the grant transition.
    identity_lifecycle_lock: MutexGuard<'static, ()>,
    expires_at_unix: u64,
    token_id: String,
    device: LocalDeviceBinding,
    local_user_id: String,
    local_organization_id: String,
}

pub(super) fn require_local_control_account(
    claims: &BackendControlTokenClaims,
    accounts: &FileAccountStore,
    binding_label: &str,
) -> Result<(String, String), LocalApiError> {
    let account = accounts.load().map_err(|_| {
        LocalApiError::LocalOperationFailed(format!(
            "{binding_label} account binding is unavailable"
        ))
    })?;
    let local_user_id = account
        .user
        .as_ref()
        .map(|user| user.id.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    let local_organization_id = account
        .organization
        .as_ref()
        .map(|organization| organization.id.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    if account.state != LocalAccountState::Connected
        || claims.user_id.as_deref() != Some(local_user_id)
        || claims.organization_id.as_deref() != Some(local_organization_id)
    {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    Ok((local_user_id.to_string(), local_organization_id.to_string()))
}

/// Prelude of the provider-daily-reference bridge. Check order is part of the
/// contract. `binding_label` names the bridge in the binding-load errors.
fn authorize_codex_control_token(
    control_token: &str,
    action_slug: &str,
    api_base_url: Option<&str>,
    requires_mutation_reservation: bool,
    binding_label: &str,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
) -> Result<CodexControlTokenAuthority, LocalApiError> {
    let expires_at_unix = validate_control_token_fresh_for(control_token, action_slug, "codex")?;
    let token_validation_base_url = control_token_validation_base_url(api_base_url)?;
    let claims = validate_control_token_with_backend_for(
        &token_validation_base_url,
        control_token,
        action_slug,
        "codex",
    )?;

    // Identity reset/replacement paths acquire this same lock around their
    // grant preflight and filesystem mutation.
    let identity_lifecycle_lock = lock_setup_run_binding();
    if requires_mutation_reservation {
        require_identity_mutation_reservation(None)?;
    }

    let (local_user_id, local_organization_id) =
        require_local_control_account(&claims, accounts, binding_label)?;
    let device = devices
        .load()
        .map_err(|_| {
            LocalApiError::LocalOperationFailed(format!(
                "{binding_label} device binding is unavailable"
            ))
        })?
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    if claims.device_id.as_deref() != Some(device.device_id.as_str())
        || !device.sources.iter().any(|source| source == "codex")
    {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let token_id = claims
        .token_id
        .as_deref()
        .ok_or(LocalApiError::LocalClientNotTrusted)?;
    Ok(CodexControlTokenAuthority {
        identity_lifecycle_lock,
        expires_at_unix,
        token_id: token_id.to_string(),
        local_user_id,
        local_organization_id,
        device,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ProviderDailyReferenceControlResult {
    pub(super) action: ProviderDailyReferenceControlAction,
    pub(super) status: crate::provider_daily_reference::CollectorStatusV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) backend_create_request: Option<crate::provider_daily_reference::GrantCreateRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) backend_revoke_target: Option<crate::provider_daily_reference::GrantRevokeTarget>,
}

pub(super) fn provider_daily_reference_action_slug(
    action: &ProviderDailyReferenceControlAction,
) -> &'static str {
    match action {
        ProviderDailyReferenceControlAction::Prepare => "prepare_provider_daily_reference",
        ProviderDailyReferenceControlAction::Bind => "bind_provider_daily_reference",
        ProviderDailyReferenceControlAction::Revoke => "revoke_provider_daily_reference",
        ProviderDailyReferenceControlAction::ConfirmRevoked => {
            "confirm_provider_daily_reference_revoked"
        }
        ProviderDailyReferenceControlAction::Status => "provider_daily_reference_status",
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount => {
            "exclude_provider_daily_reference_current_account"
        }
        ProviderDailyReferenceControlAction::IncludeCurrentAccount => {
            "include_provider_daily_reference_current_account"
        }
    }
}

/// Drive the local Codex daily-aggregates consent state on behalf of an
/// operator who asked for it in the UI.
///
/// This command packages consent; it never creates it. Prepare records the
/// operator's explicit local consent and hands back the credential-free DTO the
/// browser POSTs; nothing collects until the backend's answer is bound, the
/// server policy approves, and the admitted build matches. All collection
/// gates from the collector are untouched by this path.
pub(super) fn provider_daily_reference_control(
    action: ProviderDailyReferenceControlAction,
    control_token: SecretString,
    api_base_url: Option<String>,
    backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
    expected_account_fingerprint: Option<String>,
) -> Result<ProviderDailyReferenceControlResult, LocalApiError> {
    provider_daily_reference_control_with_stores(
        action,
        control_token,
        api_base_url,
        backend_grant,
        expected_account_fingerprint,
        &FileAccountStore::default(),
        &FileDeviceStore::default(),
        &crate::provider_daily_reference::GrantStore::default(),
        &crate::provider_daily_reference::control_token_use_store(),
        // Consent is taken over a Codex account signed in right now. Only the
        // account id leaves the login read; the token never enters this path.
        &|prepare_fallback| {
            crate::provider_daily_reference::control_account_scope(prepare_fallback)
        },
        crate::provider_daily_reference::network_disabled(),
    )
}

#[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
pub(super) fn provider_daily_reference_control_with_stores(
    action: ProviderDailyReferenceControlAction,
    control_token: SecretString,
    api_base_url: Option<String>,
    backend_grant: Option<ProviderDailyReferenceBackendGrantResponseV1>,
    expected_account_fingerprint: Option<String>,
    accounts: &FileAccountStore,
    devices: &FileDeviceStore,
    grants: &crate::provider_daily_reference::GrantStore,
    token_uses: &crate::cloud_sessions::CloudSessionControlTokenUseStore,
    // Read lazily: only Prepare (`true`, which may fall back to the first
    // live login) and the account privacy controls (`false`, the default
    // home's login) call it, after the token is consumed.
    provider_account_scope: &dyn Fn(bool) -> Option<String>,
    network_disabled: bool,
) -> Result<ProviderDailyReferenceControlResult, LocalApiError> {
    let CodexControlTokenAuthority {
        identity_lifecycle_lock,
        expires_at_unix,
        token_id,
        device,
        local_user_id,
        local_organization_id,
    } = authorize_codex_control_token(
        control_token.expose_secret(),
        provider_daily_reference_action_slug(&action),
        api_base_url.as_deref(),
        action != ProviderDailyReferenceControlAction::Status,
        "codex daily aggregates",
        accounts,
        devices,
    )?;

    let backend_grant_allowed = matches!(
        action,
        ProviderDailyReferenceControlAction::Bind
            | ProviderDailyReferenceControlAction::Revoke
            | ProviderDailyReferenceControlAction::ConfirmRevoked
    );
    let backend_grant_required = matches!(
        action,
        ProviderDailyReferenceControlAction::Bind
            | ProviderDailyReferenceControlAction::ConfirmRevoked
    );
    if (backend_grant_required && backend_grant.is_none())
        || (!backend_grant_allowed && backend_grant.is_some())
    {
        return Err(LocalApiError::InvalidRequest(
            "backend_grant presence does not match provider daily reference action".to_string(),
        ));
    }
    let targets_current_account = matches!(
        action,
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount
            | ProviderDailyReferenceControlAction::IncludeCurrentAccount
    );
    if targets_current_account != expected_account_fingerprint.is_some() {
        return Err(LocalApiError::InvalidRequest(
            "expected_account_fingerprint presence does not match provider daily reference action"
                .to_string(),
        ));
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_secs();
    // Consume after trusted-backend and exact local binding validation, but
    // before any local grant side effect.
    token_uses
        .consume(&token_id, expires_at_unix, now_unix)
        .map_err(|_| LocalApiError::LocalClientNotTrusted)?;

    let mut backend_create_request = None;
    let mut backend_revoke_target = None;
    let result = match action {
        ProviderDailyReferenceControlAction::Prepare => {
            let scope = provider_account_scope(true);
            let Some(provider_account_scope) = scope
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(LocalApiError::LocalOperationFailed(
                    "a signed-in Codex account is required before consent".to_string(),
                ));
            };
            grants
                .enable(
                    &crate::provider_daily_reference::GrantSetup {
                        installation_id: device.device_id.clone(),
                        organization_scope: local_organization_id.to_string(),
                        effective_user_scope: local_user_id.to_string(),
                        provider_account_scope: provider_account_scope.to_string(),
                    },
                    time::OffsetDateTime::now_utc(),
                )
                .and_then(|_| grants.grant_create_request(&device.device_id))
                .map(|request| backend_create_request = Some(request))
        }
        ProviderDailyReferenceControlAction::Bind => grants
            .bind_backend_grant(
                backend_grant
                    .as_ref()
                    .expect("backend grant presence validated"),
                &device.device_id,
            )
            .map(|_| ()),
        ProviderDailyReferenceControlAction::Revoke => grants
            .revoke(time::OffsetDateTime::now_utc())
            .and_then(|()| {
                // Completion-safe compensating cleanup: an authenticated POST
                // response can arrive after the local revoke. Binding it
                // retains only its identity - a revoked local grant is never
                // resurrected - so the DELETE has an exact target.
                if let Some(response) = backend_grant.as_ref() {
                    grants.bind_backend_grant(response, &device.device_id)?;
                }
                Ok(())
            }),
        ProviderDailyReferenceControlAction::ConfirmRevoked => grants
            .apply_backend_revocation(
                backend_grant
                    .as_ref()
                    .expect("backend grant presence validated"),
                &device.device_id,
            )
            .map(|_| ()),
        ProviderDailyReferenceControlAction::Status => Ok(()),
        ProviderDailyReferenceControlAction::ExcludeCurrentAccount
        | ProviderDailyReferenceControlAction::IncludeCurrentAccount => {
            let scope = provider_account_scope(false);
            let Some(provider_account_scope) = scope
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(LocalApiError::LocalOperationFailed(
                    "a signed-in Codex account is required for this privacy control".to_string(),
                ));
            };
            let fingerprint = grants
                .account_fingerprint_for(provider_account_scope)
                .map_err(|_| {
                    LocalApiError::LocalOperationFailed(
                        "codex daily aggregates account attribution is unavailable".to_string(),
                    )
                })?
                .ok_or_else(|| {
                    LocalApiError::LocalOperationFailed(
                        "codex daily aggregates consent is absent".to_string(),
                    )
                })?;
            if expected_account_fingerprint.as_deref() != Some(fingerprint.as_str()) {
                return Err(LocalApiError::InvalidRequest(
                    "the signed-in Codex account changed; refresh status before changing privacy controls"
                        .to_string(),
                ));
            }
            grants.set_account_excluded(
                &fingerprint,
                action == ProviderDailyReferenceControlAction::ExcludeCurrentAccount,
            )
        }
    };
    result.map_err(|_| {
        LocalApiError::LocalOperationFailed(
            "codex daily aggregates local control failed".to_string(),
        )
    })?;

    if action == ProviderDailyReferenceControlAction::Status
        && grants
            .load()
            .map_err(|_| {
                LocalApiError::LocalOperationFailed(
                    "codex daily aggregates local control failed".to_string(),
                )
            })?
            .is_some_and(|grant| grant.backend_create_pending)
    {
        // An authenticated Status after a lost Prepare response returns the
        // create DTO again, so the browser retries the idempotent POST and
        // binds its response instead of guessing one.
        backend_create_request = Some(grants.grant_create_request(&device.device_id).map_err(
            |_| {
                LocalApiError::LocalOperationFailed(
                    "codex daily aggregates local control failed".to_string(),
                )
            },
        )?);
    }

    if action == ProviderDailyReferenceControlAction::Revoke {
        // Best effort by design: an unreconciled create has no backend id to
        // delete, and that is "nothing to delete", not a failed revoke - the
        // local stop already happened and already blocks collection.
        backend_revoke_target = grants.grant_revoke_target().ok();
    }
    #[cfg(test)]
    tests::before_daily_reference_status();
    let installation_id = devices.load().ok().flatten().map(|device| device.device_id);

    let response = ProviderDailyReferenceControlResult {
        action,
        // Built from the stores this call was handed, not from process-wide
        // state, so the reported status belongs to this installation and the
        // account actually signed in. A status that can read `enabled` while
        // every collection cycle refuses is the bug this closes.
        status: crate::provider_daily_reference::status_with_live_binding(
            grants,
            crate::provider_daily_reference::collector_status(grants, network_disabled),
            installation_id.as_deref(),
        ),

        backend_create_request,
        backend_revoke_target,
    };
    drop(identity_lifecycle_lock);
    Ok(response)
}

fn decode_control_token_payload(token: &str) -> Result<serde_json::Value, LocalApiError> {
    let mut parts = token.split('.');
    let _header = parts.next();
    let Some(payload) = parts.next() else {
        return Err(LocalApiError::LocalClientNotTrusted);
    };
    let Some(_signature) = parts.next() else {
        return Err(LocalApiError::LocalClientNotTrusted);
    };
    if parts.next().is_some() {
        return Err(LocalApiError::LocalClientNotTrusted);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| LocalApiError::LocalClientNotTrusted)?;
    serde_json::from_slice(&decoded).map_err(|_| LocalApiError::LocalClientNotTrusted)
}

pub(super) fn action_slug(action: &TelemetryControlAction) -> &'static str {
    match action {
        TelemetryControlAction::EnableTelemetry => "enable_telemetry",
        TelemetryControlAction::DisableTelemetry => "disable_telemetry",
        TelemetryControlAction::Status => "status",
    }
}
