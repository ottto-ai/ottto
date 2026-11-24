//! setup claims credentials for local control.

use crate::control::api_url_with_base;
use crate::control::backend_get_agent_read_json;
use crate::control::backend_get_json;
use crate::control::backend_post_json;
use crate::control::backend_post_json_with_timeout;
use crate::control::backend_response_unexpected;
use crate::control::constant_work_eq;
use crate::control::current_millis;
use crate::control::default_prior_device_path;
use crate::control::history_now;
use crate::control::history_stores;
use crate::control::json;
use crate::control::lock_history_recovery;
use crate::control::lock_setup_run_binding;
use crate::control::operating_system_slug;
use crate::control::registration_history_choice_error;
use crate::control::remember_revocation_receipt;
use crate::control::secret_sha256;
use crate::control::setup_run_binding_matches;
use crate::control::source_slug;
use crate::control::stage_local_release;
#[cfg(test)]
use crate::control::tests;
use crate::control::validate_pending_candidate_secret;
use crate::control::validate_pending_prior_credential_binding;
use crate::control::validated_api_base_url;
use crate::control::wait_for_setup_run_verification_with_base_timeout;
use crate::control::ControlTokenStore;
use crate::control::DeviceCredentialConfirmationApiResponse;
use crate::control::DeviceCredentialPreparationApiResponse;
use crate::control::DeviceCredentialPreparationStatusApiResponse;
use crate::control::DeviceReleaseProof;
use crate::control::DeviceSelfReleaseResponse;
use crate::control::Digest;
use crate::control::FileAccountStore;
use crate::control::FileConnectionStore;
use crate::control::FileDeviceStore;
use crate::control::FileMachineStore;
use crate::control::FileOwnerSnapshotNamespaceStore;
use crate::control::FilePendingDeviceCredentialStore;
use crate::control::InstallSessionApiResponse;
use crate::control::InstallSessionEvent;
use crate::control::KeychainSecretStore;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::LocalCredentialOwner;
use crate::control::LocalDeviceEnvelope;
use crate::control::MachineIdentity;
use crate::control::OrStatePoisoned;
use crate::control::OwnerSnapshotKey;
use crate::control::OwnerSnapshotNamespace;
use crate::control::Path;
use crate::control::PendingDeviceCredentialPreparation;
use crate::control::PendingDeviceCredentialRequestAuthority;
use crate::control::RefreshedSetupRunToken;
use crate::control::SetupRunCredentials;
use crate::control::SetupRunDisconnectResponse;
use crate::control::SetupRunRefreshResponse;
use crate::control::SetupRunVerificationFilters;
use crate::control::SetupRunVerificationResponse;
use crate::control::SetupVerificationTimeouts;
use crate::control::Sha256;
use crate::control::SourceKind;
use crate::control::TokenStoreError;
use crate::control::BACKEND_REQUEST_TIMEOUT;
use crate::control::DEVICE_CREDENTIAL_PREPARATION_CAPABILITY;
use crate::control::DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER;
use crate::control::OTTTO_CLIENT_NAME;
use crate::control::OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT;
use crate::control::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
use crate::control::OTTTO_SETUP_RUN_TOKEN_ACCOUNT;
use crate::control::OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION;
use crate::control::PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION;
use crate::control::SETUP_VERIFICATION_HTTP_TIMEOUT;
use crate::control::SETUP_VERIFICATION_MARKER_HTTP_TIMEOUT;
use crate::control::VERIFICATION_WAIT_TIMEOUT;

pub(in crate::control) fn supported_pending_credential_schema(version: u16) -> bool {
    matches!(
        version,
        PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION | OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
    )
}

/// Load the active device id and secret together. The server rejects one
/// without the other, so a missing or unreadable half yields no proof.
pub(in crate::control) fn load_device_release_proof() -> Option<DeviceReleaseProof> {
    let device = FileDeviceStore::default().load().ok().flatten()?;
    let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .ok()?;
    device_release_proof(device.device_id, device_secret)
}

pub(in crate::control) fn device_release_proof(
    device_id: String,
    device_secret: String,
) -> Option<DeviceReleaseProof> {
    if device_id.trim().is_empty() || device_secret.is_empty() {
        return None;
    }
    Some(DeviceReleaseProof {
        device_id,
        device_secret,
    })
}

/// Ask Ottto to release this Mac's registration with the device's own
/// secret, for a cloud logout whose setup run has already ended. Needs no
/// setup run. True only on a 200 that says `device_released: true`; any other
/// status (older servers answer 404 or 405), an unparsable body, or a
/// transport failure is not a release.
pub(in crate::control) fn release_device_without_setup_run(
    api_base_url: &str,
    release: &DeviceReleaseProof,
) -> bool {
    // SECURITY: the request carries the long-lived device secret. Gate the
    // base through the trusted-base validator, only put an id made of plain
    // path characters into the URL, and never follow a redirect: ureq would
    // forward the custom secret header to the redirect target, so a 3xx is
    // an unconfirmed release.
    let Ok(api_base_url) = validated_api_base_url(Some(api_base_url)) else {
        return false;
    };
    if !release
        .device_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    let url = api_url_with_base(
        &api_base_url,
        &format!("/api/v1/telemetry/devices/{}/release", release.device_id),
    );
    let Ok(_history_lock) = lock_history_recovery() else {
        return false;
    };
    let stores = history_stores();
    if stage_local_release(&api_base_url, release, &stores, history_now()).is_err() {
        return false;
    }
    crate::retry_tls::credential_agent()
        .post(&url)
        .set("Accept", "application/json")
        .set("X-Ottto-Device-Secret", &release.device_secret)
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_bytes(&[])
        .ok()
        .filter(|response| response.status() == 200)
        .and_then(|response| response.into_json::<DeviceSelfReleaseResponse>().ok())
        .is_some_and(|response| {
            remember_revocation_receipt(
                response.device_released,
                response.revocation_receipt,
                &stores,
                history_now(),
            );
            response.device_released
        })
}

pub(in crate::control) fn setup_run_disconnect_body(
    release: Option<&DeviceReleaseProof>,
) -> serde_json::Value {
    match release {
        Some(release) => json!({
            "reason": "logout",
            "release_device_id": release.device_id,
            "release_device_secret": release.device_secret,
        }),
        None => json!({ "reason": "logout" }),
    }
}

/// Mint a fresh `setup_run_token` for the current run using the daemon's
/// long-lived device secret. The token is persisted to Keychain and the
/// connection's expiry timestamp is updated. Returns the new token so the
/// caller can immediately retry whatever 401'd.
pub(in crate::control) fn refresh_setup_run_token_via_device_secret(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
) -> Result<RefreshedSetupRunToken, LocalApiError> {
    refresh_setup_run_token_checked(api_base_url, connection, |_| Ok(()))
}

/// Lets a caller refuse a refresh that would change its binding, before storing any update.
pub(in crate::control) fn refresh_setup_run_token_checked(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    check: impl FnOnce(&SetupRunRefreshResponse) -> Result<(), LocalApiError>,
) -> Result<RefreshedSetupRunToken, LocalApiError> {
    // SECURITY: this path POSTs the long-lived relay device_secret to the
    // backend. `connection.api_base_url` is deserialized from on-disk
    // connection.json (see `LocalConnectionBinding`) and is not trusted — a
    // co-resident attacker who tampers that file could otherwise exfiltrate the
    // secret to their own host. Gate the base through the same trusted-base
    // validator every other secret-bearing egress in this file uses, BEFORE
    // touching the device secret. Fail closed: both callers map an `Err` to a
    // reconnect/backend error, so an untrusted base never releases the secret.
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    crate::snapshot_client::ensure_no_incomplete_device_credential_promotion()
        .map_err(|_| LocalApiError::IdentityMutationInProgress)?;
    let device = FileDeviceStore::default()
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let device_secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .map_err(|_| LocalApiError::SetupRunConnectionMissing)?;

    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/refresh",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "device_id": device.device_id,
        "device_secret": device_secret,
    });
    let response: SetupRunRefreshResponse = backend_post_json(&url, &body, &[])?;
    check(&response)?;
    let mut refreshed = connection.clone();
    if let Some(setup_run_id) = response
        .setup_run_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        refreshed.setup_run_id = setup_run_id.to_string();
    }
    refreshed.setup_run_token_expires_at = response.expires_at.clone();
    let committed = {
        let _binding_lock = lock_setup_run_binding();
        commit_refreshed_setup_run_binding_locked(
            connection,
            &refreshed,
            &response.setup_run_token,
            &FileConnectionStore::default(),
            &KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
        )?
    };
    Ok(RefreshedSetupRunToken {
        run: response.run,
        setup_run_token: response.setup_run_token,
        connection: committed,
    })
}

/// The connection half of a refresh commit; a seam so storage failures can be
/// exercised without touching the real support directory.
pub(in crate::control) trait SetupRunConnectionStore {
    fn load_connection(&self) -> anyhow::Result<Option<LocalConnectionBinding>>;
    fn save_connection(&self, connection: &LocalConnectionBinding) -> anyhow::Result<()>;
}

impl SetupRunConnectionStore for FileConnectionStore {
    fn load_connection(&self) -> anyhow::Result<Option<LocalConnectionBinding>> {
        self.load()
    }

    fn save_connection(&self, connection: &LocalConnectionBinding) -> anyhow::Result<()> {
        self.save(connection)
    }
}

/// Persist a refreshed setup-run token and connection only if the persisted
/// binding is still the one this refresh belongs to, and return the binding
/// written. The caller holds the setup-run binding lock, which every writer
/// of these two stores (claim, switch, setup attach, terminal clear, logout
/// reset) also holds, so this compare-and-swap cannot interleave with a
/// reconnect or logout.
///
/// The persisted binding may name the refresh's own run, or the run the
/// backend just minted for (an earlier refresh rebinding to the latest run
/// persists that run while the in-memory binding keeps the old id). Only the
/// run id and token expiry change; the persisted record's other fields are
/// kept. Anything else means the binding was replaced or removed while the
/// refresh was in flight; the minted token is dropped and nothing is written.
/// If the connection write fails after the token write, the prior token is
/// put back (or the new one removed when none could be read), so the stores
/// keep the prior binding. The two stores are not written atomically: if that
/// rollback also fails, the new token stays beside the prior connection until
/// the next refresh.
pub(in crate::control) fn commit_refreshed_setup_run_binding_locked(
    expected: &LocalConnectionBinding,
    refreshed: &LocalConnectionBinding,
    setup_run_token: &str,
    connections: &impl SetupRunConnectionStore,
    tokens: &impl ControlTokenStore,
) -> Result<LocalConnectionBinding, LocalApiError> {
    let persisted = connections
        .load_connection()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    if !setup_run_binding_matches(&persisted, expected)
        && !setup_run_binding_matches(&persisted, refreshed)
    {
        return Err(LocalApiError::SetupRunConnectionMismatch);
    }
    let committed = LocalConnectionBinding {
        setup_run_id: refreshed.setup_run_id.clone(),
        setup_run_token_expires_at: refreshed.setup_run_token_expires_at.clone(),
        ..persisted
    };
    let prior_token = tokens.load().ok();
    tokens.save(setup_run_token).or_state_poisoned()?;
    if connections.save_connection(&committed).is_err() {
        let _ = match prior_token {
            Some(token) => tokens.save(&token),
            None => tokens.delete(),
        };
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(committed)
}

pub(crate) fn refresh_setup_run_token_for_persisted_connection() -> Result<(), LocalApiError> {
    let connection = FileConnectionStore::default()
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    refresh_setup_run_token_via_device_secret(&connection.api_base_url, &connection).map(|_| ())
}

pub(in crate::control) fn setup_run_token_for_connection(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
) -> Result<SetupRunCredentials, LocalApiError> {
    setup_run_token_for_connection_with_refresh(connection, || {
        refresh_setup_run_token_via_device_secret(api_base_url, connection)
    })
}

pub(in crate::control) fn setup_run_token_for_connection_with_refresh(
    connection: &LocalConnectionBinding,
    refresh: impl FnOnce() -> Result<RefreshedSetupRunToken, LocalApiError>,
) -> Result<SetupRunCredentials, LocalApiError> {
    crate::snapshot_client::ensure_no_incomplete_device_credential_promotion()
        .map_err(|_| LocalApiError::IdentityMutationInProgress)?;
    match KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() {
        Ok(token) => Ok(SetupRunCredentials {
            setup_run_token: token,
            connection: connection.clone(),
        }),
        Err(_) => refresh().map(|refreshed| SetupRunCredentials {
            setup_run_token: refreshed.setup_run_token,
            connection: refreshed.connection,
        }),
    }
}

pub(in crate::control) fn setup_run_request_with_refresh_mut<T>(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    request: impl Fn(&LocalConnectionBinding, &str) -> Result<T, LocalApiError>,
) -> Result<T, LocalApiError> {
    match request(&credentials.connection, &credentials.setup_run_token) {
        Ok(response) => Ok(response),
        Err(original) if is_setup_run_token_auth_error(&original) => {
            match refresh_setup_run_token_via_device_secret(api_base_url, &credentials.connection) {
                Ok(refreshed) => {
                    *credentials = SetupRunCredentials {
                        setup_run_token: refreshed.setup_run_token,
                        connection: refreshed.connection,
                    };
                    request(&credentials.connection, &credentials.setup_run_token)
                }
                Err(LocalApiError::SetupRunConnectionMissing) => Err(original),
                Err(other) => Err(other),
            }
        }
        Err(other) => Err(other),
    }
}

fn is_setup_run_token_auth_error(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status == Some(401) {
        return true;
    }
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let body = body.to_ascii_lowercase();
    body.contains("setup run companion token expired")
        || body.contains("setup run companion token is invalid")
}

/// Agent reads (context, costs, sessions, recommendations, provider impact)
/// refresh the setup-run token and retry once only on a backend 401. Unlike
/// `setup_run_request_with_refresh_mut`, a token-expiry body under another
/// status does not refresh. `read_url` builds the URL for whichever connection
/// is current, so the retry targets the refreshed run.
pub(in crate::control) fn agent_read_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    read_url: impl Fn(&str, &LocalConnectionBinding) -> String,
) -> Result<serde_json::Value, LocalApiError> {
    let read = |connection: &LocalConnectionBinding,
                setup_run_token: &str|
     -> Result<serde_json::Value, LocalApiError> {
        let url = read_url(api_base_url, connection);
        backend_get_agent_read_json(&url, &[("X-Ottto-Setup-Run-Token", setup_run_token)])
    };
    match read(connection, setup_run_token) {
        Ok(value) => Ok(value),
        Err(error) => {
            if matches!(&error, LocalApiError::Backend(details) if details.status == Some(401)) {
                let refreshed =
                    refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
                return read(&refreshed.connection, &refreshed.setup_run_token);
            }
            Err(error)
        }
    }
}

pub(in crate::control) fn disconnect_setup_run_with_refresh(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    release: Option<&DeviceReleaseProof>,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    match disconnect_setup_run_local_client(api_base_url, connection, setup_run_token, release) {
        Ok(response) => Ok(response),
        Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
            let refreshed = refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
            disconnect_setup_run_local_client(
                api_base_url,
                &refreshed.connection,
                &refreshed.setup_run_token,
                release,
            )
        }
        Err(other) => Err(other),
    }
}

fn disconnect_setup_run_local_client(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    release: Option<&DeviceReleaseProof>,
) -> Result<SetupRunDisconnectResponse, LocalApiError> {
    // SECURITY: a release proof carries the long-lived device secret. Gate the
    // base through the trusted-base validator here as well, so no caller can
    // send the secret to a base read from tampered on-disk state.
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/disconnect",
            connection.setup_run_id
        ),
    );
    let _history_lock = lock_history_recovery()?;
    let stores = history_stores();
    if let Some(release) = release {
        stage_local_release(&api_base_url, release, &stores, history_now())?;
    }
    let body = setup_run_disconnect_body(release);
    let mut response: SetupRunDisconnectResponse =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    remember_revocation_receipt(
        response.device_released,
        response.revocation_receipt.take(),
        &stores,
        history_now(),
    );
    Ok(response)
}

/// Call `wait_for_setup_run_verification_with_base` with one transparent
/// retry on 401: refresh the companion token via device-secret auth, then
/// re-issue the verify call with the new token. Other errors pass through.
pub(in crate::control) fn wait_for_verification_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    wait_for_setup_run_verification_with_refresh_mut(
        api_base_url,
        credentials,
        source,
        smoke_after,
        None,
    )
}

fn wait_for_setup_run_verification_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    wait_for_setup_run_verification_with_refresh_mut_timeout(
        api_base_url,
        credentials,
        source,
        smoke_after,
        filters,
        SetupVerificationTimeouts {
            wait: VERIFICATION_WAIT_TIMEOUT,
            request: SETUP_VERIFICATION_HTTP_TIMEOUT,
        },
    )
}

pub(in crate::control) fn wait_for_setup_run_verification_with_refresh_mut_timeout(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    timeouts: SetupVerificationTimeouts,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        wait_for_setup_run_verification_with_base_timeout(
            api_base_url,
            active,
            token,
            source,
            smoke_after,
            filters,
            timeouts,
        )
    })
}

pub(in crate::control) fn emit_setup_run_fast_verification_marker_with_refresh_mut(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    flow: &str,
) -> Result<String, LocalApiError> {
    let marker_id = format!("m3-{}-{}", source_slug(source), current_millis());
    let body = json!({
        "source": source_slug(source),
        "marker_id": marker_id,
        "details": {
            "flow": flow,
            "client": OTTTO_CLIENT_NAME,
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/verification-marker",
                active.setup_run_id
            ),
        );
        let _: serde_json::Value = backend_post_json_with_timeout(
            &url,
            &body,
            &[("X-Ottto-Setup-Run-Token", token)],
            SETUP_VERIFICATION_MARKER_HTTP_TIMEOUT,
        )?;
        Ok(marker_id.clone())
    })
}

pub(in crate::control) fn prepare_telemetry_device_registration(
    api_base_url: &str,
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
) -> Result<
    (
        DeviceCredentialPreparationApiResponse,
        Option<PriorDeviceCredential>,
        PendingDeviceCredentialRequestAuthority,
    ),
    LocalApiError,
> {
    let url = api_url_with_base(
        api_base_url,
        "/api/v1/telemetry/devices/registration-preparations",
    );
    let prior = prior_device_credential_for_registration()?;
    let request_authority = device_credential_request_authority(
        "register",
        &install_session.install_session_id,
        machine,
        prior.as_ref(),
        Some(IDENTITY_CONTINUITY_CAPABILITY),
    );
    let mut body =
        telemetry_device_register_body_with_prior(install_session, machine, prior.as_ref());
    body["credential_preparation_capability"] = json!(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY);
    body["credential_preparation_idempotency_key"] = json!(request_authority
        .credential_preparation_idempotency_key
        .clone());
    let prepared =
        backend_post_json(&url, &body, &[]).map_err(registration_history_choice_error)?;
    validate_device_credential_preparation(&url, &prepared, prior.as_ref())?;
    Ok((prepared, prior, request_authority))
}

pub(in crate::control) fn confirm_device_credential_preparation(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<DeviceCredentialConfirmationApiResponse, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    if !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
        || pending.confirmed_at.is_some()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    // The pending file is local state, not authority. Revalidate its base
    // before releasing the candidate secret in a request header.
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/device-credential-preparations/{}/confirm",
            pending.preparation_id
        ),
    );
    let body = json!({
        "capability": DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
        "credential_generation": pending.credential_generation,
    });
    let confirmed = backend_post_json(
        &url,
        &body,
        &[(
            DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER,
            candidate_secret,
        )],
    )
    .map_err(registration_history_choice_error)?;
    validate_device_credential_confirmation(&url, pending, &confirmed)?;
    Ok(confirmed)
}

pub(in crate::control) fn inspect_device_credential_preparation(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<DeviceCredentialPreparationStatusApiResponse, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/device-credential-preparations/{}",
            pending.preparation_id
        ),
    );
    let status = backend_get_json(
        &url,
        &[(
            DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER,
            candidate_secret,
        )],
    )?;
    validate_device_credential_status(&url, pending, &status)?;
    Ok(status)
}

pub(in crate::control) fn device_credential_preparation_idempotency_key(
    flow: &str,
    operation_id: &str,
    installation_id: &str,
) -> String {
    let mut digest = Sha256::new();
    for part in [
        DEVICE_CREDENTIAL_PREPARATION_CAPABILITY,
        flow,
        operation_id,
        installation_id,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

pub(in crate::control) fn device_credential_request_authority(
    flow: &str,
    operation_id: &str,
    machine: &MachineIdentity,
    prior: Option<&PriorDeviceCredential>,
    identity_continuity_capability: Option<&str>,
) -> PendingDeviceCredentialRequestAuthority {
    PendingDeviceCredentialRequestAuthority {
        flow: flow.to_string(),
        credential_preparation_idempotency_key: device_credential_preparation_idempotency_key(
            flow,
            operation_id,
            &machine.installation_id,
        ),
        machine_id: machine.machine_id.clone(),
        installation_id: machine.installation_id.clone(),
        hardware_uuid: machine.hardware_uuid.clone(),
        account_scope: machine.account_scope.clone(),
        identity_continuity_capability: identity_continuity_capability.map(str::to_string),
        prior_device_id: prior.map(|value| value.device_id.clone()),
        prior_device_sources: prior.map(|value| value.device_sources.clone()),
        prior_secret_commitment_sha256: prior.map(|value| secret_sha256(&value.device_secret)),
        canonical_snapshot_namespace: None,
        incoming_snapshot_namespace: None,
    }
}

pub(in crate::control) fn pending_credential_owner(
    pending: &PendingDeviceCredentialPreparation,
) -> Option<LocalCredentialOwner> {
    let claim = pending.claim_commit.as_ref()?;
    Some(LocalCredentialOwner {
        user_id: claim.target_user_id.clone(),
        organization_id: claim.account.organization.as_ref()?.id.clone(),
        api_base_url: pending.api_base_url.clone(),
    })
}

/// Exact claim identity; history never supplies authentication.
pub(in crate::control) fn pending_owner_snapshot_key(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<OwnerSnapshotKey, LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let authority = pending
        .request_authority
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let owner = pending_credential_owner(pending).ok_or(LocalApiError::StatePoisoned)?;
    if authority.flow != "setup_claim"
        || claim.account.user.as_ref().map(|u| &u.id) != Some(&owner.user_id)
        || owner.api_base_url != validated_api_base_url(Some(&claim.connection.api_base_url))?
        || pending.device.machine_id.as_deref() != Some(authority.machine_id.as_str())
        || claim.connection.machine_id.as_deref() != Some(authority.machine_id.as_str())
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(OwnerSnapshotKey {
        owner,
        machine_id: authority.machine_id.clone(),
        installation_id: authority.installation_id.clone(),
        account_scope: authority
            .account_scope
            .clone()
            .filter(|v| !v.is_empty())
            .ok_or(LocalApiError::StatePoisoned)?,
    })
}

#[cfg(test)]
thread_local! {
    pub(in crate::control) static OWNER_SNAPSHOT_MACHINE_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// One physical-observation boundary for selection, staging, promotion and logout.
fn owner_snapshot_live_machine(
    key: &OwnerSnapshotKey,
    hardware: Option<&str>,
) -> Result<bool, LocalApiError> {
    #[cfg(test)]
    if let Some(allowed) = OWNER_SNAPSHOT_MACHINE_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(allowed && tests::owner_return_test_machine(key)?);
    }
    let Some(machine) = FileMachineStore::default().load().or_state_poisoned()? else {
        return Ok(false);
    };
    Ok(machine.machine_id == key.machine_id
        && machine.installation_id == key.installation_id
        && crate::local_account_scope(&machine.machine_id).as_deref()
            == Some(key.account_scope.as_str())
        && crate::grant_rebind::verified_live_hardware().is_ok()
        && crate::grant_rebind::verify_hardware(
            hardware,
            crate::grant_rebind::live_hardware_id().as_deref(),
        )
        .is_ok())
}

/// Preserve main's same-owner rotation policy before consulting return history.
fn select_rotation_snapshot_namespace(
    pending: &mut PendingDeviceCredentialPreparation,
    prior: Option<&PriorDeviceCredential>,
) -> bool {
    let (Some(prior), Some(claim), Some(authority)) = (
        prior,
        pending.claim_commit.as_ref(),
        pending.request_authority.as_mut(),
    ) else {
        return false;
    };
    let Some(owner) = prior.owner.as_ref() else {
        return false;
    };
    if authority.flow == "setup_claim"
        && authority.prior_device_id.as_deref() == Some(prior.device_id.as_str())
        && pending.device.machine_id.as_deref() == Some(authority.machine_id.as_str())
        && claim.account.user.as_ref().map(|user| &user.id) == Some(&owner.user_id)
        && claim.account.organization.as_ref().map(|org| &org.id) == Some(&owner.organization_id)
        && claim.connection.api_base_url.trim_end_matches('/')
            == owner.api_base_url.trim_end_matches('/')
    {
        authority.canonical_snapshot_namespace = Some(prior.snapshot_namespace.clone());
        return true;
    }
    false
}

pub(in crate::control) fn select_owner_snapshot_namespace(
    pending: &mut PendingDeviceCredentialPreparation,
    candidate: &str,
    prior: Option<&PriorDeviceCredential>,
    store: &FileOwnerSnapshotNamespaceStore,
    support: &Path,
) -> Result<(), LocalApiError> {
    if let Some(existing) =
        FilePendingDeviceCredentialStore::new(support.join("pending-device-credential.json"))
            .load()
            .or_state_poisoned()?
        && existing.preparation_id == pending.preparation_id
    {
        pending.schema_version = existing.schema_version;
        pending.request_authority = existing.request_authority;
        return Ok(()); // Immutable journal equality is checked at staging.
    }
    // Rotation keeps the released v2 path, including when live hardware,
    // installation scope, history or source custody is unavailable.
    if select_rotation_snapshot_namespace(pending, prior) {
        return Ok(());
    }
    let key = match pending_owner_snapshot_key(pending) {
        Ok(key) => key,
        Err(_) => return Ok(()),
    };
    let hardware = pending
        .request_authority
        .as_ref()
        .and_then(|a| a.hardware_uuid.as_deref());
    if !owner_snapshot_live_machine(&key, hardware)? {
        return Ok(());
    }
    let history = store.load().or_state_poisoned()?;
    let recorded = history.iter().find(|row| row.key == key);
    let selected = match recorded {
        Some(row)
            if crate::snapshot_sync::snapshot_namespace_has_store(support, &row.namespace)
                .or_state_poisoned()? =>
        {
            Some(row.namespace.clone())
        }
        _ => None,
    };
    let namespace = selected.clone().unwrap_or_else(|| {
        crate::snapshot_sync::snapshot_destination_namespace(&pending.device, candidate, None)
    });
    let authority = pending
        .request_authority
        .as_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    authority.canonical_snapshot_namespace = selected;
    authority.incoming_snapshot_namespace = Some(OwnerSnapshotNamespace { key, namespace });
    pending.schema_version = OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION;
    Ok(())
}

/// Called at the durable staging and promotion boundaries.
pub(in crate::control) fn validate_owner_snapshot_selection(
    pending: &PendingDeviceCredentialPreparation,
    candidate: &str,
    store: &FileOwnerSnapshotNamespaceStore,
) -> Result<(), LocalApiError> {
    validate_pending_prior_credential_binding(pending)?;
    if pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
        return Ok(());
    }
    let authority = pending
        .request_authority
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let incoming = authority
        .incoming_snapshot_namespace
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    incoming.validate().or_state_poisoned()?;
    if incoming.key != pending_owner_snapshot_key(pending)?
        || !owner_snapshot_live_machine(&incoming.key, authority.hardware_uuid.as_deref())?
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let history = store.load().or_state_poisoned()?;
    if let Some(namespace) = authority.canonical_snapshot_namespace.as_ref() {
        if incoming.namespace != *namespace
            || !history
                .iter()
                .any(|row| row.key == incoming.key && row.namespace == *namespace)
        {
            return Err(LocalApiError::StatePoisoned);
        }
    } else if incoming.namespace
        != crate::snapshot_sync::snapshot_destination_namespace(&pending.device, candidate, None)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(in crate::control) fn publish_owner_snapshot_history(
    pending: &PendingDeviceCredentialPreparation,
    store: &FileOwnerSnapshotNamespaceStore,
) -> Result<(), LocalApiError> {
    if pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
        return Ok(());
    }
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let incoming = pending
        .request_authority
        .as_ref()
        .and_then(|a| a.incoming_snapshot_namespace.as_ref())
        .ok_or(LocalApiError::StatePoisoned)?;
    store
        .upsert(std::slice::from_ref(incoming))
        .or_state_poisoned()
}

/// Mid-claim logout keeps existing history and never seeds from mixed halves.
pub(in crate::control) fn owner_snapshot_logout_can_retain_active(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<bool, LocalApiError> {
    if !supported_pending_credential_schema(pending.schema_version) {
        return Err(LocalApiError::StatePoisoned);
    }
    validate_pending_prior_credential_binding(pending)?;
    Ok(pending.confirmed_at.is_none() && !pending.preconfirm_guards_passed)
}

pub(in crate::control) fn seed_owner_snapshot_history_for_logout() -> Result<bool, LocalApiError> {
    let store = FileOwnerSnapshotNamespaceStore::default();
    if let Some(pending) = FilePendingDeviceCredentialStore::default()
        .load()
        .or_state_poisoned()?
        && !owner_snapshot_logout_can_retain_active(&pending)?
    {
        return Ok(false);
    }
    let Some(machine) = FileMachineStore::default().load().or_state_poisoned()? else {
        return Ok(true);
    };
    let Some(scope) = crate::local_account_scope(&machine.machine_id) else {
        return Ok(true);
    };
    // Missing active secret is not a reason to make local logout unavailable.
    match KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).load() {
        Err(TokenStoreError::Missing) => return Ok(true),
        Err(_) => return Err(LocalApiError::StatePoisoned),
        Ok(_) => {}
    }
    if let Some(prior) = prior_device_credential_for_registration()?
        && let Some(mut owner) = prior.owner
    {
        owner.api_base_url = validated_api_base_url(Some(&owner.api_base_url))?;
        let key = OwnerSnapshotKey {
            owner,
            machine_id: machine.machine_id,
            installation_id: machine.installation_id,
            account_scope: scope,
        };
        if prior.machine_id.as_deref() == Some(key.machine_id.as_str())
            && owner_snapshot_live_machine(&key, machine.hardware_uuid.as_deref())?
        {
            if store
                .upsert(&[OwnerSnapshotNamespace {
                    key,
                    namespace: prior.snapshot_namespace,
                }])
                .is_err()
            {
                crate::local_resource_diagnostics::traversal_point(
                    "owner_history_seed_skipped",
                    "control",
                    &json!({"skipped_seeds": 1}),
                );
            }
        }
    }
    Ok(true)
}

pub(in crate::control) fn same_prior_device_authority(
    expected: Option<&PriorDeviceCredential>,
    actual: Option<&PriorDeviceCredential>,
) -> bool {
    match (expected, actual) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            let expected_secret_commitment = secret_sha256(&expected.device_secret);
            let actual_secret_commitment = secret_sha256(&actual.device_secret);
            expected.machine_id == actual.machine_id
                && expected.device_id == actual.device_id
                && expected.device_sources == actual.device_sources
                && expected.owner == actual.owner
                && expected.snapshot_namespace == actual.snapshot_namespace
                && constant_work_eq(
                    expected_secret_commitment.as_bytes(),
                    actual_secret_commitment.as_bytes(),
                )
        }
        _ => false,
    }
}

/// The operation id is server-issued and survives a daemon crash. Retrying the
/// same install session or claim therefore reuses one idempotency key. An
/// expired attempt obtains a new boundary only by obtaining a new server
/// install session or setup claim; the daemon never spins on a locally minted
/// replacement key after a definitive 410.
pub(in crate::control) fn validate_device_credential_preparation(
    url: &str,
    prepared: &DeviceCredentialPreparationApiResponse,
    prior: Option<&PriorDeviceCredential>,
) -> Result<(), LocalApiError> {
    if prepared.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || prepared.preparation_id.trim().is_empty()
        || prepared.expires_at.trim().is_empty()
        || prepared.credential_generation == 0
        || prepared.device.id.trim().is_empty()
        || prepared.device.sources.is_empty()
        || prepared.candidate_secret.trim().is_empty()
    {
        return Err(backend_response_unexpected(
            url,
            "telemetry registration returned an incomplete credential preparation".to_string(),
        ));
    }
    if prepared
        .identity_continuity_capability
        .as_deref()
        .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
    {
        return Err(backend_response_unexpected(
            url,
            "telemetry registration returned an unsupported identity continuity capability"
                .to_string(),
        ));
    }
    match prior {
        Some(prior)
            if !prepared.credential_rotation_planned
                || prepared.identity_continuity_capability.as_deref()
                    != Some(IDENTITY_CONTINUITY_CAPABILITY)
                || prepared.prior_device_id.as_deref() != Some(prior.device_id.as_str()) =>
        {
            Err(backend_response_unexpected(
                url,
                "telemetry registration returned inconsistent credential rotation preparation"
                    .to_string(),
            ))
        }
        None if prepared.credential_rotation_planned || prepared.prior_device_id.is_some() => {
            Err(backend_response_unexpected(
                url,
                "telemetry registration planned a prior-device rotation without prior authority"
                    .to_string(),
            ))
        }
        _ => Ok(()),
    }
}

pub(in crate::control) fn validate_device_credential_confirmation(
    url: &str,
    pending: &PendingDeviceCredentialPreparation,
    confirmed: &DeviceCredentialConfirmationApiResponse,
) -> Result<(), LocalApiError> {
    if confirmed.preparation_id != pending.preparation_id
        || confirmed.status != "confirmed"
        || confirmed.confirmed_at.trim().is_empty()
        || confirmed.credential_generation != pending.credential_generation
        || confirmed.device.id != pending.device.device_id
        || confirmed.device.machine_id != pending.device.machine_id
        || confirmed.device.sources != pending.device.sources
    {
        return Err(backend_response_unexpected(
            url,
            "credential confirmation did not match the staged preparation".to_string(),
        ));
    }
    if confirmed
        .identity_continuity_capability
        .as_deref()
        .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
        || confirmed.credential_rotation_performed != confirmed.rotated_prior_device_id.is_some()
    {
        return Err(backend_response_unexpected(
            url,
            "credential confirmation returned inconsistent rotation proof".to_string(),
        ));
    }
    if let Some(prior_device_id) = pending
        .request_authority
        .as_ref()
        .and_then(|authority| authority.prior_device_id.as_deref())
    {
        if confirmed.identity_continuity_capability.as_deref()
            != Some(IDENTITY_CONTINUITY_CAPABILITY)
            || !confirmed.credential_rotation_performed
            || confirmed.rotated_prior_device_id.as_deref() != Some(prior_device_id)
        {
            return Err(backend_response_unexpected(
                url,
                "credential confirmation did not match the journaled prior authority".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_device_credential_status(
    url: &str,
    pending: &PendingDeviceCredentialPreparation,
    status: &DeviceCredentialPreparationStatusApiResponse,
) -> Result<(), LocalApiError> {
    if status.preparation_id != pending.preparation_id
        || status.expires_at != pending.expires_at
        || status.credential_generation != pending.credential_generation
        || status.device.id != pending.device.device_id
        || status.device.machine_id != pending.device.machine_id
        || status.device.sources != pending.device.sources
        || !matches!(
            status.status.as_str(),
            "pending" | "confirmed" | "expired" | "superseded"
        )
        || (status.status == "confirmed") != status.confirmed_at.is_some()
    {
        return Err(backend_response_unexpected(
            url,
            "credential preparation status did not match the staged generation".to_string(),
        ));
    }
    Ok(())
}

pub(in crate::control) const IDENTITY_CONTINUITY_CAPABILITY: &str = "prior_device_credential_v1";

// Advertise only with the uploader that reprojects health and heartbeat using
// the paired machine id. This is compatibility information, not authority.
pub(in crate::control) const MACHINE_IDENTITY_CAPABILITY: &str = "paired_machine_local_health_v1";

pub(in crate::control) struct PriorDeviceCredential {
    pub(in crate::control) machine_id: Option<String>,
    pub(in crate::control) device_id: String,
    pub(in crate::control) device_sources: Vec<String>,
    pub(in crate::control) device_secret: String,
    /// Account the credential was installed for, if known.
    pub(in crate::control) owner: Option<LocalCredentialOwner>,
    /// The namespace its local snapshot history lives under.
    pub(in crate::control) snapshot_namespace: String,
}

pub(in crate::control) fn prior_device_credential_for_registration(
) -> Result<Option<PriorDeviceCredential>, LocalApiError> {
    let active_store = FileDeviceStore::default();
    if active_store.load().or_state_poisoned()?.is_some() {
        return prior_device_credential_with_stores(
            &active_store,
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            connected_account_owner(),
        );
    }
    // A retained prior carries the owner recorded before logout reset the account.
    prior_device_credential_with_stores(
        &FileDeviceStore::new(default_prior_device_path()),
        &KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT),
        None,
    )
}

/// Owner of a legacy active binding written before credentials recorded one:
/// the bound account, only while it is connected.
fn connected_account_owner() -> Option<LocalCredentialOwner> {
    let account = FileAccountStore::default().load().ok()?;
    let connection = FileConnectionStore::default().load().ok()??;
    if account.state != LocalAccountState::Connected {
        return None;
    }
    Some(LocalCredentialOwner {
        user_id: account.user?.id,
        organization_id: account.organization?.id,
        api_base_url: connection.api_base_url,
    })
}

pub(in crate::control) fn retain_prior_device_credential_for_logout() -> Result<(), LocalApiError> {
    retain_prior_device_credential_with_stores(
        &FileDeviceStore::default(),
        &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        &FileDeviceStore::new(default_prior_device_path()),
        &KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT),
        connected_account_owner(),
    )
}

pub(in crate::control) fn retain_prior_device_credential_with_stores(
    active_device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
    prior_device_store: &FileDeviceStore,
    prior_secret_store: &impl ControlTokenStore,
    legacy_owner: Option<LocalCredentialOwner>,
) -> Result<(), LocalApiError> {
    let Some(mut envelope) = active_device_store.load_envelope().or_state_poisoned()? else {
        return Ok(());
    };
    let secret = match active_secret_store.load() {
        Ok(secret) => secret,
        Err(TokenStoreError::Missing) => {
            // The active binding was already incomplete before logout. Do not
            // fail logout or reuse an unrelated older proof; the next claim
            // will surface the typed replacement path.
            prior_device_store.reset().or_state_poisoned()?;
            // The public device-id half is the authority selector. Removing it
            // makes any orphaned secret unusable; secret deletion is best
            // effort because a locked Keychain must not block local logout.
            let _ = prior_secret_store.delete();
            return Ok(());
        }
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    if envelope.device.device_id.trim().is_empty() || secret.trim().is_empty() {
        return Err(LocalApiError::StatePoisoned);
    }
    prior_secret_store.save(&secret).or_state_poisoned()?;
    envelope.continuity.owner = envelope.continuity.owner.take().or(legacy_owner);
    prior_device_store
        .save_envelope(&envelope)
        .or_state_poisoned()
}

pub(in crate::control) fn clear_prior_device_credential() -> Result<(), LocalApiError> {
    clear_prior_device_selector()?;
    KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT)
        .delete()
        .or_state_poisoned()
}

pub(in crate::control) fn clear_prior_device_selector() -> Result<(), LocalApiError> {
    FileDeviceStore::new(default_prior_device_path())
        .reset()
        .map(|_| ())
        .or_state_poisoned()
}

pub(in crate::control) fn prior_device_credential_with_stores(
    device_store: &FileDeviceStore,
    secret_store: &impl ControlTokenStore,
    legacy_owner: Option<LocalCredentialOwner>,
) -> Result<Option<PriorDeviceCredential>, LocalApiError> {
    let Some(LocalDeviceEnvelope { device, continuity }) =
        device_store.load_envelope().or_state_poisoned()?
    else {
        return Ok(None);
    };
    let device_secret = secret_store.load().or_state_poisoned()?;
    if device.device_id.trim().is_empty() || device_secret.trim().is_empty() {
        return Err(LocalApiError::StatePoisoned);
    }
    let snapshot_namespace = crate::snapshot_sync::snapshot_destination_namespace(
        &device,
        &device_secret,
        continuity.snapshot_namespace.as_ref(),
    );
    Ok(Some(PriorDeviceCredential {
        machine_id: device.machine_id,
        device_id: device.device_id,
        device_sources: device.sources,
        device_secret,
        owner: continuity.owner.or(legacy_owner),
        snapshot_namespace,
    }))
}

#[cfg(test)]
pub(in crate::control) fn telemetry_device_register_body(
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
) -> serde_json::Value {
    telemetry_device_register_body_with_prior(install_session, machine, None)
}

pub(in crate::control) fn telemetry_device_register_body_with_prior(
    install_session: &InstallSessionApiResponse,
    machine: &MachineIdentity,
    prior: Option<&PriorDeviceCredential>,
) -> serde_json::Value {
    let mut body = json!({
        "install_session_id": install_session.install_session_id,
        "install_session_token": install_session.install_session_token,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "client_name": OTTTO_CLIENT_NAME,
        "client_version": machine.local_platform_version,
        "machine_id": machine.machine_id,
        "machine_identity_capability": MACHINE_IDENTITY_CAPABILITY,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "identity_continuity_capability": IDENTITY_CONTINUITY_CAPABILITY,
    });
    if let Some(prior) = prior {
        body["prior_device_id"] = json!(prior.device_id);
        body["prior_device_secret"] = json!(prior.device_secret);
    }
    body
}

pub(in crate::control) fn record_install_session_event(
    api_base_url: &str,
    install_session_id: &str,
    install_session_token: &str,
    event: InstallSessionEvent<'_>,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/telemetry/devices/install-sessions/{install_session_id}/events"),
    );
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "metadata": event.metadata,
        "device_id": event.device_id,
    });
    let _: serde_json::Value = backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Install-Session-Token", install_session_token)],
    )?;
    Ok(())
}
