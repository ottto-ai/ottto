//! setup claims for local control.

#[cfg(test)]
use crate::control::BTreeMap;
use crate::control::{
    api_url, api_url_with_base, append_nonce_to_claim_url, backend_error_from_ureq,
    backend_get_json, backend_post_json, backend_response_unexpected, backend_success,
    clear_prior_device_credential, clear_prior_device_selector,
    confirm_device_credential_preparation, current_rfc3339_timestamp, default_support_dir,
    device_credential_request_authority, disconnect_setup_run_with_refresh, fs,
    generate_control_token, inspect_device_credential_preparation, io, json,
    load_device_release_proof, pending_credential_owner, prior_device_credential_for_registration,
    publish_owner_snapshot_history, reattach_required_state, redact_inline,
    relay_token_request_payload, release_device_without_setup_run,
    request_snapshot_sync_after_device_registration, require_authorized_local_client,
    require_setup_run_still_bound, retain_prior_device_credential_for_logout,
    safe_backend_endpoint, same_prior_device_authority, seed_owner_snapshot_history_for_logout,
    select_owner_snapshot_namespace, status_for, supported_pending_credential_schema,
    terminal_refresh_rejection, validate_device_credential_preparation,
    validate_owner_snapshot_selection, validated_api_base_url, AtomicU64, AuthCompleteResponse,
    AuthResetResponse, AuthStartResponse, BackendErrorDetails, BackendErrorKind, ControlTokenStore,
    Deserialize, DeserializeOwned, DeviceCredentialContinuity,
    DeviceCredentialPreparationApiResponse, DeviceReleaseProof, Digest, FileAccountStore,
    FileConnectionStore, FileDeviceStore, FileMachineStore, FileOwnerSnapshotNamespaceStore,
    FilePendingDeviceCredentialStore, KeychainSecretStore, LocalAccountBinding,
    LocalAccountOrganization, LocalAccountState, LocalAccountUser, LocalApiError,
    LocalConnectionBinding, LocalDaemon, LocalDeviceBinding, LocalDeviceCredentialBinding,
    MachineIdentity, Mutex, MutexGuard, OrStatePoisoned, Ordering, PathBuf, PendingAuthClaim,
    PendingClaimCredentialCommit, PendingDeviceCredentialPreparation,
    PendingDeviceCredentialRequestAuthority, PriorDeviceCredential, RequestAuthorization,
    SecretString, Serialize, SetupClaimCompleteResponse, SetupClaimCompletion,
    SetupClaimCreateResponse, SetupRunDisconnectResponse, Sha256, SnapshotNamespaceAlias,
    StableMessage, StagedAccountSwitch, TerminalRefreshRejection, TokenStoreError,
    BACKEND_REQUEST_TIMEOUT, DEVICE_CREDENTIAL_PREPARATION_CAPABILITY, HISTORY_BROWSER_ACCOUNT,
    HISTORY_MARKER_ACCOUNT, HISTORY_PROOF_ACCOUNT, IDENTITY_CONTINUITY_CAPABILITY,
    MACHINE_IDENTITY_CAPABILITY, OTTTO_CLIENT_NAME, OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT, OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_REVOCATION_RECEIPT_ACCOUNT,
    OTTTO_SETUP_RUN_TOKEN_ACCOUNT, OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION,
    PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION, PROTOCOL_VERSION,
};
pub(in crate::control) mod credentials;

// Serializes every account/device identity mutation with Codex cloud-task I/O
// admission. The same lock covers that admission and the identity write/reset.
static SETUP_RUN_BINDING_LOCK: Mutex<()> = Mutex::new(());

pub(in crate::control) static IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(0);

static NEXT_IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn lock_setup_run_binding() -> MutexGuard<'static, ()> {
    SETUP_RUN_BINDING_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn try_lock_setup_run_binding() -> Option<MutexGuard<'static, ()>> {
    SETUP_RUN_BINDING_LOCK.try_lock().ok()
}

pub(crate) fn identity_mutation_in_progress() -> bool {
    IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire) != 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::control) struct LocalIdentityAuthoritySnapshot {
    pub(in crate::control) account: LocalAccountBinding,
    pub(in crate::control) device: Option<LocalDeviceBinding>,
}

pub(in crate::control) struct IdentityMutationReservation {
    pub(in crate::control) id: u64,
    pub(in crate::control) snapshot: LocalIdentityAuthoritySnapshot,
}

impl IdentityMutationReservation {
    pub(in crate::control) fn validate_locked(&self) -> Result<(), LocalApiError> {
        require_identity_mutation_reservation(Some(self))?;
        if load_local_identity_authority_snapshot()? != self.snapshot {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        Ok(())
    }
}

impl Drop for IdentityMutationReservation {
    fn drop(&mut self) {
        let _ = IDENTITY_MUTATION_RESERVATION.compare_exchange(
            self.id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

pub(in crate::control) fn reserve_identity_mutation(
) -> Result<IdentityMutationReservation, LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reserve_identity_mutation_locked()
}

/// [`reserve_identity_mutation`] for a caller already holding the identity
/// lifecycle lock.
fn reserve_identity_mutation_locked() -> Result<IdentityMutationReservation, LocalApiError> {
    require_identity_mutation_reservation(None)?;
    let snapshot = load_local_identity_authority_snapshot()?;
    crate::account_nicknames::invalidate_locked();
    let id = NEXT_IDENTITY_MUTATION_RESERVATION.fetch_add(1, Ordering::Relaxed);
    if id == 0
        || IDENTITY_MUTATION_RESERVATION
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let reservation = IdentityMutationReservation { id, snapshot };
    // The reservation closes new Codex cloud-task admission. Drain work
    // already admitted before replacing local identity.
    crate::cloud_sessions::CloudSessionCheckpointStore::default()
        .wait_for_collector_io_idle(crate::cloud_sessions::COLLECTOR_IO_STOP_TIMEOUT)
        .map_err(|_| LocalApiError::CloudSessionCleanupRequired)?;
    Ok(reservation)
}

pub(in crate::control) fn require_identity_mutation_reservation(
    owner: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    let active = IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire);
    if match owner {
        Some(owner) => active == owner.id,
        None => active == 0,
    } {
        Ok(())
    } else {
        Err(LocalApiError::IdentityMutationInProgress)
    }
}

fn load_local_identity_authority_snapshot() -> Result<LocalIdentityAuthoritySnapshot, LocalApiError>
{
    let account = FileAccountStore::default().load().or_state_poisoned()?;
    let device = FileDeviceStore::default().load().or_state_poisoned()?;
    Ok(LocalIdentityAuthoritySnapshot { account, device })
}

pub(in crate::control) fn auth_start(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<AuthStartResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    // A connected Mac whose setup run Ottto no longer accepts can only recover
    // through a fresh claim: Verify and `ottto doctor` tell the user to sign
    // in, so refusing here would dead-end them. The claim keeps the bound
    // user, and completing it for that user replaces the dead binding.
    let history_pending = local_history_recovery_expected()?
        || registration_history_choice_account(&status.account)
        || history_load::<StoredHistoryBrowserClaim>(history_stores().browser.as_ref())
            .is_ok_and(|claim| claim.is_some_and(|claim| claim.registration_pending))
        || history_account_store()
            .load()
            .is_ok_and(|account| registration_history_choice_account(&account));
    if status.account.state == LocalAccountState::Connected
        && status.account.user.is_some()
        && !history_pending
        && !daemon.connected_setup_run_needs_reconnect()?
    {
        return Err(LocalApiError::InvalidRequest(
            "This Mac is already connected. Run `ottto account` to view it, or `ottto logout` before pairing a different account."
                .to_string(),
        ));
    }
    // Idempotent re-trigger: while a claim is in flight and unexpired,
    // repeated Sign-in presses return the SAME claim instead of minting a
    // parallel one. Racing claims were one writer behind the observed
    // ClaimPending/ResetRequired status flip-flop (a completion for claim A
    // landing while claim B had already replaced the pending state).
    if let Some((pending, account)) = daemon.pending_auth_claim_snapshot()? {
        if matches!(
            account.state,
            LocalAccountState::ClaimPending | LocalAccountState::ReattachRequired
        ) && !auth_claim_is_expired(&pending.expires_at)
        {
            return Ok(AuthStartResponse {
                account,
                claim_code: pending.claim_code,
                claim_url: pending.claim_url,
                nonce: pending.nonce,
                expires_at: pending.expires_at,
            });
        }
    }
    if let Some(pending) =
        resume_history_browser_claim(&status.machine, &validated_api_base_url(None)?)?
    {
        let response = begin_durable_browser_claim(daemon, pending)?;
        crate::snapshot_sync::reset_relay_authorization_backoff();
        return Ok(response);
    }
    if !history_pending {
        discard_abandoned_unconfirmed_claim_credential()?;
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = create_setup_claim(&status.machine, &nonce)?;
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let claim_url = append_nonce_to_claim_url(&claim.claim_url, &nonce);
    let response = begin_durable_browser_claim(
        daemon,
        PendingAuthClaim {
            claim_code: claim.claim_code,
            claim_token: claim.claim_token,
            nonce,
            claim_url,
            expires_at: claim.expires_at,
        },
    )?;
    crate::snapshot_sync::reset_relay_authorization_backoff();
    Ok(response)
}

pub(in crate::control) fn begin_durable_browser_claim(
    daemon: &LocalDaemon,
    pending: PendingAuthClaim,
) -> Result<AuthStartResponse, LocalApiError> {
    let _identity_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let registration = history_account_store()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account));
    let response = daemon.begin_auth_with_claim(pending)?;
    let mut persisted = response.account.clone();
    if registration {
        persisted.message = Some(registration_history_choice_message());
    }
    history_account_store()
        .save(&persisted)
        .or_state_poisoned()?;
    Ok(response)
}

fn retire_refused_registration_after_browser_answer(claim_code: &str) -> Result<(), LocalApiError> {
    retire_refused_registration_after_browser_answer_with_stores(claim_code, &history_stores())
}

pub(in crate::control) fn retire_refused_registration_after_browser_answer_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let browser: Option<StoredHistoryBrowserClaim> = match history_load(stores.browser.as_ref()) {
        Ok(browser) => browser,
        Err(_) if !local_history_recovery_expected()? => return Ok(()),
        Err(error) => return Err(error),
    };
    if !browser.is_some_and(|browser| {
        browser.registration_pending && browser.claim.claim_code == claim_code
    }) {
        return Ok(());
    }
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if pending.claim_commit.is_some() {
        return Ok(());
    }
    if pending.confirmed_at.is_some() {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let candidate = secret_store.load().or_state_poisoned()?;
    match inspect_device_credential_preparation(&pending, &candidate) {
        Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) if backend_error_has_status(&error, 410) => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) => Err(error),
        Ok(_) => Err(LocalApiError::IdentityMutationInProgress),
    }
}

fn history_recovery_indicator_path() -> PathBuf {
    history_support_dir().join("local-history-recovery-required")
}

pub(in crate::control) fn local_history_recovery_expected() -> Result<bool, LocalApiError> {
    // Presence only: no device selector, timestamp, receipt, or credential is
    // mirrored here. The actual marker/proof remain Keychain-only. This lets a
    // locked optional Keychain be distinguished from ordinary first sign-in,
    // without changing the account captured by an identity reservation.
    match fs::symlink_metadata(history_recovery_indicator_path()) {
        Ok(metadata) if metadata.is_file() => return Ok(true),
        Ok(_) => return Err(LocalApiError::StatePoisoned),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LocalApiError::StatePoisoned),
    }
    history_account_store()
        .load()
        .map(|account| registration_history_choice_account(&account))
        .or_state_poisoned()
}

pub(in crate::control) fn persist_local_release_expected() -> Result<(), LocalApiError> {
    ottto_core::write_owner_only_file_atomic(&history_recovery_indicator_path(), b"1")
        .or_state_poisoned()
}

fn clear_local_release_expected() -> Result<(), LocalApiError> {
    match fs::remove_file(history_recovery_indicator_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}

pub(in crate::control) fn registration_history_choice_account(
    account: &LocalAccountBinding,
) -> bool {
    account
        .message
        .as_ref()
        .is_some_and(|m| m.code == "history_choice_required")
}

pub(in crate::control) fn registration_history_choice_required(error: &LocalApiError) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(400)
        && (details.reason_code.as_deref() == Some("history_choice_required") || auth_complete_error_is_pending(error)))
}

fn registration_history_choice_message() -> StableMessage {
    StableMessage {
        code: "history_choice_required".to_string(),
        text: "Waiting for browser sign-in to finish.".to_string(),
    }
}

fn persist_registration_history_choice() -> Result<(), LocalApiError> {
    let _lock = lock_setup_run_binding();
    let store = history_account_store();
    let mut account = store.load().or_state_poisoned()?;
    // Preserve the bound identity and all credential journals. This is a
    // durable user action, not an authority transition or a failed install.
    account.state = LocalAccountState::ReattachRequired;
    account.message = Some(registration_history_choice_message());
    account.can_reconnect = Some(true);
    store.save(&account).or_state_poisoned()
}

pub(in crate::control) fn registration_history_choice_error(error: LocalApiError) -> LocalApiError {
    if registration_history_choice_required(&error) {
        if let Err(error) = persist_registration_history_choice() {
            return error;
        }
    }
    error
}

pub(in crate::control) fn reoffer_registration_browser_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    base: &str,
) -> Result<AuthStartResponse, LocalApiError> {
    daemon.mark_history_choice_required()?;
    if let Some((claim, _)) = daemon.pending_auth_claim_snapshot()? {
        if !auth_claim_is_expired(&claim.expires_at) {
            return begin_durable_browser_claim(daemon, claim);
        }
    }
    if let Some(claim) = resume_history_browser_claim(machine, base)? {
        return begin_durable_browser_claim(daemon, claim);
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = {
        let _lock = lock_history_recovery()?;
        create_setup_claim_with_history(
            &api_url_with_base(base, "/api/v1/setup-claims"),
            machine,
            &nonce,
            &history_stores(),
            history_now(),
        )?
    };
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let pending = PendingAuthClaim {
        claim_code: claim.claim_code,
        claim_token: claim.claim_token,
        claim_url: append_nonce_to_claim_url(&claim.claim_url, &nonce),
        nonce,
        expires_at: claim.expires_at,
    };
    begin_durable_browser_claim(daemon, pending)
}

/// A fresh claim is the explicit cancellation boundary for an older completed
/// claim that was waiting for account-switch confirmation. The journal is not
/// active authority until confirmation is authorized, so invalidate it before
/// asking the backend to mint a different immutable preparation. The binding
/// lock plus the reservation check exclude a concurrently completing claim.
fn discard_abandoned_unconfirmed_claim_credential() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.confirmed_at.is_some()
        || pending.confirmation_authorized
        || pending.preconfirm_guards_passed
        || pending.claim_commit.is_none()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    clear_pending_device_credential(
        &pending_store,
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

/// Whether a pending claim's `expires_at` is in the past (with a 30s safety
/// margin so a claim that is about to lapse mid-browser-open is not reused).
/// Unparseable timestamps count as expired so a fresh claim is minted.
pub(in crate::control) fn auth_claim_is_expired(expires_at: &str) -> bool {
    use time::format_description::well_known::Rfc3339;
    let Ok(expires) = time::OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return true;
    };
    expires - time::Duration::seconds(30) <= time::OffsetDateTime::now_utc()
}

pub(in crate::control) fn auth_complete(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
    nonce: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    let pending = daemon.pending_auth_claim(claim_code, nonce)?;
    complete_pending_auth_claim(daemon, &status.machine, pending)
}

pub(in crate::control) fn auth_complete_pending(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    match daemon.pending_auth_claim_for_resume(claim_code) {
        Ok(pending) => complete_pending_auth_claim(daemon, &status.machine, pending),
        Err(LocalApiError::NoPendingAuthClaim) => daemon
            .completed_auth_claim_for_resume(claim_code)?
            .ok_or(LocalApiError::NoPendingAuthClaim),
        Err(error) => Err(error),
    }
}

pub(in crate::control) fn complete_pending_auth_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    pending: PendingAuthClaim,
) -> Result<AuthCompleteResponse, LocalApiError> {
    // Claim completion can rotate/revoke backend device credentials. Reserve
    // identity mutation before that remote side effect, but release the
    // lifecycle mutex during network I/O. The RAII guard blocks concurrent
    // Codex cloud-task admission and clears on every return or panic.
    let identity_reservation = reserve_identity_mutation()?;
    let completion = match complete_setup_claim(&pending, machine, Some(&identity_reservation)) {
        Ok(completed) => completed,
        Err(error) => {
            log_auth_complete_backend_failure(&error);
            if let Some(reattach) = reattach_required_state(&error) {
                let _binding_lock = lock_setup_run_binding();
                daemon.mark_reattach_required(reattach.message.clone(), reattach.can_reconnect)?;
                let account = daemon.account_for_trusted_client()?;
                FileAccountStore::default()
                    .save(&account)
                    .or_state_poisoned()?;
            }
            return Err(error);
        }
    };
    let completed = completion.response;
    // Validate the relay-device payload up front so a malformed completion is
    // rejected before any staging or persistence.
    let relay_credentials = relay_device_credentials_from_claim_completion(
        &completed,
        completion.prior_device_credential.as_ref(),
    )?;
    retire_refused_registration_after_browser_answer(&pending.claim_code)?;
    let _ = finish_history_browser_claim(&pending.claim_code);
    let account = LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: completed.user.id.clone(),
            email: completed.user.email.clone(),
            display_name: completed.user.display_name.clone(),
        }),
        organization: Some(LocalAccountOrganization {
            id: completed.organization.id.clone(),
            name: completed.organization.name.clone(),
        }),
        connected_at: Some(completed.connected_at.clone()),
        last_refreshed_at: Some(completed.connected_at.clone()),
        message: Some(StableMessage {
            code: "connected".to_string(),
            text: "This Mac is connected to Ottto.".to_string(),
        }),
        can_reconnect: None,
    };
    let prepared_pending = match &relay_credentials {
        ClaimRelayDeviceCredential::Prepared(prepared) => {
            let claim_commit = PendingClaimCredentialCommit {
                account: account.clone(),
                connection: LocalConnectionBinding {
                    setup_run_id: completed.setup_run_id.clone(),
                    setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
                    machine_id: completed.machine_id.clone(),
                    claim_code: Some(pending.claim_code.clone()),
                    api_base_url: validated_api_base_url(None)?,
                },
                target_user_id: completed.user.id.clone(),
                setup_run_token_sha256: secret_sha256(&completed.setup_run_token),
                backfill_policy: completed.backfill_policy.clone(),
                backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
            };
            let mut pending = pending_device_credential_from_preparation(
                &validated_api_base_url(None)?,
                prepared,
                false,
                Some(claim_commit),
                completion.request_authority.clone(),
            )?;
            {
                let _binding_lock = lock_setup_run_binding();
                identity_reservation.validate_locked()?;
                select_owner_snapshot_namespace(
                    &mut pending,
                    &prepared.candidate_secret,
                    completion.prior_device_credential.as_ref(),
                    &FileOwnerSnapshotNamespaceStore::default(),
                    &default_support_dir(),
                )?;
            }
            stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
            stage_pending_setup_run_token(&pending, &completed.setup_run_token)?;
            let staged = FilePendingDeviceCredentialStore::default()
                .load()
                .or_state_poisoned()?
                .ok_or(LocalApiError::StatePoisoned)?;
            if staged.preparation_id != pending.preparation_id {
                return Err(LocalApiError::StatePoisoned);
            }
            Some(staged)
        }
        ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Legacy(_, _) => None,
    };
    // Claim-collision check BEFORE any persistence. Previously the new
    // setup-run token and relay-device credentials were written to the
    // keychain before the user-mismatch check fired, leaving a half-installed
    // credential set for the wrong user alongside the old account files. On a
    // mismatch the fully-completed claim is staged in memory and surfaced as a
    // switch candidate. A modern candidate may already be present in the
    // separate pending journal/Keychain account, but active account/device
    // authority remains unchanged until `auth_switch_account`.
    if let Some(candidate) = daemon.stage_account_switch_if_user_mismatch(StagedAccountSwitch {
        claim_code: pending.claim_code.clone(),
        new_account: account.clone(),
        setup_run_id: completed.setup_run_id.clone(),
        setup_run_token: completed.setup_run_token.clone(),
        setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
        machine_id: completed.machine_id.clone(),
        relay_device: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, _) => Some(device.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_secret: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(_, secret) => Some(secret.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_credential_preparation_id: prepared_pending
            .as_ref()
            .map(|pending| pending.preparation_id.clone()),
        backfill_policy: completed.backfill_policy.clone(),
        backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
    })? {
        return Err(LocalApiError::AccountSwitchCandidate {
            current_user_email: candidate.current_user_email,
            new_user_email: candidate.new_user_email,
            new_organization_name: candidate.new_organization_name,
            claim_code: candidate.claim_code,
        });
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(authorize_pending_device_credential_confirmation(
            &pending.preparation_id,
        )?),
        None => None,
    };
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(mark_pending_device_credential_guards_passed(
            &pending,
            &FilePendingDeviceCredentialStore::default(),
        )?),
        None => None,
    };
    let confirmed_pending = match (&relay_credentials, prepared_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Prepared(prepared), Some(pending)) => {
            if pending.confirmed_at.is_some() {
                Some(pending.clone())
            } else {
                let confirmed =
                    confirm_device_credential_preparation(pending, &prepared.candidate_secret)?;
                Some(mark_pending_device_credential_confirmed(
                    pending,
                    &confirmed.confirmed_at,
                    &FilePendingDeviceCredentialStore::default(),
                )?)
            }
        }
        (ClaimRelayDeviceCredential::Prepared(_), None) => {
            return Err(LocalApiError::StatePoisoned)
        }
        _ => None,
    };
    if let (ClaimRelayDeviceCredential::Prepared(prepared), Some(confirmed)) =
        (&relay_credentials, confirmed_pending.as_ref())
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        write_and_verify_pending_claim_commit(confirmed, &prepared.candidate_secret)?;
        let response = daemon.complete_auth_with_account(
            &pending.claim_code,
            &pending.nonce,
            account,
            completed.setup_run_id,
            completed.setup_run_token_expires_at,
            completed.machine_id,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    // Persist the server-issued backfill policy BEFORE committing any of the
    // new binding (token, relay credentials, account/connection files): if
    // this write failed after the binding were already durable, the daemon
    // would come up connected without the cutoff and the next snapshot sync
    // would re-attribute the previous owner's pre-cutoff history to the new
    // account. A stray cutoff for a never-installed binding is harmless; a
    // binding without its cutoff is not.
    persist_claim_backfill_policy(
        completed.backfill_policy.as_deref(),
        completed.backfill_cutoff_at.as_deref(),
        &completed.user.id,
        match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, secret) => Some(
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None),
            ),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&completed.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (&relay_credentials, confirmed_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Legacy(device, secret), _) => {
            persist_relay_device_credentials_locked(device, secret, Some(&identity_reservation))?;
            true
        }
        (ClaimRelayDeviceCredential::Prepared(_), _) => return Err(LocalApiError::StatePoisoned),
        (ClaimRelayDeviceCredential::None, _) => false,
    };
    let response = daemon.complete_auth_with_account(
        &pending.claim_code,
        &pending.nonce,
        account.clone(),
        completed.setup_run_id.clone(),
        completed.setup_run_token_expires_at.clone(),
        completed.machine_id.clone(),
    )?;
    FileAccountStore::default()
        .save(&account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: completed.setup_run_id,
            setup_run_token_expires_at: completed.setup_run_token_expires_at,
            machine_id: completed.machine_id,
            claim_code: Some(pending.claim_code),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Persist the additive claim-completion backfill policy into the snapshot
/// backfill state (`snapshot_backfill_state.json`). An unwritable state file is
/// a poisoned-state error for `"from"` decisions — proceeding without the
/// cutoff would double-count the previous owner's history at org level.
fn persist_claim_backfill_policy(
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
    namespace: Option<String>,
) -> Result<(), LocalApiError> {
    let support_dir = default_support_dir();
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &support_dir,
        policy,
        cutoff_at,
        user_id,
        namespace.as_deref(),
    )
    .map_err(|error| {
        eprintln!("ottto-service: persisting claim backfill policy failed: {error}");
        LocalApiError::StatePoisoned
    })
}

/// Confirmed account switch (`auth_switch_account`): consume the staged claim
/// completion for `claim_code`, best-effort disconnect the OLD cloud binding
/// (tolerating auth failures and an already-deleted account), clear the old
/// local artifacts, and install the new binding in one in-memory state
/// transition. Status readers never observe an intermediate
/// `ResetRequired`→`NotConnected` hop — the binding goes straight to the new
/// `Connected` account.
pub(in crate::control) fn auth_switch_account(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    daemon.require_staged_account_switch(claim_code)?;
    let staged_snapshot = daemon.staged_account_switch_snapshot(claim_code)?;
    if let Some(preparation_id) = staged_snapshot
        .relay_device_credential_preparation_id
        .as_deref()
    {
        // This bit is only the user's durable approval. The reservation is
        // revalidated immediately before every confirm, including startup
        // recovery after a crash at the next instruction.
        authorize_pending_device_credential_confirmation(preparation_id)?;
    }
    // Reserve before `take_staged_account_switch`, which mutates the
    // in-memory switch state.
    let identity_reservation = reserve_identity_mutation()?;
    let staged = daemon.take_staged_account_switch(claim_code)?;
    if staged.relay_device_credential_preparation_id.is_none() {
        disconnect_previous_binding_best_effort(
            daemon,
            staged
                .relay_device
                .as_ref()
                .map(|device| device.device_id.as_str()),
        );
    }
    match install_staged_account_switch(daemon, &staged, &identity_reservation) {
        Ok(response) => Ok(response),
        Err(error) => {
            // Keep the staged completion so the user can retry the confirm
            // (e.g. after a transient keychain/file failure) without redoing
            // the whole browser claim.
            let _ = daemon.restore_staged_account_switch(staged);
            Err(error)
        }
    }
}

/// Best-effort cloud disconnect of the binding being replaced. Failures are
/// tolerated by design: the old account may already be deleted server-side
/// (401/404), the token may be unrefreshable, or the network may be down. The
/// switch proceeds either way; the backend reconciles a dangling setup run on
/// its side.
///
/// The request also asks the server to release the previous device
/// registration, unless the incoming binding reuses the same device id: a
/// release must never revoke the credential the switch is about to install.
fn disconnect_previous_binding_best_effort(daemon: &LocalDaemon, incoming_device_id: Option<&str>) {
    let connection = match daemon.connection_for_authorized_client() {
        Ok(Some(connection)) => connection,
        Ok(None) | Err(_) => return,
    };
    let Ok(setup_run_token) = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() else {
        return;
    };
    let Ok(api_base_url) = validated_api_base_url(Some(connection.api_base_url.as_str())) else {
        return;
    };
    let release =
        load_device_release_proof().filter(|proof| releasable_on_switch(proof, incoming_device_id));
    if let Err(error) = disconnect_setup_run_with_refresh(
        &api_base_url,
        &connection,
        &setup_run_token,
        release.as_ref(),
    ) {
        eprintln!(
            "ottto-service: account switch: cloud disconnect of previous binding skipped: {error}"
        );
    }
}

pub(in crate::control) fn releasable_on_switch(
    proof: &DeviceReleaseProof,
    incoming_device_id: Option<&str>,
) -> bool {
    incoming_device_id.map_or(true, |incoming| incoming != proof.device_id)
}

fn install_staged_account_switch(
    daemon: &LocalDaemon,
    staged: &StagedAccountSwitch,
    identity_reservation: &IdentityMutationReservation,
) -> Result<AuthCompleteResponse, LocalApiError> {
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let modern_credential = if let Some(preparation_id) =
        staged.relay_device_credential_preparation_id.as_deref()
    {
        if staged.relay_device.is_some() || staged.relay_device_secret.is_some() {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending_store = FilePendingDeviceCredentialStore::default();
        let pending = pending_store
            .load()
            .or_state_poisoned()?
            .ok_or(LocalApiError::StatePoisoned)?;
        if pending.preparation_id != preparation_id {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending = authorize_pending_device_credential_confirmation(&pending.preparation_id)?;
        let pending = mark_pending_device_credential_guards_passed(&pending, &pending_store)?;
        let candidate_secret = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .or_state_poisoned()?;
        let confirmed_pending = if pending.confirmed_at.is_some() {
            pending
        } else {
            let confirmed = confirm_device_credential_preparation(&pending, &candidate_secret)?;
            mark_pending_device_credential_confirmed(
                &pending,
                &confirmed.confirmed_at,
                &pending_store,
            )?
        };
        // Only now may the old local/cloud binding be disconnected: every
        // earlier failure cut retained usable old authority.
        disconnect_previous_binding_best_effort(
            daemon,
            Some(confirmed_pending.device.device_id.as_str()),
        );
        Some((confirmed_pending, candidate_secret))
    } else {
        None
    };
    if let Some((pending, candidate_secret)) = modern_credential.as_ref() {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        let claim = pending
            .claim_commit
            .as_ref()
            .ok_or(LocalApiError::StatePoisoned)?;
        if claim.account != staged.new_account
            || claim.connection.setup_run_id != staged.setup_run_id
            || claim.connection.setup_run_token_expires_at != staged.setup_run_token_expires_at
            || claim.connection.machine_id != staged.machine_id
            || claim.connection.claim_code.as_deref() != Some(staged.claim_code.as_str())
            || claim.backfill_policy != staged.backfill_policy
            || claim.backfill_cutoff_at != staged.backfill_cutoff_at
        {
            return Err(LocalApiError::StatePoisoned);
        }
        write_and_verify_pending_claim_commit(pending, candidate_secret)?;
        let response = daemon.install_switched_account(
            staged.new_account.clone(),
            staged.setup_run_id.clone(),
            staged.setup_run_token_expires_at.clone(),
            staged.machine_id.clone(),
            &staged.claim_code,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    reset_local_account_files_locked(Some(identity_reservation))?;
    let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
    let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
    // Persist the server-issued backfill policy BEFORE committing the new
    // binding (see auth claim completion for the failure-ordering rationale):
    // a same-org takeover must not re-attribute the previous owner's
    // already-ingested history to the new account.
    persist_claim_backfill_policy(
        staged.backfill_policy.as_deref(),
        staged.backfill_cutoff_at.as_deref(),
        staged
            .new_account
            .user
            .as_ref()
            .map(|user| user.id.as_str())
            .unwrap_or_default(),
        staged
            .relay_device
            .as_ref()
            .zip(staged.relay_device_secret.as_deref())
            .map(|(device, secret)| {
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None)
            }),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&staged.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (
        &staged.relay_device,
        &staged.relay_device_secret,
        modern_credential.as_ref(),
    ) {
        (Some(device), Some(secret), None) => {
            persist_relay_device_credentials_locked(device, secret, Some(identity_reservation))?;
            true
        }
        (None, None, Some(_)) => return Err(LocalApiError::StatePoisoned),
        (None, None, None) => false,
        _ => return Err(LocalApiError::StatePoisoned),
    };
    let response = daemon.install_switched_account(
        staged.new_account.clone(),
        staged.setup_run_id.clone(),
        staged.setup_run_token_expires_at.clone(),
        staged.machine_id.clone(),
        &staged.claim_code,
    )?;
    FileAccountStore::default()
        .save(&staged.new_account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: staged.setup_run_id.clone(),
            setup_run_token_expires_at: staged.setup_run_token_expires_at.clone(),
            machine_id: staged.machine_id.clone(),
            claim_code: Some(staged.claim_code.clone()),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Whether a terminal backend auth failure indicates the bound account (or its
/// setup run/device row) no longer exists server-side — as opposed to an
/// expired/invalid token, which is recoverable via refresh. Used to transition
/// the binding to the unbound-equivalent `account_not_found` state so the next
/// sign-in by ANY user proceeds as a fresh first claim.
pub(crate) fn backend_error_indicates_account_gone(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status == Some(404)
        && (details.endpoint.contains("/setup-runs/")
            || details.endpoint.contains("/local-client/"))
    {
        return true;
    }
    if !matches!(details.status, Some(401) | Some(403)) {
        return false;
    }
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let body = body.to_ascii_lowercase();
    body.contains("account_not_found")
        || body.contains("user_not_found")
        || body.contains("workspace_not_found")
        || body.contains("account no longer exists")
        || body.contains("user no longer exists")
        || body.contains("workspace no longer exists")
}

fn log_auth_complete_backend_failure(error: &LocalApiError) {
    if auth_complete_error_is_pending(error) {
        return;
    }
    match error {
        LocalApiError::Backend(details) => {
            let status = details
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string());
            let body = details
                .body_excerpt
                .as_deref()
                .unwrap_or("backend returned no response body");
            eprintln!(
                "ottto-service: auth_complete backend request failed endpoint={} status={} kind={:?} body_excerpt={}",
                auth_complete_log_endpoint(&details.endpoint),
                status,
                details.kind,
                body,
            );
        }
        LocalApiError::TimedOut(detail) => {
            eprintln!(
                "ottto-service: auth_complete backend request timed out endpoint=/api/v1/setup-claims/[claim]/local-client/complete detail={}",
                redact_inline(detail),
            );
        }
        _ => {}
    }
}

/// Browser approval and local claim completion are separate steps. The backend
/// returns this bounded 400 while the owner is still looking at the claim page;
/// it is an expected polling result, not a rejected pairing attempt.
fn auth_complete_error_is_pending(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status != Some(400) {
        return false;
    }
    details.body_excerpt.as_deref().is_some_and(|body| {
        body.to_ascii_lowercase()
            .contains("setup claim session is pending")
    })
}

pub(in crate::control) fn auth_complete_log_endpoint(endpoint: &str) -> String {
    let marker = "/api/v1/setup-claims/";
    let Some(start) = endpoint.find(marker) else {
        return endpoint.to_string();
    };
    let prefix_end = start + marker.len();
    let Some(suffix_start) = endpoint[prefix_end..].find("/local-client/complete") else {
        return endpoint.to_string();
    };
    let suffix_index = prefix_end + suffix_start;
    format!(
        "{}[claim]{}",
        &endpoint[..prefix_end],
        &endpoint[suffix_index..]
    )
}

pub(in crate::control) enum ClaimRelayDeviceCredential {
    None,
    Legacy(LocalDeviceBinding, String),
    Prepared(DeviceCredentialPreparationApiResponse),
}

/// Validate and materialize the relay-device credential transition from a
/// claim completion without persisting anything. Modern and legacy forms are
/// mutually exclusive so a malformed response cannot silently downgrade after
/// the server has created a preparation.
pub(in crate::control) fn relay_device_credentials_from_claim_completion(
    completed: &SetupClaimCompleteResponse,
    prior: Option<&PriorDeviceCredential>,
) -> Result<ClaimRelayDeviceCredential, LocalApiError> {
    if let Some(prepared) = &completed.relay_device_credential_preparation {
        if completed.relay_device.is_some() || completed.relay_device_secret.is_some() {
            return Err(claim_completion_response_unexpected(
                "claim completion mixed prepared and active relay-device credentials",
            ));
        }
        validate_device_credential_preparation(
            "/api/v1/setup-claims/[claim]/local-client/complete",
            prepared,
            prior,
        )?;
        return Ok(ClaimRelayDeviceCredential::Prepared(prepared.clone()));
    }
    match (&completed.relay_device, &completed.relay_device_secret) {
        (None, None) => Ok(ClaimRelayDeviceCredential::None),
        (Some(device), Some(device_secret)) => {
            if device.sources.is_empty() || device_secret.trim().is_empty() {
                return Err(claim_completion_response_unexpected(
                    "claim completion returned incomplete relay-device credentials",
                ));
            }
            Ok(ClaimRelayDeviceCredential::Legacy(
                LocalDeviceBinding {
                    device_id: device.id.clone(),
                    machine_id: device
                        .machine_id
                        .clone()
                        .or_else(|| completed.machine_id.clone()),
                    sources: device.sources.clone(),
                },
                device_secret.clone(),
            ))
        }
        _ => Err(claim_completion_response_unexpected(
            "claim completion returned partial relay-device credentials",
        )),
    }
}

#[cfg(test)]
pub(in crate::control) fn persist_relay_device_credentials(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    persist_relay_device_credentials_locked(device, device_secret, None)
}

fn persist_relay_device_credentials_locked(
    device: &LocalDeviceBinding,
    device_secret: &str,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    let device_store = FileDeviceStore::default();
    let current_device = device_store.load().or_state_poisoned()?;

    let secret_store = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    let current_secret = match current_device {
        Some(_) => match secret_store.load() {
            Ok(secret) => Some(secret),
            Err(TokenStoreError::Missing) => None,
            Err(_) => return Err(LocalApiError::StatePoisoned),
        },
        // With no active device binding, a stray old secret is not usable
        // authority and does not need to be read for rollback. This also lets
        // first registration use the owner-only fallback when Keychain reads
        // are transiently unavailable.
        None => None,
    };
    secret_store.save(device_secret).or_state_poisoned()?;
    if device_store.save(device).is_ok() {
        return Ok(());
    }

    // The device binding is an atomic file replace, but the credential spans
    // that file and Keychain. Restore the exact prior secret on any file-side
    // failure so callers never observe a durably half-rotated pair.
    let rollback = match current_secret {
        Some(secret) => secret_store.save(&secret),
        None => secret_store.delete(),
    };
    if rollback.is_err() {
        return Err(LocalApiError::StatePoisoned);
    }
    Err(LocalApiError::StatePoisoned)
}

pub(in crate::control) fn pending_device_credential_from_preparation(
    api_base_url: &str,
    prepared: &DeviceCredentialPreparationApiResponse,
    confirmation_authorized: bool,
    claim_commit: Option<PendingClaimCredentialCommit>,
    request_authority: PendingDeviceCredentialRequestAuthority,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    Ok(PendingDeviceCredentialPreparation {
        schema_version: PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        capability: prepared.capability.clone(),
        preparation_id: prepared.preparation_id.clone(),
        api_base_url: validated_api_base_url(Some(api_base_url))?,
        expires_at: prepared.expires_at.clone(),
        credential_generation: prepared.credential_generation,
        secret_commitment_sha256: secret_sha256(&prepared.candidate_secret),
        request_authority: Some(request_authority),
        device: LocalDeviceBinding {
            device_id: prepared.device.id.clone(),
            machine_id: prepared.device.machine_id.clone(),
            sources: prepared.device.sources.clone(),
        },
        confirmation_authorized,
        preconfirm_guards_passed: false,
        claim_commit,
        confirmed_at: None,
    })
}

fn authorize_pending_device_credential_confirmation(
    preparation_id: &str,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    let store = FilePendingDeviceCredentialStore::default();
    let mut pending = store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.preparation_id != preparation_id {
        return Err(LocalApiError::StatePoisoned);
    }
    if pending.confirmation_authorized {
        return Ok(pending);
    }
    pending.confirmation_authorized = true;
    store.save(&pending).or_state_poisoned()?;
    if store.load().or_state_poisoned()?.as_ref() != Some(&pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(pending)
}

pub(in crate::control) fn mark_pending_device_credential_guards_passed(
    pending: &PendingDeviceCredentialPreparation,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if pending.confirmed_at.is_some() {
        return if pending.confirmation_authorized && pending.preconfirm_guards_passed {
            Ok(pending.clone())
        } else {
            Err(LocalApiError::StatePoisoned)
        };
    }
    if !pending.confirmation_authorized {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut guarded = pending.clone();
    guarded.preconfirm_guards_passed = true;
    pending_store.save(&guarded).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&guarded) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(guarded)
}

pub(in crate::control) fn stage_pending_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    stage_pending_device_credential_with_stores(
        pending,
        candidate_secret,
        &FilePendingDeviceCredentialStore::default(),
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

pub(in crate::control) fn stage_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_candidate_secret(pending, candidate_secret).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    let existing = pending_store.load().or_state_poisoned()?;
    let effective_pending = if let Some(current) = existing.as_ref() {
        // An idempotent server retry must reproduce the entire immutable
        // preparation and candidate. Never replace a same-ID candidate or
        // mutate its account commit merely because the identifier matches.
        let mut immutable = current.clone();
        immutable.confirmation_authorized = pending.confirmation_authorized;
        immutable.preconfirm_guards_passed = pending.preconfirm_guards_passed;
        immutable.confirmed_at = pending.confirmed_at.clone();
        if immutable != *pending {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        match pending_secret_store.load() {
            Ok(stored) if stored == candidate_secret => return Ok(()),
            Ok(_) => return Err(LocalApiError::StatePoisoned),
            Err(TokenStoreError::Missing) => {}
            Err(_) => return Err(LocalApiError::StatePoisoned),
        }
        current
    } else {
        pending
    };

    pending_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    if pending_store.save(effective_pending).is_err() {
        // A newly written orphan candidate is not active authority. Remove it
        // when possible; if deletion itself fails, the active credential and
        // device binding are still unchanged and usable.
        if existing.is_none() {
            let _ = pending_secret_store.delete();
        }
        return Err(LocalApiError::StatePoisoned);
    }
    let stored_secret = pending_secret_store.load().or_state_poisoned()?;
    let stored_pending = pending_store.load().or_state_poisoned()?;
    if stored_secret != candidate_secret || stored_pending.as_ref() != Some(effective_pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(in crate::control) fn stage_pending_setup_run_token(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
) -> Result<(), LocalApiError> {
    let store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    stage_pending_setup_run_token_with_store(pending, setup_run_token, &store)
}

pub(in crate::control) fn stage_pending_setup_run_token_with_store<
    S: ControlTokenStore + ?Sized,
>(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
    store: &S,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if setup_run_token.trim().is_empty()
        || claim.setup_run_token_sha256 != secret_sha256(setup_run_token)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match store.load() {
        Ok(current) if current == setup_run_token => return Ok(()),
        // A different value cannot belong to this hash-bound journal. It is
        // an inert orphan from a cut before the journal write and is safe to
        // replace with the exact server-reproduced token.
        // The same recovery is safe when the old value cannot be read (for
        // example, while macOS is re-resolving a replaced login Keychain):
        // the exact journal-bound value is written and then read back before
        // this function succeeds.
        Ok(_) | Err(_) => {}
    }
    store.save(setup_run_token).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != setup_run_token {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(crate) fn secret_sha256(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

pub(crate) fn secret_commitment_matches(commitment: &str, secret: &str) -> bool {
    constant_work_eq(commitment.as_bytes(), secret_sha256(secret).as_bytes())
}

pub(in crate::control) fn constant_work_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(in crate::control) fn validate_pending_candidate_secret(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    if candidate_secret.trim().is_empty()
        || !valid_secret_commitment(&pending.secret_commitment_sha256)
        || !secret_commitment_matches(&pending.secret_commitment_sha256, candidate_secret)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn valid_secret_commitment(commitment: &str) -> bool {
    commitment.len() == 71
        && commitment.starts_with("sha256:")
        && commitment[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(in crate::control) fn validate_pending_prior_credential_binding(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<(), LocalApiError> {
    let Some(authority) = pending.request_authority.as_ref() else {
        // Additive compatibility for a v2 journal created by an older binary.
        return if pending.schema_version == OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
            Err(LocalApiError::StatePoisoned)
        } else {
            Ok(())
        };
    };
    if !matches!(authority.flow.as_str(), "register" | "setup_claim")
        || !valid_secret_commitment(&authority.credential_preparation_idempotency_key)
        || authority.machine_id.trim().is_empty()
        || authority.installation_id.trim().is_empty()
        || authority
            .identity_continuity_capability
            .as_deref()
            .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
        || authority
            .canonical_snapshot_namespace
            .as_deref()
            .is_some_and(|namespace| {
                authority.flow != "setup_claim"
                    || (pending.schema_version == PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION
                        && authority.prior_device_id.is_none())
                    || !crate::hex::is_sha256_lower(namespace)
            })
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if authority.incoming_snapshot_namespace.is_some()
        && (pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
            || authority.flow != "setup_claim")
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match (
        authority.prior_device_id.as_deref(),
        authority.prior_device_sources.as_deref(),
        authority.prior_secret_commitment_sha256.as_deref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(device_id), Some(sources), Some(commitment))
            if !device_id.trim().is_empty()
                && !sources.is_empty()
                && authority.identity_continuity_capability.as_deref()
                    == Some(IDENTITY_CONTINUITY_CAPABILITY)
                && valid_secret_commitment(commitment) =>
        {
            Ok(())
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

pub(in crate::control) fn mark_pending_device_credential_confirmed(
    pending: &PendingDeviceCredentialPreparation,
    confirmed_at: &str,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if !pending.confirmation_authorized || !pending.preconfirm_guards_passed {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut confirmed = pending.clone();
    confirmed.confirmed_at = Some(confirmed_at.to_string());
    pending_store.save(&confirmed).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&confirmed) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(confirmed)
}

pub(in crate::control) fn write_and_verify_active_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let expected_binding = LocalDeviceCredentialBinding {
        device: pending.device.clone(),
        credential_generation: pending.credential_generation,
        continuity: DeviceCredentialContinuity {
            owner: pending_credential_owner(pending),
            snapshot_namespace: pending_snapshot_alias(pending),
        },
    };

    active_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    device_store
        .save_with_credential_generation(&expected_binding)
        .or_state_poisoned()?;

    let active_secret = active_secret_store.load().or_state_poisoned()?;
    let active_binding = device_store
        .load_with_credential_generation()
        .or_state_poisoned()?;
    if active_secret != candidate_secret || active_binding.as_ref() != Some(&expected_binding) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

/// The journaled same-account namespace, bound to the staged candidate secret.
pub(in crate::control) fn pending_snapshot_alias(
    pending: &PendingDeviceCredentialPreparation,
) -> Option<SnapshotNamespaceAlias> {
    let namespace = pending
        .request_authority
        .as_ref()?
        .canonical_snapshot_namespace
        .clone()?;
    Some(SnapshotNamespaceAlias {
        namespace,
        secret_commitment_sha256: pending.secret_commitment_sha256.clone(),
    })
}

fn clear_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    pending_store.reset().or_state_poisoned()?;
    let _ = pending_secret_store.delete();
    let _ = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT).delete();
    Ok(())
}

pub(crate) fn promote_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    // A failed marker write keeps the candidate staged, so recovery retries both.
    if let Ok(Some(current)) = device_store.load() {
        crate::snapshot_sync::disable_sources_dropped_from_grant(
            &default_support_dir(),
            &current,
            &pending.device,
        )
        .or_state_poisoned()?;
    }
    // After server confirmation the old active secret may already be invalid.
    // Never roll it back on a file-side failure: keep the separately staged
    // candidate intact so restart recovery can finish the same generation.
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        device_store,
        active_secret_store,
    )?;

    // Delete metadata first. A crash between these operations leaves only an
    // inert orphan Keychain entry while the verified active pair keeps working.
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn backend_error_has_status(error: &LocalApiError, status: u16) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrunedDeviceCredentialProbe {
    Confirmed,
    Inactive,
}

fn pending_device_credential_is_past_expiry(pending: &PendingDeviceCredentialPreparation) -> bool {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(&pending.expires_at, &Rfc3339)
        .is_ok_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
}

fn relay_auth_local_error(url: &str, status: u16) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: safe_backend_endpoint(url),
        status: Some(status),
        body_excerpt: None,
        reason_code: None,
    })
}

fn probe_pruned_device_credential_authority(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<PrunedDeviceCredentialProbe, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/devices/{}/relay-token",
            pending.device.device_id
        ),
    );
    let source = pending
        .device
        .sources
        .first()
        .ok_or(LocalApiError::StatePoisoned)?;
    let body = relay_token_request_payload(&pending.device, source);
    let mut probe =
        crate::relay_auth::Probe::begin(&api_base_url, &pending.device, candidate_secret, source)
            .map_err(|held| relay_auth_local_error(&url, held.status))?;
    match backend_post_json::<serde_json::Value>(
        &url,
        &body,
        &[("X-Ottto-Device-Secret", candidate_secret)],
    ) {
        Ok(_) => {
            probe.success();
            Ok(PrunedDeviceCredentialProbe::Confirmed)
        }
        Err(error)
            if matches!(
                &error,
                LocalApiError::Backend(details) if details.status == Some(401)
            ) && pending_device_credential_is_past_expiry(pending) =>
        {
            probe.reject(401);
            Ok(PrunedDeviceCredentialProbe::Inactive)
        }
        Err(error) => {
            if let LocalApiError::Backend(details) = &error {
                if let Some(status @ (401 | 403)) = details.status {
                    probe.reject(status);
                }
            }
            Err(error)
        }
    }
}

fn discard_server_inactive_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn write_and_verify_pending_claim_commit(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
        || claim.target_user_id.trim().is_empty()
        || claim.connection.setup_run_id.trim().is_empty()
        || claim
            .connection
            .claim_code
            .as_deref()
            .map_or(true, str::is_empty)
        || claim
            .account
            .user
            .as_ref()
            .map_or(true, |user| user.id != claim.target_user_id)
        || validated_api_base_url(Some(&claim.connection.api_base_url))?
            != claim.connection.api_base_url
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let pending_setup_token_store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    let setup_run_token = pending_setup_token_store.load().or_state_poisoned()?;
    if claim.setup_run_token_sha256 != secret_sha256(&setup_run_token) {
        return Err(LocalApiError::StatePoisoned);
    }

    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    // The attribution boundary must become durable before any credential or
    // account binding from the new claim. This operation is idempotent.
    persist_claim_backfill_policy(
        claim.backfill_policy.as_deref(),
        claim.backfill_cutoff_at.as_deref(),
        &claim.target_user_id,
        Some(crate::snapshot_sync::snapshot_destination_namespace(
            &pending.device,
            candidate_secret,
            pending_snapshot_alias(pending).as_ref(),
        )),
    )?;
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        &FileDeviceStore::default(),
        &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&setup_run_token)
        .or_state_poisoned()?;
    FileAccountStore::default()
        .save(&claim.account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&claim.connection)
        .or_state_poisoned()?;

    let active_setup_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .or_state_poisoned()?;
    let active_account = FileAccountStore::default().load().or_state_poisoned()?;
    let active_connection = FileConnectionStore::default().load().or_state_poisoned()?;
    if active_setup_token != setup_run_token
        || active_account != claim.account
        || active_connection.as_ref() != Some(&claim.connection)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    publish_owner_snapshot_history(pending, &FileOwnerSnapshotNamespaceStore::default())?;
    Ok(())
}

/// Resume an exact prepared generation before relays start. Local wall-clock
/// expiry never deletes a pending candidate: only a definitive server 410 can
/// prove an unconfirmed preparation is safe to discard.
pub fn recover_pending_device_credential_at_startup() -> Result<bool, LocalApiError> {
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending_secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(false);
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_prior_credential_binding(&pending).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let candidate_secret = pending_secret_store.load().or_state_poisoned()?;
    validate_pending_candidate_secret(&pending, &candidate_secret)?;
    if pending.confirmed_at.is_none() && !pending.confirmation_authorized {
        return match inspect_device_credential_preparation(&pending, &candidate_secret) {
            Ok(status) if status.status == "pending" => Ok(false),
            Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            // A server-confirmed switch that was never locally authorized is
            // an invariant violation. Retain both halves for operator recovery;
            // never silently install or discard it.
            Ok(_) => Err(LocalApiError::StatePoisoned),
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => Err(LocalApiError::StatePoisoned),
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        Ok(false)
                    }
                }
            }
            Err(error) => Err(error),
        };
    }
    if pending.confirmed_at.is_some()
        && (!pending.confirmation_authorized || !pending.preconfirm_guards_passed)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let identity_reservation = reserve_identity_mutation()?;
    // A persisted guard bit records the prior process's cut, but it is never
    // authority to confirm. Revalidate a fresh reservation at the last
    // possible point before confirm/promotion.
    let pending = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        if pending.confirmed_at.is_none() {
            mark_pending_device_credential_guards_passed(&pending, &pending_store)?
        } else {
            pending
        }
    };
    let confirmed = if pending.confirmed_at.is_some() {
        pending
    } else {
        match confirm_device_credential_preparation(&pending, &candidate_secret) {
            Ok(receipt) => mark_pending_device_credential_confirmed(
                &pending,
                &receipt.confirmed_at,
                &pending_store,
            )?,
            Err(error) if registration_history_choice_required(&error) => {
                // The lower-level refusal persisted the browser re-offer. Leave
                // the same pending candidate and old credential pair intact.
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => {
                        mark_pending_device_credential_confirmed(
                            &pending,
                            &current_rfc3339_timestamp(),
                            &pending_store,
                        )?
                    }
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        return Ok(false);
                    }
                }
            }
            Err(error) => return Err(error),
        }
    };
    let _identity_lifecycle_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    if confirmed.claim_commit.is_some() {
        write_and_verify_pending_claim_commit(&confirmed, &candidate_secret)?;
        clear_pending_device_credential(&pending_store, &pending_secret_store)?;
    } else {
        promote_pending_device_credential_with_stores(
            &confirmed,
            &candidate_secret,
            &pending_store,
            &pending_secret_store,
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    Ok(true)
}

#[cfg(test)]
pub(in crate::control) fn save_relay_device_binding(
    device: &LocalDeviceBinding,
) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    save_relay_device_binding_locked(device, None)
}

#[cfg(test)]
fn save_relay_device_binding_locked(
    device: &LocalDeviceBinding,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileDeviceStore::default().save(device).or_state_poisoned()
}

fn claim_completion_response_unexpected(detail: &str) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: "/api/v1/setup-claims/[claim]/local-client/complete".to_string(),
        status: None,
        body_excerpt: Some(detail.to_string()),
        reason_code: None,
    })
}

/// `only_if_bound`: reset only while this setup run is still the bound one
/// (the automatic reset after a terminal refresh answer about it).
pub(in crate::control) fn auth_reset(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    local_only: bool,
    forget_installation: bool,
    only_if_bound: Option<&LocalConnectionBinding>,
) -> Result<AuthResetResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    // Both ordinary and explicit local-only logout replace account/device
    // authority, so both drain admitted Codex cloud-task I/O first.
    let identity_reservation = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        require_setup_run_still_bound(daemon, only_if_bound)?;
        reserve_identity_mutation_locked()?
    };
    let mut cloud_disconnect: Option<SetupRunDisconnectResponse> = None;
    let mut setup_run_already_ended = false;
    let mut released_without_setup_run = false;

    if !local_only {
        let connection = daemon
            .connection_for_authorized_client()?
            .ok_or_else(|| cloud_logout_requires_connection_error(forget_installation))?;
        let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .map_err(|_| cloud_logout_requires_connection_error(forget_installation))?;
        let api_base_url = validated_api_base_url(Some(connection.api_base_url.as_str()))?;
        // Read the release proof before any local deletion below; the server
        // revokes this Mac's registration only when both halves authenticate.
        let release = load_device_release_proof();
        match disconnect_setup_run_with_refresh(
            &api_base_url,
            &connection,
            &setup_run_token,
            release.as_ref(),
        ) {
            Ok(disconnect) => cloud_disconnect = Some(disconnect),
            // Ottto already ended this run, so it can never be disconnected.
            // This Mac can still release its own registration with its device
            // secret, which needs no setup run; once Ottto confirms, the reset
            // continues exactly like a successful cloud logout. Otherwise a
            // plain logout falls through to the local-only cleanup (prior
            // device proof kept for reconnecting) and reports that Ottto was
            // not changed; forgetting the installation still needs the
            // release, and every other failure still aborts with local state
            // intact.
            Err(error)
                if terminal_refresh_rejection(&error)
                    == Some(TerminalRefreshRejection::SetupRunEnded) =>
            {
                if release
                    .as_ref()
                    .is_some_and(|release| release_device_without_setup_run(&api_base_url, release))
                {
                    released_without_setup_run = true;
                } else if forget_installation {
                    return Err(error);
                } else {
                    setup_run_already_ended = true;
                }
            }
            Err(error) => return Err(error),
        }
    }
    let local_only = local_only || setup_run_already_ended;

    // Every local deletion, Keychain included, happens under the identity
    // lifecycle lock after the binding is rechecked, so a setup run attached
    // meanwhile (which takes the same lock) is never cleared by this reset.
    let mut reset = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        require_setup_run_still_bound(daemon, only_if_bound)?;
        let retain_active = seed_owner_snapshot_history_for_logout()?;
        if local_only && retain_active {
            retain_prior_device_credential_for_logout()?;
        } else if local_only {
            // A partial promotion may mix the active file and secret halves.
            // Existing history stays intact; that mixed pair is not
            // predecessor authority for a later registration.
            clear_prior_device_selector()?;
        }
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        if !local_only || forget_installation {
            // The public selector is the usable half of a retained predecessor
            // credential. A destructive reset must durably remove it before
            // reporting success. The now-unusable Keychain half is deleted
            // best-effort below so a locked Keychain cannot strand the reset.
            clear_prior_device_selector()?;
        }
        reset_local_account_files_locked(Some(&identity_reservation))?;
        if forget_installation {
            forget_installation_state_locked()?;
        }
        let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
        let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        if !local_only || forget_installation {
            let _ = KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        }
        daemon.reset_account_for_authorized_client()?
    };
    reset.local_only = local_only;
    reset.cloud_disconnected = cloud_disconnect.is_some();
    reset.setup_run_id = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.setup_run_id.clone());
    reset.disconnected_at = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.disconnected_at.clone());
    reset.device_released = if released_without_setup_run {
        Some(true)
    } else {
        cloud_disconnect
            .as_ref()
            .map(|disconnect| disconnect.device_released)
    };
    reset.message = if released_without_setup_run {
        released_without_setup_run_message(forget_installation)
    } else if setup_run_already_ended {
        StableMessage {
            code: "setup_run_already_ended".to_string(),
            text: "Ottto had already ended this Mac's setup run, so nothing changed in Ottto and this Mac's server registration was not released. Active local credentials were cleared; prior device proof was retained securely for reconnection."
                .to_string(),
        }
    } else {
        auth_reset_message(forget_installation, reset.device_released)
    };
    Ok(reset)
}

const FORGOTTEN_INSTALLATION: &str = "Installation identity and credentials were cleared. Collected state and local sync receipts stay; only uninstall deletes them. Agent source data was not changed. Restart ottto-service before pairing.";

/// `device_released` is `None` for a local-only reset, which never contacts
/// Ottto, and the server's answer for a cloud reset.
fn auth_reset_message(forget_installation: bool, device_released: Option<bool>) -> StableMessage {
    const NOT_RELEASED: &str = "Ottto did not confirm releasing this Mac's server registration, so it may still be active; the account that owns it can disconnect this Mac on its Apps page (Disconnect).";
    const STILL_REGISTERED: &str = "This Mac may still be registered to the previous Ottto account on the server. If that account was deleted or already disconnected this Mac, sign in and choose Replace it on the claim page. Otherwise a different account can connect it only after the previous account disconnects this Mac on its Apps page (Disconnect). The normal path is `ottto logout --forget-installation --confirm` without --local-only, which releases the registration first.";
    const FORGOTTEN: &str = FORGOTTEN_INSTALLATION;
    let (code, text) = match (forget_installation, device_released) {
        (true, None) => (
            "installation_forgotten",
            format!("Ottto was not contacted. {FORGOTTEN} {STILL_REGISTERED}"),
        ),
        (true, Some(true)) => (
            "installation_forgotten",
            format!(
                "This Mac was disconnected from Ottto and its server registration was released. {FORGOTTEN}"
            ),
        ),
        (true, Some(false)) => (
            "installation_forgotten",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED} {FORGOTTEN}"),
        ),
        (false, None) => (
            "local_disconnect_complete",
            "Active local credentials were cleared without changing cloud state; prior device proof was retained securely for reconnection."
                .to_string(),
        ),
        (false, Some(true)) => (
            "cloud_disconnect_complete",
            "This Mac was disconnected from Ottto and its server registration was released."
                .to_string(),
        ),
        (false, Some(false)) => (
            "cloud_disconnect_complete",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED}"),
        ),
    };
    StableMessage {
        code: code.to_string(),
        text,
    }
}

/// A cloud reset whose setup run had already ended, after this Mac released
/// its own server registration directly.
fn released_without_setup_run_message(forget_installation: bool) -> StableMessage {
    const RELEASED: &str = "This Mac's Ottto connection had expired, so it released its server registration directly and was logged out.";
    if forget_installation {
        StableMessage {
            code: "installation_forgotten".to_string(),
            text: format!("{RELEASED} {FORGOTTEN_INSTALLATION}"),
        }
    } else {
        StableMessage {
            code: "device_released_after_run_ended".to_string(),
            text: RELEASED.to_string(),
        }
    }
}

pub(in crate::control) fn forget_installation_state_locked() -> Result<(), LocalApiError> {
    // This explicit identity-forget action closes the old local ceremony.
    // Complete secure cleanup BEFORE replacing the installation identity.
    {
        let _history_lock = lock_history_recovery()?;
        let stores = history_stores();
        clear_local_release(&stores)?;
        stores.browser.delete().or_state_poisoned()?;
    }
    // Collected state, caches and receipts stay; only uninstall deletes them.
    FileMachineStore::default().reset().or_state_poisoned()?;
    Ok(())
}

#[cfg(test)]
pub(in crate::control) fn reset_local_account_files() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reset_local_account_files_locked(None)
}

fn reset_local_account_files_locked(
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileAccountStore::default().reset().or_state_poisoned()?;
    FileConnectionStore::default().reset().or_state_poisoned()?;
    FileDeviceStore::default().reset().or_state_poisoned()?;
    Ok(())
}

fn cloud_logout_requires_connection_error(forget_installation: bool) -> LocalApiError {
    LocalApiError::InvalidRequest(if forget_installation {
        "logout --forget-installation requires an active Ottto cloud connection to release this Mac's server registration; use --local-only --forget-installation only to clear local state without updating Ottto"
            .to_string()
    } else {
        "logout requires an active Ottto cloud connection; use --local-only only to clear local state without updating Ottto"
            .to_string()
    })
}

fn create_setup_claim(
    machine: &MachineIdentity,
    nonce: &str,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let url = api_url("/api/v1/setup-claims");
    let _receipt_lock = lock_history_recovery()?;
    create_setup_claim_with_history(&url, machine, nonce, &history_stores(), history_now())
}

pub(in crate::control) const REVOCATION_RECEIPT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

static REVOCATION_RECEIPT_LOCK: Mutex<()> = Mutex::new(());

pub(in crate::control) fn history_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub(in crate::control) fn lock_history_recovery() -> Result<MutexGuard<'static, ()>, LocalApiError>
{
    REVOCATION_RECEIPT_LOCK.lock().or_state_poisoned()
}

pub(in crate::control) struct HistoryStores {
    pub(in crate::control) receipt: Box<dyn ControlTokenStore>,
    pub(in crate::control) marker: Box<dyn ControlTokenStore>,
    pub(in crate::control) proof: Box<dyn ControlTokenStore>,
    pub(in crate::control) browser: Box<dyn ControlTokenStore>,
}

fn history_support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return ottto_core::token_store::isolated_test_secret_dir()
            .expect("isolated history test store")
            .join(format!("history-{:?}", std::thread::current().id()));
    }
    default_support_dir()
}

fn history_account_store() -> FileAccountStore {
    FileAccountStore::new(history_support_dir().join("account.json"))
}

fn history_connection_store() -> FileConnectionStore {
    FileConnectionStore::new(history_support_dir().join("connection.json"))
}

pub(in crate::control) fn history_stores() -> HistoryStores {
    HistoryStores {
        receipt: history_secret_store(OTTTO_REVOCATION_RECEIPT_ACCOUNT),
        marker: history_secret_store(HISTORY_MARKER_ACCOUNT),
        proof: history_secret_store(HISTORY_PROOF_ACCOUNT),
        browser: history_secret_store(HISTORY_BROWSER_ACCOUNT),
    }
}

fn history_secret_store(account: &'static str) -> Box<dyn ControlTokenStore> {
    #[cfg(not(test))]
    {
        Box::new(KeychainSecretStore::keychain_only(account))
    }
    #[cfg(test)]
    {
        // Synthetic stores survive a daemon reload, without ever touching the
        // host Keychain or writing a receipt/device proof to a fixture file.
        use ottto_core::token_store::MemoryTokenStore;
        type TestHistoryStores = Mutex<BTreeMap<(PathBuf, &'static str), MemoryTokenStore>>;
        static STORES: std::sync::OnceLock<TestHistoryStores> = std::sync::OnceLock::new();
        let mut stores = STORES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        Box::new(
            stores
                .entry((history_support_dir(), account))
                .or_default()
                .clone(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::control) struct StoredRevocationReceipt {
    pub(in crate::control) revocation_receipt: SecretString,
    pub(in crate::control) received_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::control) struct LocalReleaseMarker {
    pub(in crate::control) device_id: String,
    pub(in crate::control) api_base_url: String,
    pub(in crate::control) released_at: i64,
    #[serde(default)]
    pub(in crate::control) cleanup_required: bool,
    #[serde(default)]
    pub(in crate::control) ceremony_closed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalReleaseProof {
    device_id: String,
    device_secret: SecretString,
}

// This contains claim credentials and a nonce. Never derive Debug or put it in
// account.json; only the non-secret re-offer message belongs in that file.
#[derive(Serialize, Deserialize)]
pub(in crate::control) struct StoredHistoryBrowserClaim {
    pub(in crate::control) installation_id: String,
    pub(in crate::control) account_scope: Option<String>,
    pub(in crate::control) api_base_url: String,
    pub(in crate::control) setup_run_id: Option<String>,
    #[serde(default)]
    pub(in crate::control) registration_pending: bool,
    pub(in crate::control) nonce: SecretString,
    pub(in crate::control) claim: SetupClaimCreateResponse,
}

pub(in crate::control) fn history_load<T: DeserializeOwned>(
    store: &dyn ControlTokenStore,
) -> Result<Option<T>, LocalApiError> {
    match store.load() {
        Ok(encoded) => serde_json::from_str(&encoded).map(Some).or_state_poisoned(),
        Err(TokenStoreError::Missing) => Ok(None),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}

pub(in crate::control) fn history_save<T: Serialize>(
    store: &dyn ControlTokenStore,
    value: &T,
) -> Result<(), LocalApiError> {
    let encoded = serde_json::to_string(value).or_state_poisoned()?;
    store.save(&encoded).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != encoded {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(in crate::control) fn stage_local_release(
    api_base_url: &str,
    release: &DeviceReleaseProof,
    stores: &HistoryStores,
    now: i64,
) -> Result<(), LocalApiError> {
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    let existing: Option<LocalReleaseMarker> = history_load(stores.marker.as_ref())?;
    // Preserve the original boundary across a refresh/retry of the release.
    let same_release = existing.as_ref().is_some_and(|m| {
        m.device_id == release.device_id
            && m.api_base_url == api_base_url
            && !m.ceremony_closed
            && now
                .checked_sub(m.released_at)
                .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if !same_release {
        stores.receipt.delete().or_state_poisoned()?;
        stores.browser.delete().or_state_poisoned()?;
    }
    let released_at = existing
        .filter(|_| same_release)
        .map_or(now, |m| m.released_at);
    history_save(
        stores.proof.as_ref(),
        &LocalReleaseProof {
            device_id: release.device_id.clone(),
            device_secret: SecretString::new(&release.device_secret),
        },
    )?;
    history_save(
        stores.marker.as_ref(),
        &LocalReleaseMarker {
            device_id: release.device_id.clone(),
            api_base_url,
            released_at,
            cleanup_required: false,
            ceremony_closed: false,
        },
    )?;
    persist_local_release_expected()
}

pub(in crate::control) fn remember_revocation_receipt(
    device_released: bool,
    receipt: Option<SecretString>,
    stores: &HistoryStores,
    now: i64,
) {
    if device_released {
        // The marker and own-device proof were durably staged BEFORE release.
        // A missing receipt or failed write is recovered by the re-issue API.
        if let Some(receipt) = receipt.filter(|s| !s.expose_secret().trim().is_empty()) {
            let _ = history_save(
                stores.receipt.as_ref(),
                &StoredRevocationReceipt {
                    revocation_receipt: receipt,
                    received_at: now,
                },
            );
        }
    }
}

pub(in crate::control) fn clear_local_release(stores: &HistoryStores) -> Result<(), LocalApiError> {
    // Marker is last: any partial cleanup remains a recoverable pending action.
    if let Some(mut marker) = history_load::<LocalReleaseMarker>(stores.marker.as_ref())? {
        marker.cleanup_required = true;
        marker.ceremony_closed = true;
        history_save(stores.marker.as_ref(), &marker)?;
    }
    stores.receipt.delete().or_state_poisoned()?;
    stores.proof.delete().or_state_poisoned()?;
    clear_local_release_expected()?;
    stores.marker.delete().or_state_poisoned()
}

#[derive(Debug, Deserialize)]
struct RevocationReceiptRecoveryResponse {
    outcome: String,
    #[serde(default)]
    revocation_receipt: Option<SecretString>,
    #[serde(default)]
    claim_code: Option<SecretString>,
    #[serde(default)]
    claim_token: Option<SecretString>,
    #[serde(default)]
    client_nonce: Option<SecretString>,
}

enum ReceiptRecovery {
    Receipt(SecretString),
    Claim(SetupClaimCreateResponse),
    Refused,
}

fn reissue_revocation_receipt(
    marker: &LocalReleaseMarker,
    proof: &LocalReleaseProof,
) -> Result<ReceiptRecovery, LocalApiError> {
    let base = validated_api_base_url(Some(&marker.api_base_url))?;
    if marker.device_id != proof.device_id
        || marker.device_id.is_empty()
        || !marker
            .device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let url = api_url_with_base(
        &base,
        &format!(
            "/api/v1/telemetry/devices/{}/revocation-receipt",
            marker.device_id
        ),
    );
    let response: RevocationReceiptRecoveryResponse = match backend_post_json(
        &url,
        &json!({}),
        &[("X-Ottto-Device-Secret", proof.device_secret.expose_secret())],
    ) {
        Ok(response) => response,
        Err(LocalApiError::Backend(ref details))
            if matches!(details.status, Some(401 | 409))
                && details.reason_code.as_deref().is_some_and(|code| {
                    matches!(
                        code,
                        "device_secret_invalid"
                            | "device_reactivated"
                            | "origin_not_local_switch"
                            | "release_window_expired"
                            | "ceremony_closed"
                    )
                }) =>
        {
            eprintln!(
                "ottto-service: local history recovery outcome={}",
                details.reason_code.as_deref().unwrap()
            );
            return Ok(ReceiptRecovery::Refused);
        }
        // Daemon-first rollout: old servers do not expose this endpoint yet.
        Err(LocalApiError::Backend(ref details)) if matches!(details.status, Some(404 | 405)) => {
            eprintln!("ottto-service: local history recovery outcome=receipt_reissue_unavailable");
            return Ok(ReceiptRecovery::Refused);
        }
        Err(error) => return Err(error),
    };
    match response.outcome.as_str() {
        "receipt_issued" => {
            let receipt = response
                .revocation_receipt
                .filter(|s| !s.expose_secret().trim().is_empty())
                .ok_or(LocalApiError::StatePoisoned)?;
            eprintln!("ottto-service: local history recovery outcome=receipt_issued");
            Ok(ReceiptRecovery::Receipt(receipt))
        }
        "claim_recovered" => {
            let code = response.claim_code.ok_or(LocalApiError::StatePoisoned)?;
            let token = response.claim_token.ok_or(LocalApiError::StatePoisoned)?;
            let nonce = response.client_nonce.ok_or(LocalApiError::StatePoisoned)?;
            if !code
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(LocalApiError::StatePoisoned);
            }
            #[derive(Deserialize)]
            struct ClaimStatus {
                claim_url: String,
                expires_at: String,
            }
            let status: ClaimStatus = backend_get_json(
                &api_url_with_base(
                    &base,
                    &format!("/api/v1/setup-claims/{}", code.expose_secret()),
                ),
                &[],
            )?;
            eprintln!("ottto-service: local history recovery outcome=claim_recovered");
            Ok(ReceiptRecovery::Claim(SetupClaimCreateResponse {
                claim_code: code.expose_secret().to_string(),
                claim_token: token.expose_secret().to_string(),
                client_nonce: Some(nonce.expose_secret().to_string()),
                claim_url: status.claim_url,
                expires_at: status.expires_at,
            }))
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

pub(in crate::control) fn persist_history_browser_claim(
    claim: &SetupClaimCreateResponse,
    nonce: &str,
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    history_save(
        stores.browser.as_ref(),
        &StoredHistoryBrowserClaim {
            installation_id: machine.installation_id.clone(),
            account_scope: machine.account_scope.clone(),
            api_base_url: base.to_string(),
            setup_run_id: history_connection_store()
                .load()
                .or_state_poisoned()?
                .filter(|c| c.api_base_url == base)
                .map(|c| c.setup_run_id),
            registration_pending: history_account_store()
                .load()
                .is_ok_and(|account| registration_history_choice_account(&account)),
            nonce: SecretString::new(claim.client_nonce.as_deref().unwrap_or(nonce)),
            claim: claim.clone(),
        },
    )
}

pub(in crate::control) fn create_setup_claim_with_history(
    url: &str,
    machine: &MachineIdentity,
    nonce: &str,
    stores: &HistoryStores,
    now: i64,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let base = validated_api_base_url(Some(
        url.strip_suffix("/api/v1/setup-claims")
            .ok_or(LocalApiError::StatePoisoned)?,
    ))?;
    let expected = local_history_recovery_expected()?;
    let mut marker: Option<LocalReleaseMarker> = match history_load(stores.marker.as_ref()) {
        Ok(marker) => marker,
        Err(_) if !expected => None,
        Err(error) => return Err(error),
    };
    if marker.as_ref().is_some_and(|m| {
        m.ceremony_closed
            || now
                .checked_sub(m.released_at)
                .is_some_and(|age| age >= REVOCATION_RECEIPT_MAX_AGE_SECONDS)
    }) {
        clear_local_release(stores)?;
        marker = None;
    }
    // Only a release or registration refusal needs durable recovery. Existing
    // first-time and same-account sign-in still works with file-only stores.
    if marker.is_none() && !local_history_recovery_expected()? {
        return backend_post_json(url, &setup_claim_create_body(machine, nonce), &[]);
    }
    if marker.is_none()
        && expected
        && !history_account_store()
            .load()
            .is_ok_and(|a| registration_history_choice_account(&a))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let stored = history_load::<StoredRevocationReceipt>(stores.receipt.as_ref());
    let mut receipt = stored.ok().flatten().filter(|r| {
        now.checked_sub(r.received_at)
            .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if let Some(marker) = &marker {
        if marker.api_base_url != base {
            return Err(LocalApiError::StatePoisoned);
        }
        if receipt.is_none() || marker.cleanup_required {
            let proof = history_load::<LocalReleaseProof>(stores.proof.as_ref())?
                .ok_or(LocalApiError::StatePoisoned)?;
            match reissue_revocation_receipt(marker, &proof)? {
                ReceiptRecovery::Receipt(value) => {
                    history_save(
                        stores.receipt.as_ref(),
                        &StoredRevocationReceipt {
                            revocation_receipt: value.clone(),
                            received_at: now,
                        },
                    )?;
                    receipt = Some(StoredRevocationReceipt {
                        revocation_receipt: value,
                        received_at: now,
                    });
                }
                ReceiptRecovery::Claim(claim) => {
                    persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
                    return Ok(claim);
                }
                ReceiptRecovery::Refused => {
                    receipt = None;
                }
            }
        }
    } else if receipt.is_none() {
        // No released-local marker means an ordinary first/same-device claim.
        // A corrupt orphan receipt is purged, never logged or sent.
        stores.receipt.delete().or_state_poisoned()?;
    }
    let mut body = setup_claim_create_body(machine, nonce);
    if let Some(receipt) = &receipt {
        body["revocation_receipt"] = json!(receipt.revocation_receipt.expose_secret());
    }
    let response = crate::retry_tls::credential_agent()
        .post(url)
        .set("Accept", "application/json")
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_json(&body);
    match response {
        Ok(response) => {
            let response = backend_success(url, response)?;
            let claim: SetupClaimCreateResponse = response
                .into_json()
                .map_err(|error| backend_response_unexpected(url, error.to_string()))?;
            if claim.claim_code.trim().is_empty()
                || claim.claim_token.trim().is_empty()
                || claim.claim_url.trim().is_empty()
            {
                return Err(LocalApiError::StatePoisoned);
            }
            // Durable browser handoff precedes secret cleanup. Even a lost local
            // reply/restart returns this exact ceremony and its original nonce.
            persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
            if stores.receipt.delete().is_err() {
                if let Some(mut marker) = marker {
                    marker.cleanup_required = true;
                    history_save(stores.marker.as_ref(), &marker)?;
                }
            }
            Ok(claim)
        }
        Err(error) => {
            if matches!(&error, ureq::Error::Status(status, _) if definitive_claim_refusal(*status))
            {
                clear_local_release(stores)?;
            }
            Err(backend_error_from_ureq(url, error))
        }
    }
}

fn definitive_claim_refusal(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 425 | 429)
}

pub(in crate::control) fn resume_history_browser_claim(
    machine: &MachineIdentity,
    base: &str,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let _lock = lock_history_recovery()?;
    resume_history_browser_claim_with_stores(machine, base, &history_stores())
}

pub(in crate::control) fn resume_history_browser_claim_with_stores(
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let stored = match history_load::<StoredHistoryBrowserClaim>(stores.browser.as_ref()) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Ok(None),
        Err(_) if !local_history_recovery_expected()? => return Ok(None),
        Err(_) if history_load::<LocalReleaseMarker>(stores.marker.as_ref())?.is_some() => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    if stored.installation_id != machine.installation_id
        || stored.account_scope != machine.account_scope
        || stored.api_base_url != base
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if auth_claim_is_expired(&stored.claim.expires_at) {
        return Ok(None);
    }
    Ok(Some(PendingAuthClaim {
        claim_code: stored.claim.claim_code,
        claim_token: stored.claim.claim_token,
        nonce: stored.nonce.expose_secret().to_string(),
        claim_url: append_nonce_to_claim_url(&stored.claim.claim_url, stored.nonce.expose_secret()),
        expires_at: stored.claim.expires_at,
    }))
}

fn finish_history_browser_claim(claim_code: &str) -> Result<(), LocalApiError> {
    let _lock = lock_history_recovery()?;
    finish_history_browser_claim_with_stores(claim_code, &history_stores())
}

pub(in crate::control) fn finish_history_browser_claim_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let stored: Option<StoredHistoryBrowserClaim> = history_load(stores.browser.as_ref())?;
    if !stored.is_some_and(|stored| stored.claim.claim_code == claim_code) {
        return Ok(());
    }
    clear_local_release(stores)?;
    stores.browser.delete().or_state_poisoned()
}

pub(in crate::control) fn setup_claim_create_body(
    machine: &MachineIdentity,
    nonce: &str,
) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
        "client_nonce": nonce,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

pub(in crate::control) fn complete_setup_claim(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
    identity_reservation: Option<&IdentityMutationReservation>,
) -> Result<SetupClaimCompletion, LocalApiError> {
    let url = api_url(&format!(
        "/api/v1/setup-claims/{}/local-client/complete",
        claim.claim_code
    ));
    // Snapshot established file + Keychain authority under the identity
    // lifecycle fence. Network I/O runs without the mutex, while the
    // reservation prevents legitimate local writers from rotating authority.
    let prior_device_credential = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        prior_device_credential_for_registration()?
    };
    let request_authority = device_credential_request_authority(
        "setup_claim",
        &claim.claim_code,
        machine,
        prior_device_credential.as_ref(),
        prior_device_credential
            .as_ref()
            .map(|_| IDENTITY_CONTINUITY_CAPABILITY),
    );
    let mut body = setup_claim_complete_body(claim, machine);
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "credential_preparation_capability".to_string(),
            json!(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY),
        );
        object.insert(
            "credential_preparation_idempotency_key".to_string(),
            json!(request_authority
                .credential_preparation_idempotency_key
                .clone()),
        );
    }
    if let Some(prior) = prior_device_credential.as_ref() {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "identity_continuity_capability".to_string(),
                json!(IDENTITY_CONTINUITY_CAPABILITY),
            );
            object.insert("relay_device_id".to_string(), json!(prior.device_id));
            object.insert(
                "relay_device_sources".to_string(),
                json!(prior.device_sources),
            );
            object.insert(
                "prior_device_secret".to_string(),
                json!(prior.device_secret),
            );
        }
    }
    let response = backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Setup-Claim-Token", claim.claim_token.as_str())],
    )?;
    // Revalidate immediately after the remote preparation and before any
    // journal write. This catches out-of-band Keychain mutation in addition
    // to file/account mutations fenced by the reservation snapshot.
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        let current = prior_device_credential_for_registration()?;
        if !same_prior_device_authority(prior_device_credential.as_ref(), current.as_ref()) {
            return Err(LocalApiError::StatePoisoned);
        }
    }
    Ok(SetupClaimCompletion {
        response,
        prior_device_credential,
        request_authority,
    })
}

pub(in crate::control) fn setup_claim_complete_body(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
) -> serde_json::Value {
    json!({
        "nonce": claim.nonce,
        "machine_id": machine.machine_id,
        "machine_identity_capability": MACHINE_IDENTITY_CAPABILITY,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
    })
}
