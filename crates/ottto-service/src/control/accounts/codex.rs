//! accounts codex for local control.

use crate::control::CodexAccountSetupOperationStateV1;
use crate::control::CodexAccountSlotSettingsError;
use crate::control::Duration;
use crate::control::FileCodexAccountSlotSettingsStore;
use crate::control::Instant;
use crate::control::LocalApiError;
use crate::control::Mutex;
use crate::control::SourceKind;

fn load_codex_account_settings() -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .load()
        .map_err(codex_account_slot_settings_error)
        .map(crate::agent_status::annotate_codex_accounts_status)
}

/// How long a status read may reuse the last annotated Codex accounts status.
/// Annotation serves each home's saved quota (it never starts `codex
/// app-server`), but it still runs the local `codex login status` and model
/// listing per home. The companion polls this read every few seconds while an
/// accounts surface is visible, so the reuse bounds those local runs.
const CODEX_ACCOUNTS_STATUS_READ_REUSE: Duration = Duration::from_secs(30);

struct CachedCodexAccountsStatus {
    settings: ottto_protocol::CodexAccountsStatusV1,
    /// [`crate::agent_status::saved_codex_quota_generation`] when annotated.
    saved_quota_generation: u64,
    annotated: ottto_protocol::CodexAccountsStatusV1,
    annotated_at: Instant,
}

/// The polled read. Reuses a recent annotation while the stored settings and
/// the saved quota readings are unchanged; any settings change (connect,
/// remove, prepare) or newly saved reading misses the cache. Holding the lock
/// across annotation also collapses concurrent polls into one annotation.
pub(in crate::control) fn load_codex_account_settings_for_status_read(
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    static CACHE: Mutex<Option<CachedCodexAccountsStatus>> = Mutex::new(None);
    let settings = FileCodexAccountSlotSettingsStore::default()
        .load()
        .map_err(codex_account_slot_settings_error)?;
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let saved_quota_generation = crate::agent_status::saved_codex_quota_generation();
    if let Some(cached) = cache.as_ref() {
        if status_read_reusable(
            &(&cached.settings, cached.saved_quota_generation),
            cached.annotated_at,
            &(&settings, saved_quota_generation),
            Instant::now(),
        ) {
            return Ok(cached.annotated.clone());
        }
    }
    let annotated = crate::agent_status::annotate_codex_accounts_status(settings.clone());
    *cache = Some(CachedCodexAccountsStatus {
        settings,
        saved_quota_generation,
        annotated: annotated.clone(),
        annotated_at: Instant::now(),
    });
    Ok(annotated)
}

fn status_read_reusable<T: PartialEq>(
    cached_settings: &T,
    annotated_at: Instant,
    settings: &T,
    now: Instant,
) -> bool {
    cached_settings == settings
        && now.saturating_duration_since(annotated_at) < CODEX_ACCOUNTS_STATUS_READ_REUSE
}

pub(in crate::control) fn prepare_codex_account(
    schema_version: u16,
    operation_id: String,
    expected_account_identifier_hash: String,
    expected_workspace_identifier_hash: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .prepare_managed_account(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        )
        .map_err(codex_account_slot_settings_error)
}

pub(in crate::control) fn prepare_open_codex_account(
    schema_version: u16,
    operation_id: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .prepare_open_account(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)
}

pub(in crate::control) fn prepare_codex_account_target(
    schema_version: u16,
    operation_id: String,
    target_id: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let current = load_codex_account_settings()?;
    let (account_hash, workspace_hash) =
        codex_account_target_binding(&current, target_id.as_str())?;
    prepare_codex_account(schema_version, operation_id, account_hash, workspace_hash)
}

pub(in crate::control) fn codex_account_target_binding(
    current: &ottto_protocol::CodexAccountsStatusV1,
    target_id: &str,
) -> Result<(String, String), LocalApiError> {
    let target = current
        .target_coverage
        .targets
        .iter()
        .find(|target| target.target_id == target_id)
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex workspace is not a current daemon-selected setup target".to_string(),
            )
        })?;
    if !target.connectable
        || target.durability == ottto_protocol::CodexAccountTargetDurabilityV1::Durable
        || !target.setup_blockers.is_empty()
    {
        return Err(LocalApiError::InvalidRequest(
            "Codex workspace target is not currently eligible for durable setup".to_string(),
        ));
    }
    let account_hash = target.account_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Codex workspace target does not have a confirmed account identity".to_string(),
        )
    })?;
    let workspace_hash = target.workspace_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Codex workspace target does not have a confirmed workspace identity".to_string(),
        )
    })?;
    Ok((account_hash, workspace_hash))
}

pub(in crate::control) fn reconnect_codex_account(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    expected_account_identifier_hash: String,
    expected_workspace_identifier_hash: String,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    FileCodexAccountSlotSettingsStore::default()
        .begin_reconnect(
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        )
        .map_err(codex_account_slot_settings_error)
}

pub(in crate::control) fn check_codex_account(
    schema_version: u16,
    operation_id: &str,
    explicit: bool,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let store = FileCodexAccountSlotSettingsStore::default();
    let current_operation = store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?;
    // A daemon-run sign-in reads the account itself when `codex login` ends,
    // so a check while it runs (an older client polling, or a second app)
    // only reports where it is.
    if current_operation.state == CodexAccountSetupOperationStateV1::Complete
        || crate::codex_sign_in::is_running(&current_operation)
    {
        return store
            .load()
            .map_err(codex_account_slot_settings_error)
            .map(crate::agent_status::annotate_codex_accounts_status);
    }
    // `codex login` completes outside this request. A visible client is allowed
    // to poll while the provider-owned browser flow is open, but an incomplete
    // login is progress, not a failed durable connection. Probe before moving
    // the persisted operation to `validating`; only a complete exact identity
    // and fresh quota snapshot crosses that state boundary. Clients poll this
    // every few seconds, so the probe's provider reads are spaced per home.
    let pending_collection = if current_operation.state
        == CodexAccountSetupOperationStateV1::WaitingForUserLogin
    {
        let slot_id = current_operation.slot_id.as_deref().ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex setup operation has no durable connection slot".to_string(),
            )
        })?;
        match crate::agent_status::collect_registered_codex_slot_for_setup(
            slot_id,
            crate::agent_status::CodexSetupRead::WaitingForLogin {
                operation_id,
                explicit,
            },
        ) {
            Ok(result) => Some(Ok(result)),
            Err(crate::agent_status::CodexSlotSetupCollectionError::ProviderLoginPending(_)) => {
                return store
                    .load()
                    .map_err(codex_account_slot_settings_error)
                    .map(crate::agent_status::annotate_codex_accounts_status);
            }
            Err(error) => Some(Err(error)),
        }
    } else {
        None
    };
    store
        .begin_validation(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)?;
    let slot_id = codex_setup_slot_id(&store, operation_id)?;
    if store
        .is_verifying_pinned_workspace(operation_id)
        .map_err(codex_account_slot_settings_error)?
    {
        return verify_pinned_codex_setup(&store, schema_version, operation_id, &slot_id)
            .map(|(status, _)| crate::agent_status::annotate_codex_accounts_status(status));
    }
    let collection = match pending_collection {
        Some(result) => result,
        None => crate::agent_status::collect_registered_codex_slot_for_setup(
            &slot_id,
            crate::agent_status::CodexSetupRead::Validation,
        ),
    };
    finish_codex_setup_validation(&store, schema_version, operation_id, &slot_id, collection)
        .map(|(status, _)| crate::agent_status::annotate_codex_accounts_status(status))
}

/// How the validation of a Codex setup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexSetupValidationEnd {
    /// The exact account and workspace is connected.
    Accepted,
    IdentityMismatch,
    DuplicateAccount,
    /// The workspace restriction did not hold in a fresh provider session.
    WorkspaceNotKept,
    /// The account read failed; the setup failed with its message.
    ReadFailed,
}

/// The managed slot of the setup operation.
pub(crate) fn codex_setup_slot_id(
    store: &FileCodexAccountSlotSettingsStore,
    operation_id: &str,
) -> Result<String, LocalApiError> {
    store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?
        .slot_id
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Codex setup operation has no durable connection slot".to_string(),
            )
        })
}

/// The fresh restricted read that accepts a pinned workspace, for a setup
/// whose restriction is already durable.
pub(crate) fn verify_pinned_codex_setup(
    store: &FileCodexAccountSlotSettingsStore,
    schema_version: u16,
    operation_id: &str,
    slot_id: &str,
) -> Result<
    (
        ottto_protocol::CodexAccountsStatusV1,
        CodexSetupValidationEnd,
    ),
    LocalApiError,
> {
    let operation = store
        .setup_operation(operation_id)
        .map_err(codex_account_slot_settings_error)?;
    let account_hash = operation
        .account_identifier_hash
        .as_deref()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Pinned Codex verification has no account identity.".to_string(),
            )
        })?;
    let workspace_hash = operation
        .workspace_identifier_hash
        .as_deref()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Pinned Codex verification has no workspace identity.".to_string(),
            )
        })?;
    let sign_in_home = store
        .setup_sign_in_home(slot_id)
        .map_err(codex_account_slot_settings_error)?;
    let slot_home = store
        .slot_home(slot_id)
        .map_err(codex_account_slot_settings_error)?;
    // A login in a staging home moves into the slot only when the read saw
    // the same file from its start to its end: one replaced meanwhile (another
    // sign-in into that home) may belong to someone else.
    let read_from = ottto_core::codex_auth_file_mark(&sign_in_home);
    match crate::agent_status::collect_registered_codex_slot_for_setup(
        slot_id,
        crate::agent_status::CodexSetupRead::Validation,
    ) {
        Ok((pinned, _))
            if pinned.account_identifier_hash == account_hash
                && pinned.workspace_identifier_hash == workspace_hash =>
        {
            let validated_login = ottto_core::codex_auth_file_mark(&sign_in_home);
            if sign_in_home != slot_home
                && (validated_login.is_none() || validated_login != read_from)
            {
                return store
                    .fail_validation(
                        schema_version,
                        operation_id,
                        "The Codex login changed while Ottto checked it. Sign in again.",
                    )
                    .map_err(codex_account_slot_settings_error)
                    .map(|status| (status, CodexSetupValidationEnd::ReadFailed));
            }
            // The verified login is published into the slot's home under that
            // home's read lock, so no limit read rewrites the slot's credential
            // meanwhile; the store publishes only the file with this mark.
            crate::agent_status::with_codex_home_read_lock(&slot_home, || {
                store
                    .complete_pinned_verification(
                        schema_version,
                        operation_id,
                        account_hash,
                        workspace_hash,
                        validated_login,
                    )
                    .inspect(|_| {
                        if sign_in_home != slot_home {
                            crate::agent_status::adopt_saved_codex_reading(
                                &sign_in_home,
                                &slot_home,
                            );
                        }
                    })
            })
            .map_err(codex_account_slot_settings_error)
            .map(|status| (status, CodexSetupValidationEnd::Accepted))
        }
        _ => store
            .fail_validation(
                schema_version,
                operation_id,
                "Codex workspace restriction did not survive a fresh provider restart.",
            )
            .map_err(codex_account_slot_settings_error)
            .map(|status| (status, CodexSetupValidationEnd::WorkspaceNotKept)),
    }
}

/// Validate a setup from one account read of its home: accept the exact
/// identity (pinning its workspace and verifying the pin in a fresh read),
/// or record a mismatch, a duplicate, or the read's failure.
pub(crate) fn finish_codex_setup_validation(
    store: &FileCodexAccountSlotSettingsStore,
    schema_version: u16,
    operation_id: &str,
    slot_id: &str,
    collection: Result<
        (
            crate::agent_status::CodexStrongIdentity,
            ottto_protocol::CodexAccountSlotCollectionStatusV1,
        ),
        crate::agent_status::CodexSlotSetupCollectionError,
    >,
) -> Result<
    (
        ottto_protocol::CodexAccountsStatusV1,
        CodexSetupValidationEnd,
    ),
    LocalApiError,
> {
    let (identity, _) = match collection {
        Ok(result) => result,
        Err(error) => {
            return store
                .fail_validation(schema_version, operation_id, error.message())
                .map_err(codex_account_slot_settings_error)
                .map(|status| (status, CodexSetupValidationEnd::ReadFailed));
        }
    };
    let duplicate = store
        .has_registered_binding(
            &identity.account_identifier_hash,
            &identity.workspace_identifier_hash,
            Some(slot_id),
        )
        .map_err(codex_account_slot_settings_error)?;
    let status = store
        .finish_validation(
            schema_version,
            operation_id,
            identity.account_identifier_hash.clone(),
            identity.workspace_identifier_hash.clone(),
            &identity.raw_workspace_id,
            duplicate,
        )
        .map_err(codex_account_slot_settings_error)?;
    if store
        .is_verifying_pinned_workspace(operation_id)
        .map_err(codex_account_slot_settings_error)?
    {
        return verify_pinned_codex_setup(store, schema_version, operation_id, slot_id);
    }
    let end = match status.setup_operation.state {
        CodexAccountSetupOperationStateV1::DuplicateAccount => {
            CodexSetupValidationEnd::DuplicateAccount
        }
        CodexAccountSetupOperationStateV1::Complete => CodexSetupValidationEnd::Accepted,
        _ => CodexSetupValidationEnd::IdentityMismatch,
    };
    Ok((status, end))
}

/// v26: start the daemon-run sign-in of a setup operation.
pub(in crate::control) fn start_codex_sign_in(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    crate::codex_sign_in::start(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)?;
    load_codex_account_settings()
}

pub(in crate::control) fn stop_waiting_for_codex_account(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    // A running `codex login` ends first, so it cannot write into a home that
    // stopping is about to remove; the sign-in then stops the setup itself.
    if crate::codex_sign_in::cancel(operation_id) {
        return load_codex_account_settings();
    }
    FileCodexAccountSlotSettingsStore::default()
        .stop_waiting(schema_version, operation_id)
        .map_err(codex_account_slot_settings_error)
        .map(crate::agent_status::annotate_codex_accounts_status)
}

pub(in crate::control) fn set_codex_quota_refresh_consent(
    schema_version: u16,
    consent: bool,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let status = FileCodexAccountSlotSettingsStore::default()
        .set_quota_refresh_consent(schema_version, consent)
        .map_err(codex_account_slot_settings_error)?;
    // Switched on: the schedule's next round runs now, not at its next wake.
    if consent {
        crate::agent_status::wake_codex_quota_scheduler();
    }
    Ok(crate::agent_status::annotate_codex_accounts_status(status))
}

pub(in crate::control) fn remove_codex_account(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::CodexAccountsStatusV1, LocalApiError> {
    let store = FileCodexAccountSlotSettingsStore::default();
    // A sign-in into the home being removed ends first, so `codex login`
    // never writes into a removed home.
    if let Ok(status) = store.load() {
        let operation = &status.setup_operation;
        if operation.slot_id.as_deref() == Some(slot_id)
            && crate::codex_sign_in::is_running(operation)
            && status
                .managed_slots
                .iter()
                .any(|slot| slot.slot_id == slot_id)
        {
            if let Some(operation_id) = operation.operation_id.as_deref() {
                stop_waiting_for_codex_account(schema_version, operation_id)?;
            }
        }
    }
    // Under the home's read lock: a limits read that may be renewing its login
    // ends (and drains) before the home is removed, so none writes it back.
    let remove = || store.remove(schema_version, slot_id);
    match store.slot_home(slot_id) {
        Ok(home) => crate::agent_status::with_codex_home_read_lock(&home, remove),
        Err(_) => remove(),
    }
    .map_err(codex_account_slot_settings_error)
    .map(crate::agent_status::annotate_codex_accounts_status)
    .inspect(|_| crate::agent_status_refresh::request_now(&SourceKind::Codex))
}

fn codex_account_slot_settings_error(error: CodexAccountSlotSettingsError) -> LocalApiError {
    match error {
        CodexAccountSlotSettingsError::Invalid(message) => LocalApiError::InvalidRequest(message),
        CodexAccountSlotSettingsError::State(_) => LocalApiError::StatePoisoned,
    }
}
