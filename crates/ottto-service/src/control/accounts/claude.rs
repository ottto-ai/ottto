//! accounts claude for local control.

use crate::control::claude_code_relay_env_for_machine_id;
use crate::control::current_rfc3339;
use crate::control::default_support_dir;
use crate::control::home_path;
use crate::control::rfc3339_after_minutes;
use crate::control::source_patch_disabled;
use crate::control::BTreeSet;
use crate::control::ClaudeAccountSetupOperationState;
use crate::control::ClaudeConfigSlotCollectionStateV1;
use crate::control::ClaudeConfigSlotSettingsError;
use crate::control::FileClaudeConfigSlotSettingsStore;
use crate::control::FileDeviceStore;
use crate::control::FileMachineStore;
use crate::control::LocalApiError;
use crate::control::Mutex;
use crate::control::MutexGuard;
use crate::control::OrStatePoisoned;
use crate::control::Path;
use crate::control::SourceKind;
use crate::control::AGENT_STATUS_SNAPSHOT_TTL_MINUTES;

pub(in crate::control) fn load_claude_config_slot_settings(
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
        .map(crate::claude_browser_auth::annotate_status)
}

fn complete_claude_registry_mutation(
    status: ottto_protocol::ClaudeAccountsStatusV1,
) -> ottto_protocol::ClaudeAccountsStatusV1 {
    crate::snapshot_sync::spawn_claude_agent_status_refresh("registry_mutation");
    crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(status),
    )
}

// Account setup must not grant telemetry consent. Only extend an already
// approved source's existing local relay configuration to daemon-owned roots.
static MANAGED_CLAUDE_SETTINGS_LOCK: Mutex<()> = Mutex::new(());

pub(in crate::control) fn lock_managed_claude_settings() -> MutexGuard<'static, ()> {
    MANAGED_CLAUDE_SETTINGS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) enum ManagedClaudeRelaySettings {
    Revoked,
    Missing,
    Body(String),
}

pub(crate) fn read_managed_claude_relay_settings(
) -> Result<ManagedClaudeRelaySettings, LocalApiError> {
    if source_patch_disabled(&SourceKind::ClaudeCode) {
        return Ok(ManagedClaudeRelaySettings::Revoked);
    }
    let device = FileDeviceStore::default().load().map_err(|_| {
        LocalApiError::LocalOperationFailed("read managed Claude source approval".into())
    })?;
    if !device.is_some_and(|device| device.sources.iter().any(|source| source == "claude_code")) {
        return Ok(ManagedClaudeRelaySettings::Revoked);
    }
    let Some(body) = crate::agent_configs::claude_managed_settings::read_settings(&home_path(
        ".claude/settings.json",
    ))
    .map_err(|_| {
        LocalApiError::LocalOperationFailed("read approved Claude relay settings".into())
    })?
    else {
        return Ok(ManagedClaudeRelaySettings::Missing);
    };
    Ok(ManagedClaudeRelaySettings::Body(body))
}

pub(crate) fn approved_managed_claude_relay_endpoint() -> Result<Option<String>, LocalApiError> {
    let body = match read_managed_claude_relay_settings()? {
        ManagedClaudeRelaySettings::Body(body) => body,
        ManagedClaudeRelaySettings::Revoked | ManagedClaudeRelaySettings::Missing => {
            return Ok(None)
        }
    };
    if crate::agent_configs::claude_managed_settings::approved_relay_port(&body).is_none() {
        return Ok(None);
    }
    let settings: serde_json::Value = serde_json::from_str(&body).or_state_poisoned()?;
    Ok(settings["env"]["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]
        .as_str()
        .map(str::to_owned))
}

pub(in crate::control) fn approved_managed_claude_relay_env(
) -> Result<Option<Vec<(&'static str, String)>>, LocalApiError> {
    let Some(endpoint) = approved_managed_claude_relay_endpoint()? else {
        return Ok(None);
    };
    let Some(port) = crate::otlp_relay::local_relay_port_from_endpoint(&endpoint) else {
        return Ok(None);
    };
    let Some(machine) = FileMachineStore::default().load().map_err(|_| {
        LocalApiError::LocalOperationFailed("read managed Claude machine binding".into())
    })?
    else {
        return Ok(None);
    };
    Ok(Some(claude_code_relay_env_for_machine_id(
        &machine.machine_id,
        &crate::otlp_relay::local_relay_base_url_for_port(port),
    )))
}

pub(crate) fn provision_managed_claude_relay_settings(
    config_dir: &str,
) -> Result<bool, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    let Some(env) = approved_managed_claude_relay_env()? else {
        return Ok(false);
    };
    let current = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    if !current.managed_slots.iter().any(|slot| {
        slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            && slot.config_dir.as_deref() == Some(config_dir)
    }) && !crate::claude_browser_auth::active_provisional_telemetry_root(config_dir)
    {
        return Ok(false);
    }
    provision_managed_claude_relay_settings_with_env(config_dir, &env)
}

fn provision_managed_claude_relay_settings_with_env(
    config_dir: &str,
    env: &[(&str, String)],
) -> Result<bool, LocalApiError> {
    validate_managed_claude_settings_root(config_dir)?;
    crate::agent_configs::claude_managed_settings::reconcile(Path::new(config_dir), env)
        .map(|outcome| outcome == crate::agent_configs::claude_managed_settings::Outcome::Changed)
        .map_err(|_| {
            LocalApiError::LocalOperationFailed(
                "managed Claude settings could not be safely provisioned".into(),
            )
        })
}

fn validate_managed_claude_settings_root(config_dir: &str) -> Result<(), LocalApiError> {
    // Lexical authority first; the settings writer then opens every component
    // without following links. Do not use the auth-root validator here: it
    // repairs permissions and can follow an intermediate parent link.
    let root = Path::new(config_dir);
    let managed_parent = default_support_dir().join(ottto_core::CLAUDE_MANAGED_ACCOUNTS_DIR_NAME);
    if root.parent() != Some(managed_parent.as_path())
        || ottto_core::ClaudeConfigDirSlot::registered(config_dir.to_owned()).is_err()
    {
        return Err(LocalApiError::LocalOperationFailed(
            "managed Claude settings root is unavailable or unsafe".into(),
        ));
    }
    Ok(())
}

pub(in crate::control) fn disable_managed_claude_relay_settings() -> Result<bool, LocalApiError> {
    crate::otlp_relay::legacy::revoke_now();
    let _settings_guard = lock_managed_claude_settings();
    use crate::agent_configs::claude_managed_settings::{disable_settings, Outcome};
    let default_root = home_path(".claude");
    let mut changed = disable_settings(&default_root, true).map_err(|_| {
        LocalApiError::LocalOperationFailed("Claude relay opt-out could not be safely saved".into())
    })? == Outcome::Changed;
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    let mut roots: BTreeSet<String> = status
        .managed_slots
        .iter()
        .filter(|slot| slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed)
        .filter_map(|slot| slot.config_dir.clone())
        .collect();
    roots.extend(crate::claude_browser_auth::managed_telemetry_roots());
    let mut failure = None;
    for root in roots {
        let result = validate_managed_claude_settings_root(&root).and_then(|()| {
            disable_settings(Path::new(&root), false).map_err(|_| {
                LocalApiError::LocalOperationFailed(
                    "managed Claude relay settings could not be safely disabled".into(),
                )
            })
        });
        match result {
            Ok(outcome) => changed |= outcome == Outcome::Changed,
            Err(error) => failure = Some(error),
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(changed)
}

#[cfg(test)]
pub(in crate::control) fn repair_registered_managed_claude_relay_settings(
) -> Result<bool, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    repair_registered_managed_claude_relay_settings_locked()
}

pub(in crate::control) fn repair_registered_managed_claude_relay_settings_locked(
) -> Result<bool, LocalApiError> {
    let Some(env) = approved_managed_claude_relay_env()? else {
        return Ok(false);
    };
    let status = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map_err(claude_config_slot_settings_error)?;
    let mut changed = false;
    let mut failure = None;
    for slot in status
        .managed_slots
        .iter()
        .filter(|slot| slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed)
    {
        if let Some(root) = slot.config_dir.as_deref() {
            match provision_managed_claude_relay_settings_with_env(root, &env) {
                Ok(updated) => changed |= updated,
                Err(error) => failure = Some(error),
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(changed)
}

fn complete_claude_setup_mutation(
    status: ottto_protocol::ClaudeAccountsStatusV1,
) -> ottto_protocol::ClaudeAccountsStatusV1 {
    if !claude_setup_operation_is_terminal(&status) {
        if let Some(root) = status
            .managed_slots
            .iter()
            .find(|slot| {
                Some(&slot.slot_id) == status.setup_operation.slot_id.as_ref()
                    && slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            })
            .and_then(|slot| slot.config_dir.as_deref())
        {
            if let Err(error) = provision_managed_claude_relay_settings(root) {
                eprintln!("managed Claude settings repair skipped: {error}");
            }
        }
    }
    complete_claude_registry_mutation(status)
}

fn claude_setup_operation_is_terminal(status: &ottto_protocol::ClaudeAccountsStatusV1) -> bool {
    matches!(
        status.setup_operation.state,
        ottto_protocol::ClaudeAccountSetupOperationState::Complete
            | ottto_protocol::ClaudeAccountSetupOperationState::SetupStopped
            | ottto_protocol::ClaudeAccountSetupOperationState::SetupFailed
            | ottto_protocol::ClaudeAccountSetupOperationState::IdentityMismatch
    )
}

fn active_claude_browser_replay(
    store: &FileClaudeConfigSlotSettingsStore,
    operation_id: &str,
    mode: crate::claude_browser_auth::BrowserLoginMode,
) -> Result<Option<ottto_protocol::ClaudeAccountsStatusV1>, LocalApiError> {
    store
        .setup_operation_if_exists(operation_id)
        .map_err(claude_config_slot_settings_error)
        .map(|status| {
            status.and_then(|status| {
                crate::claude_browser_auth::active_replay_is_sealed(&status, operation_id, mode)
                    .then(|| {
                        crate::claude_browser_auth::annotate_status(
                            crate::agent_status::annotate_claude_accounts_status(status),
                        )
                    })
            })
        })
}

pub(in crate::control) fn start_claude_browser_login(
    schema_version: u16,
    operation_id: String,
    target_id: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(claude_config_slot_settings_error)?,
        ),
    );
    let mode = if target_id.is_some() {
        crate::claude_browser_auth::BrowserLoginMode::Target
    } else {
        crate::claude_browser_auth::BrowserLoginMode::Generic
    };
    crate::claude_browser_auth::preflight_browser_binding(
        &operation_id,
        mode,
        None,
        target_id.as_deref(),
    )
    .map_err(LocalApiError::LocalOperationFailed)?;
    if let Some(replay) =
        crate::claude_browser_auth::terminal_replay(current.clone(), &operation_id)
    {
        return Ok(replay);
    }
    if target_id.is_some() {
        if let Some(replay) = active_claude_browser_replay(
            &store,
            &operation_id,
            crate::claude_browser_auth::BrowserLoginMode::Target,
        )? {
            return Ok(replay);
        }
    }
    let status = if let Some(target_id) = target_id {
        prepare_claude_account_target_mode(schema_version, operation_id.clone(), target_id, true)?
    } else {
        crate::claude_browser_auth::prepare_generic(current, &operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?
    };
    crate::claude_browser_auth::start(complete_claude_registry_mutation(status), mode)
        .map_err(LocalApiError::LocalOperationFailed)
}

pub(in crate::control) fn start_claude_browser_reconnect(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::claude_browser_auth::annotate_status(
        crate::agent_status::annotate_claude_accounts_status(
            store.load().map_err(claude_config_slot_settings_error)?,
        ),
    );
    crate::claude_browser_auth::preflight_browser_binding(
        &operation_id,
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
        Some(slot_id),
        Some(&target_id),
    )
    .map_err(LocalApiError::LocalOperationFailed)?;
    if let Some(replay) = crate::claude_browser_auth::terminal_replay(current, &operation_id) {
        return Ok(replay);
    }
    if let Some(replay) = active_claude_browser_replay(
        &store,
        &operation_id,
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
    )? {
        return Ok(replay);
    }
    let status = reconnect_claude_account_target_mode(
        schema_version,
        operation_id,
        slot_id,
        target_id,
        true,
    )?;
    crate::claude_browser_auth::start(
        complete_claude_registry_mutation(status),
        crate::claude_browser_auth::BrowserLoginMode::Reconnect,
    )
    .map_err(LocalApiError::LocalOperationFailed)
}

pub(in crate::control) fn set_claude_account_upkeep_consent(
    schema_version: u16,
    consent: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .set_upkeep_consent(schema_version, consent)
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_registry_mutation)
}

pub(in crate::control) fn remove_claude_account(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let status = remove_claude_registration_with_relay_cleanup(schema_version, slot_id)?;
    // Registration removal is authoritative; current-slot filtering excludes
    // orphan collection state if best-effort cleanup cannot complete.
    let _ = crate::agent_status::prune_claude_slot_collection_state(slot_id);
    let _ = crate::claude_upkeep::prune_slot_upkeep_state(slot_id);
    crate::claude_refresher::prune_slot(slot_id);
    let status = complete_claude_registry_mutation(status);
    // The Companion confirms removal from the next status pass, not after the
    // event gap. Other registry mutations keep the ordinary request.
    crate::agent_status_refresh::request_now(&SourceKind::ClaudeCode);
    Ok(status)
}

pub(crate) fn remove_claude_registration_with_relay_cleanup(
    schema_version: u16,
    slot_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let settings_guard = lock_managed_claude_settings();
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = store.load().map_err(claude_config_slot_settings_error)?;
    // Preserve the store's request-validation contract before settings effects.
    if schema_version == current.schema_version && slot_id != "default" {
        if let Some(root) = current
            .managed_slots
            .iter()
            .find(|slot| {
                slot.slot_id == slot_id
                    && slot.ownership == ottto_protocol::ClaudeConfigSlotOwnership::Managed
            })
            .and_then(|slot| slot.config_dir.as_deref())
        {
            validate_managed_claude_settings_root(root)?;
            crate::agent_configs::claude_managed_settings::disable_settings(Path::new(root), false)
                .map_err(|_| LocalApiError::LocalOperationFailed("managed Claude relay settings must be safely cleared before removing registration".into()))?;
        }
    }
    let status = store
        .remove(schema_version, slot_id)
        .map_err(claude_config_slot_settings_error)?;
    drop(settings_guard);
    Ok(status)
}

pub(in crate::control) fn register_claude_account_path(
    schema_version: u16,
    config_dir: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    FileClaudeConfigSlotSettingsStore::default()
        .register_path(schema_version, config_dir)
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_registry_mutation)
}

pub(in crate::control) fn prepare_claude_account(
    schema_version: u16,
    operation_id: String,
    target_id: Option<String>,
    expected_account_identifier_hash: Option<String>,
    expected_organization_identifier_hash: Option<String>,
    browser_mode: Option<crate::claude_browser_auth::BrowserLoginMode>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let _registry_guard = browser_mode
        .map(|_| crate::claude_browser_auth::registry_mutation_guard(&operation_id))
        .transpose()
        .map_err(LocalApiError::LocalOperationFailed)?;
    crate::claude_browser_auth::preflight_legacy_binding(&operation_id, target_id.as_deref())
        .map_err(LocalApiError::LocalOperationFailed)?;
    let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?;
    let reusable_root = if target_id.is_some() {
        crate::claude_browser_auth::claim_reusable_root(&operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?
    } else {
        None
    };
    if let Some(mode) = browser_mode {
        if let Err(error) = crate::claude_browser_auth::persist_registry_mutation_fence(
            &operation_id,
            mode,
            None,
            reusable_root.as_deref(),
            target_id.as_deref(),
            expected_account_identifier_hash.as_deref(),
            expected_organization_identifier_hash.as_deref(),
        ) {
            crate::claude_browser_auth::release_reusable_root_claim(&operation_id);
            if acquired {
                crate::claude_browser_auth::release_ceremony(&operation_id);
            }
            return Err(LocalApiError::LocalOperationFailed(error));
        }
    }
    let result = if let Some(config_dir) = reusable_root {
        store.prepare_managed_account_target_in_reusable_root(
            schema_version,
            operation_id.clone(),
            target_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
            config_dir,
        )
    } else {
        store.prepare_managed_account_target(
            schema_version,
            operation_id.clone(),
            target_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
        )
    }
    .map_err(claude_config_slot_settings_error)
    .map(complete_claude_setup_mutation);
    if result.is_err() {
        recover_failed_claude_browser_registry_mutation(
            &store,
            &operation_id,
            browser_mode,
            acquired,
        );
    } else if result
        .as_ref()
        .is_ok_and(claude_setup_operation_is_terminal)
        && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id))
    {
        crate::claude_browser_auth::release_ceremony(&operation_id);
    }
    result
}

pub(in crate::control) fn recover_failed_claude_browser_registry_mutation(
    store: &FileClaudeConfigSlotSettingsStore,
    operation_id: &str,
    browser_mode: Option<crate::claude_browser_auth::BrowserLoginMode>,
    acquired: bool,
) {
    let fence_aborted = browser_mode.is_some()
        && store
            .setup_operation_if_exists(operation_id)
            .is_ok_and(|operation| operation.is_none())
        && crate::claude_browser_auth::abort_registry_mutation_fence(operation_id).is_ok();
    if browser_mode.is_some() && !fence_aborted {
        // The exact reusable-root claim is part of recovery authority. Never
        // release it on a transient core mutation or lookup failure.
        crate::claude_browser_auth::resume_operation_recovery(operation_id);
    } else {
        crate::claude_browser_auth::release_reusable_root_claim(operation_id);
    }
    if acquired && (browser_mode.is_none() || fence_aborted) {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
}

pub(in crate::control) fn prepare_claude_account_legacy(
    schema_version: u16,
    operation_id: String,
    expected_account_identifier_hash: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
        .is_some()
    {
        crate::claude_browser_auth::preflight_legacy_binding(&operation_id, None)
            .map_err(LocalApiError::LocalOperationFailed)?;
        let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
            .map_err(LocalApiError::LocalOperationFailed)?;
        let result = store
            .replay_legacy_managed_account_setup(
                schema_version,
                &operation_id,
                expected_account_identifier_hash.as_deref(),
            )
            .map_err(claude_config_slot_settings_error)
            .map(complete_claude_setup_mutation);
        let terminal = result
            .as_ref()
            .is_ok_and(claude_setup_operation_is_terminal);
        if (acquired && result.is_err())
            || (terminal
                && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id)))
        {
            crate::claude_browser_auth::release_ceremony(&operation_id);
        }
        return result;
    }

    let expected_organization_identifier_hash = expected_account_identifier_hash
        .as_deref()
        .map(|account_hash| {
            let current = crate::agent_status::annotate_claude_accounts_status(
                store.load().map_err(claude_config_slot_settings_error)?,
            );
            let organizations = current
                .anchor_coverage
                .accounts
                .iter()
                .filter(|account| account.account_identifier_hash == account_hash)
                .filter_map(|account| account.organization_identifier_hash.clone())
                .collect::<BTreeSet<_>>();
            if organizations.len() != 1 {
                return Err(LocalApiError::InvalidRequest(
                    "legacy Claude setup requires exactly one strong organization binding for the expected account"
                        .to_string(),
                ));
            }
            Ok(organizations
                .into_iter()
                .next()
                .expect("one organization was required"))
        })
        .transpose()?;

    prepare_claude_account(
        schema_version,
        operation_id,
        None,
        expected_account_identifier_hash,
        expected_organization_identifier_hash,
        None,
    )
}

pub(in crate::control) fn prepare_claude_account_target(
    schema_version: u16,
    operation_id: String,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    prepare_claude_account_target_mode(schema_version, operation_id, target_id, false)
}

pub(in crate::control) fn prepare_claude_account_target_mode(
    schema_version: u16,
    operation_id: String,
    target_id: String,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if let Some(existing) = store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
    {
        if existing.setup_operation.target_id.as_deref() != Some(target_id.as_str()) {
            return Err(LocalApiError::InvalidRequest(
                "setup operation target does not match its original binding".to_string(),
            ));
        }
        return prepare_claude_account(
            schema_version,
            operation_id,
            Some(target_id),
            existing.setup_operation.expected_account_identifier_hash,
            existing
                .setup_operation
                .expected_organization_identifier_hash,
            browser_fence.then_some(crate::claude_browser_auth::BrowserLoginMode::Target),
        );
    }
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let target = current
        .anchor_coverage
        .accounts
        .iter()
        .find(|account| account.target_id.as_deref() == Some(target_id.as_str()))
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "Claude account is not a current daemon-selected setup target".to_string(),
            )
        })?;
    if target.durability == ottto_protocol::ClaudeAccountAnchorDurabilityV1::Anchored
        || !target.setup_blockers.is_empty()
    {
        return Err(LocalApiError::InvalidRequest(
            "Claude anchor target is not currently eligible for managed setup".to_string(),
        ));
    }
    let organization_hash = target.organization_identifier_hash.clone().ok_or_else(|| {
        LocalApiError::InvalidRequest(
            "Claude anchor target does not have an unambiguous organization binding".to_string(),
        )
    })?;
    prepare_claude_account(
        schema_version,
        operation_id,
        Some(target_id),
        Some(target.account_identifier_hash.clone()),
        Some(organization_hash),
        browser_fence.then_some(crate::claude_browser_auth::BrowserLoginMode::Target),
    )
}

pub(in crate::control) fn reconnect_claude_account(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: Option<String>,
    expected_account_identifier_hash: String,
    expected_organization_identifier_hash: Option<String>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    reconnect_claude_account_mode(
        schema_version,
        operation_id,
        slot_id,
        target_id,
        expected_account_identifier_hash,
        expected_organization_identifier_hash,
        false,
    )
}

fn reconnect_claude_account_mode(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: Option<String>,
    expected_account_identifier_hash: String,
    expected_organization_identifier_hash: Option<String>,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let descriptor = current
        .managed_slots
        .iter()
        .chain(current.external_slots.iter())
        .find(|descriptor| descriptor.slot_id == slot_id)
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(format!(
                "unknown registered Claude account slot_id {slot_id}"
            ))
        })?;
    if descriptor.collection.account_identifier_hash.as_deref()
        != Some(expected_account_identifier_hash.as_str())
    {
        return Err(LocalApiError::InvalidRequest(
            "reconnect account binding does not match the slot's last strong identity".to_string(),
        ));
    }
    let organization_hash = descriptor
        .collection
        .organization_identifier_hash
        .clone()
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "reconnect requires the slot's last strong organization binding".to_string(),
            )
        })?;
    if expected_organization_identifier_hash
        .as_deref()
        .is_some_and(|expected| expected != organization_hash)
    {
        return Err(LocalApiError::InvalidRequest(
            "reconnect organization binding does not match the slot's last strong identity"
                .to_string(),
        ));
    }
    let _registry_guard = browser_fence
        .then(|| crate::claude_browser_auth::registry_mutation_guard(&operation_id))
        .transpose()
        .map_err(LocalApiError::LocalOperationFailed)?;
    crate::claude_browser_auth::preflight_legacy_binding(&operation_id, target_id.as_deref())
        .map_err(LocalApiError::LocalOperationFailed)?;
    let acquired = crate::claude_browser_auth::claim_ceremony(&operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?;
    if browser_fence {
        if let Err(error) = crate::claude_browser_auth::persist_registry_mutation_fence(
            &operation_id,
            crate::claude_browser_auth::BrowserLoginMode::Reconnect,
            Some(slot_id),
            descriptor.config_dir.as_deref(),
            target_id.as_deref(),
            Some(&expected_account_identifier_hash),
            Some(&organization_hash),
        ) {
            if acquired {
                crate::claude_browser_auth::release_ceremony(&operation_id);
            }
            return Err(LocalApiError::LocalOperationFailed(error));
        }
    }
    let result = store
        .begin_registered_slot_reconnect_target(
            schema_version,
            operation_id.clone(),
            slot_id,
            target_id,
            expected_account_identifier_hash,
            Some(organization_hash),
        )
        .map_err(claude_config_slot_settings_error)
        .map(complete_claude_setup_mutation);
    let terminal = result
        .as_ref()
        .is_ok_and(claude_setup_operation_is_terminal);
    let fence_aborted = result.is_err()
        && browser_fence
        && store
            .setup_operation_if_exists(&operation_id)
            .is_ok_and(|operation| operation.is_none())
        && crate::claude_browser_auth::abort_registry_mutation_fence(&operation_id).is_ok();
    if result.is_err() && browser_fence && !fence_aborted {
        crate::claude_browser_auth::resume_operation_recovery(&operation_id);
    }
    if (acquired && result.is_err() && (!browser_fence || fence_aborted))
        || (terminal
            && (acquired || !crate::claude_browser_auth::has_browser_operation(&operation_id)))
    {
        crate::claude_browser_auth::release_ceremony(&operation_id);
    }
    result
}

pub(in crate::control) fn reconnect_claude_account_target(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    reconnect_claude_account_target_mode(schema_version, operation_id, slot_id, target_id, false)
}

fn reconnect_claude_account_target_mode(
    schema_version: u16,
    operation_id: String,
    slot_id: &str,
    target_id: String,
    browser_fence: bool,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    if let Some(existing) = store
        .setup_operation_if_exists(&operation_id)
        .map_err(claude_config_slot_settings_error)?
    {
        if existing.setup_operation.target_id.as_deref() != Some(target_id.as_str()) {
            return Err(LocalApiError::InvalidRequest(
                "reconnect operation target does not match its original binding".to_string(),
            ));
        }
        return reconnect_claude_account_mode(
            schema_version,
            operation_id,
            slot_id,
            Some(target_id),
            existing
                .setup_operation
                .expected_account_identifier_hash
                .ok_or_else(|| {
                    LocalApiError::InvalidRequest("reconnect lost account binding".to_string())
                })?,
            existing
                .setup_operation
                .expected_organization_identifier_hash,
            browser_fence,
        );
    }
    let current = crate::agent_status::annotate_claude_accounts_status(
        store.load().map_err(claude_config_slot_settings_error)?,
    );
    let target = current
        .anchor_coverage
        .accounts
        .iter()
        .find(|account| account.target_id.as_deref() == Some(target_id.as_str()))
        .ok_or_else(|| {
            LocalApiError::InvalidRequest("unknown Claude anchor reconnect target".to_string())
        })?;
    if target.durability != ottto_protocol::ClaudeAccountAnchorDurabilityV1::Anchored {
        return Err(LocalApiError::InvalidRequest(
            "Claude reconnect target is not a registered anchor".to_string(),
        ));
    }
    reconnect_claude_account_mode(
        schema_version,
        operation_id,
        slot_id,
        Some(target_id),
        target.account_identifier_hash.clone(),
        target.organization_identifier_hash.clone(),
        browser_fence,
    )
}

pub(crate) fn check_claude_account(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    let result = check_claude_account_with_collector(
        schema_version,
        operation_id,
        expected_account_identifier_hash,
        crate::agent_status::collect_registered_claude_slot_status,
    );
    if result.as_ref().is_ok_and(|status| {
        matches!(
            status.setup_operation.state,
            ClaudeAccountSetupOperationState::Complete
                | ClaudeAccountSetupOperationState::SetupStopped
                | ClaudeAccountSetupOperationState::SetupFailed
                | ClaudeAccountSetupOperationState::IdentityMismatch
        )
    }) {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
    result
}

pub(in crate::control) fn check_claude_account_with_collector<F>(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
    collector: F,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError>
where
    F: FnOnce(&str, String, String) -> ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
{
    check_claude_account_with_hooks(
        schema_version,
        operation_id,
        expected_account_identifier_hash,
        || {},
        collector,
    )
}

fn check_claude_account_with_hooks<B, F>(
    schema_version: u16,
    operation_id: &str,
    expected_account_identifier_hash: Option<&str>,
    before_validating: B,
    collector: F,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError>
where
    B: FnOnce(),
    F: FnOnce(&str, String, String) -> ottto_protocol::ClaudeConfigSlotCollectionStatusV1,
{
    let store = FileClaudeConfigSlotSettingsStore::default();
    let current = store
        .setup_operation(operation_id)
        .map_err(claude_config_slot_settings_error)?;
    if let (Some(bound), Some(requested)) = (
        current
            .setup_operation
            .expected_account_identifier_hash
            .as_deref(),
        expected_account_identifier_hash,
    ) {
        if bound != requested {
            return Err(LocalApiError::InvalidRequest(
                "setup operation expected account does not match its original binding".to_string(),
            ));
        }
    }
    if current.setup_operation.kind
        == ottto_protocol::ClaudeAccountSetupOperationKind::ReconnectRegisteredSlot
    {
        let reconnect_slot_registered =
            current
                .setup_operation
                .slot_id
                .as_deref()
                .is_some_and(|slot_id| {
                    current
                        .managed_slots
                        .iter()
                        .chain(current.external_slots.iter())
                        .any(|slot| slot.slot_id == slot_id)
                });
        if !reconnect_slot_registered {
            return Err(LocalApiError::InvalidRequest(
                "reconnect operation slot is no longer registered".to_string(),
            ));
        }
    }

    // A crash-persisted Preparing intent has no registered credential slot to
    // inspect yet. Its authenticated status remains actionable and replaying
    // prepare resumes the same deterministic path transaction.
    if matches!(
        current.setup_operation.state,
        ClaudeAccountSetupOperationState::Preparing
            | ClaudeAccountSetupOperationState::SetupStopped
    ) {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            current,
        ));
    }
    let Some(_observation_guard) = store
        .try_setup_operation_observation(operation_id)
        .map_err(claude_config_slot_settings_error)?
    else {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            current,
        ));
    };
    let historical_state = current.setup_operation.state.clone();
    let historical_account_hash = current.setup_operation.account_identifier_hash.clone();
    let expected_organization_hash = current
        .setup_operation
        .expected_organization_identifier_hash
        .clone();
    let historical_organization_hash = current.setup_operation.organization_identifier_hash.clone();
    before_validating();
    let validating = store
        .transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Validating,
            historical_account_hash.as_deref(),
            historical_organization_hash.as_deref(),
            Some("Checking the exact registered Claude Code login."),
        )
        .map_err(claude_config_slot_settings_error)?;
    if validating.setup_operation.state != ClaudeAccountSetupOperationState::Validating {
        return Ok(crate::agent_status::annotate_claude_accounts_status(
            validating,
        ));
    }

    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    let slot_id = current
        .setup_operation
        .slot_id
        .as_deref()
        .ok_or(LocalApiError::StatePoisoned)?;
    let direct_slot_status = collector(slot_id, captured_at, expires_at);
    crate::agent_status::persist_one_claude_slot_collection_state(slot_id, &direct_slot_status)
        .or_state_poisoned()?;
    let refreshed = store
        .setup_operation(operation_id)
        .map_err(claude_config_slot_settings_error)?;
    let observed_account_hash = direct_slot_status.account_identifier_hash.as_deref();
    let observed_organization_hash = direct_slot_status.organization_identifier_hash.as_deref();
    let bound_account_hash = refreshed
        .setup_operation
        .expected_account_identifier_hash
        .as_deref()
        .or(expected_account_identifier_hash);
    let bound_organization_hash = refreshed
        .setup_operation
        .expected_organization_identifier_hash
        .as_deref();
    // `ConcurrentMutation` is a same-pass race (Claude Code rewrote the
    // account file between two reads), not proof of another account: a real
    // different owner is still caught by the binding comparisons below.
    if direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::IdentityMismatch
        || matches!((bound_account_hash, observed_account_hash), (Some(bound), Some(observed)) if bound != observed)
        || matches!((bound_organization_hash, observed_organization_hash), (Some(bound), Some(observed)) if bound != observed)
    {
        return store
            .transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::IdentityMismatch,
                None,
                None,
                Some("The exact slot did not match the expected Claude account. Complete /login with the intended account, then retry."),
            )
            .map_err(claude_config_slot_settings_error)
            .map(crate::agent_status::annotate_claude_accounts_status);
    }

    let full_read = direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::Fresh
        && direct_slot_status.last_full_quota_read_at.is_some()
        && direct_slot_status.has_account_windows
        && direct_slot_status.has_scoped_limits;
    let result = if full_read {
        let (Some(account_hash), Some(organization_hash)) =
            (observed_account_hash, observed_organization_hash)
        else {
            return Err(LocalApiError::StatePoisoned);
        };
        store
            .transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Reading,
                Some(account_hash),
                Some(organization_hash),
                Some("Identity matched. Reading full Claude quota for this exact account."),
            )
            .map_err(claude_config_slot_settings_error)?;
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Complete,
            Some(account_hash),
            Some(organization_hash),
            Some("Claude account identity and full quota read are complete."),
        )
    } else if let (Some(account_hash), Some(organization_hash)) =
        (observed_account_hash, observed_organization_hash)
    {
        if historical_state == ClaudeAccountSetupOperationState::Complete {
            store.transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Complete,
                Some(account_hash),
                Some(organization_hash),
                Some(
                    "Claude account remains identity-validated; the last full reading is retained.",
                ),
            )
        } else {
            store.transition_setup_operation_with_binding(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_organization_hash.as_deref(),
                ClaudeAccountSetupOperationState::Reading,
                Some(account_hash),
                Some(organization_hash),
                Some("Identity is validated; the full quota read has not completed yet."),
            )
        }
    } else if historical_state == ClaudeAccountSetupOperationState::Complete {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::Complete,
            historical_account_hash.as_deref(),
            historical_organization_hash.as_deref(),
            Some("This setup remains complete, but current exact-slot identity or quota evidence is temporarily unavailable."),
        )
    } else if direct_slot_status.state == ClaudeConfigSlotCollectionStateV1::ConcurrentMutation {
        // No verified account yet (an owner switch arrives as
        // `IdentityMismatch` above): keep waiting without asking for /login.
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
            None,
            None,
            Some("Ottto could not confirm this login yet; it will check it again."),
        )
    } else if matches!(
        direct_slot_status.state,
        ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            | ClaudeConfigSlotCollectionStateV1::IdentityUnknown
            | ClaudeConfigSlotCollectionStateV1::Unverified
    ) {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::WaitingForUserLogin,
            None,
            None,
            Some("Waiting for the customer to complete official Claude Code /login."),
        )
    } else {
        store.transition_setup_operation_with_binding(
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_organization_hash.as_deref(),
            ClaudeAccountSetupOperationState::SetupFailed,
            None,
            None,
            Some("Claude account validation could not complete from safe local evidence."),
        )
    };
    result
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
}

pub(in crate::control) fn stop_waiting_for_claude_account(
    schema_version: u16,
    operation_id: &str,
) -> Result<ottto_protocol::ClaudeAccountsStatusV1, LocalApiError> {
    if crate::claude_browser_auth::request_cancel(operation_id)
        .map_err(LocalApiError::LocalOperationFailed)?
    {
        return FileClaudeConfigSlotSettingsStore::default()
            .load()
            .map_err(claude_config_slot_settings_error)
            .map(crate::agent_status::annotate_claude_accounts_status)
            .map(crate::claude_browser_auth::annotate_status);
    }
    let result = FileClaudeConfigSlotSettingsStore::default()
        .stop_waiting(schema_version, operation_id)
        .map_err(claude_config_slot_settings_error)
        .map(crate::agent_status::annotate_claude_accounts_status)
        .map(crate::claude_browser_auth::annotate_status);
    if result.is_ok() {
        crate::claude_browser_auth::release_ceremony(operation_id);
    }
    result
}

fn claude_config_slot_settings_error(error: ClaudeConfigSlotSettingsError) -> LocalApiError {
    match error {
        ClaudeConfigSlotSettingsError::Invalid(message) => LocalApiError::InvalidRequest(message),
        ClaudeConfigSlotSettingsError::State(_) => LocalApiError::StatePoisoned,
    }
}
