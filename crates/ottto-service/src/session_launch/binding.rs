use super::{block, Block, Reason};
use crate::hex::is_sha256_lower;
use ottto_core::{
    session_launch::LaunchUser, ClaudeConfigDirSlot, CodexHomeTrust,
    FileClaudeConfigSlotSettingsStore, FileCodexAccountSlotSettingsStore,
};
use ottto_protocol::{
    ClaudeConfigSlotCollectionStateV1 as ClaudeState,
    CodexAccountSlotCollectionStateV1 as CodexState, SessionLaunchProviderV1 as Provider,
};
use std::path::PathBuf;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Binding {
    pub provider: Provider,
    pub slot_id: String,
    pub account: String,
    pub organization: String,
    pub root: PathBuf,
    pub claude_slot: Option<ClaudeConfigDirSlot>,
    pub user: LaunchUser,
}

pub(super) fn resolve(
    provider: Provider,
    slot_id: &str,
    account: &str,
    organization: &str,
    user: LaunchUser,
) -> Result<Binding, Block> {
    if !is_sha256_lower(account) || (!organization.is_empty() && !is_sha256_lower(organization)) {
        return Err(block(Reason::AccountMismatch));
    }
    let (root, claude_slot) = match provider {
        Provider::ClaudeCode => {
            let store = FileClaudeConfigSlotSettingsStore::default();
            let status = crate::agent_status::annotate_claude_accounts_status(
                store.load().map_err(|_| block(Reason::SlotNotFound))?,
            );
            let descriptor = std::iter::once(&status.default_slot)
                .chain(&status.managed_slots)
                .chain(&status.external_slots)
                .find(|slot| slot.slot_id == slot_id)
                .ok_or_else(|| block(Reason::SlotNotFound))?;
            if matches!(
                descriptor.collection.relationship,
                Some(
                    ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor
                        | ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor
                )
            ) {
                return Err(block(Reason::AccountMismatch));
            }
            match descriptor.collection.state {
                ClaudeState::NeedsLogin | ClaudeState::CredentialUnavailable => {
                    return Err(block(Reason::SlotNeedsLogin))
                }
                ClaudeState::IdentityMismatch | ClaudeState::DuplicateAccount => {
                    return Err(block(Reason::AccountMismatch))
                }
                ClaudeState::Fresh
                | ClaudeState::RefreshDue
                | ClaudeState::UpkeepNotConsented
                | ClaudeState::ReloginApproaching => {}
                _ => return Err(block(Reason::SlotNotVerified)),
            }
            if descriptor.collection.account_identifier_hash.as_deref() != Some(account)
                || descriptor
                    .collection
                    .organization_identifier_hash
                    .as_deref()
                    .unwrap_or("")
                    != organization
            {
                return Err(block(Reason::AccountMismatch));
            }
            let slot = match &descriptor.config_dir {
                Some(dir) => ClaudeConfigDirSlot::registered(dir.clone())
                    .map_err(|_| block(Reason::SlotNotFound))?,
                None if slot_id == "default" => ClaudeConfigDirSlot::Default,
                None => return Err(block(Reason::SlotNotFound)),
            };
            if slot_id != "default" {
                let approved = store
                    .expected_slot_binding(slot_id)
                    .map_err(|_| block(Reason::SlotNotVerified))?
                    .ok_or_else(|| block(Reason::SlotNotVerified))?;
                if approved.account_identifier_hash != account
                    || approved.organization_identifier_hash != organization
                {
                    return Err(block(Reason::AccountMismatch));
                }
            }
            if descriptor.collection.upkeep.as_ref().is_some_and(|status| {
                status.result == ottto_protocol::ClaudeConfigSlotUpkeepResultV1::InProgress
            }) {
                return Err(block(Reason::SlotNotVerified));
            }
            match crate::agent_status::session_launch_claude_login_state(&slot, &user.home) {
                crate::agent_status::ClaudeLocalLoginState::AccessValid
                | crate::agent_status::ClaudeLocalLoginState::RefreshPending => {}
                crate::agent_status::ClaudeLocalLoginState::Unreadable => {
                    return Err(block(Reason::SlotNotVerified))
                }
                _ => return Err(block(Reason::SlotNeedsLogin)),
            }
            let current = crate::agent_status::session_launch_claude_identity(&slot, &user.home)
                .ok_or_else(|| block(Reason::SlotNeedsLogin))?;
            if current.0 != account
                || current.1 != organization
                || descriptor.collection.account_identifier_hash.as_deref() != Some(account)
                || descriptor
                    .collection
                    .organization_identifier_hash
                    .as_deref()
                    .unwrap_or("")
                    != organization
            {
                return Err(block(Reason::AccountMismatch));
            }
            let root = slot
                .config_dir()
                .map(PathBuf::from)
                .unwrap_or_else(|| user.home.join(".claude"));
            (root, Some(slot))
        }
        Provider::Codex => {
            let store = FileCodexAccountSlotSettingsStore::default();
            let (auth_home, trust) = if slot_id == "default" {
                (user.home.join(".codex"), CodexHomeTrust::ProviderDefault)
            } else {
                (
                    store
                        .slot_home(slot_id)
                        .map_err(|_| block(Reason::SlotNotFound))?,
                    CodexHomeTrust::Managed,
                )
            };
            if crate::agent_status::session_launch_codex_api_key_route(&auth_home, trust) {
                return Err(block(Reason::CodexApiKeyLogin));
            }
            let status = crate::agent_status::session_launch_codex_accounts_status(
                store
                    .load_for_session_launch()
                    .map_err(|_| block(Reason::SlotNotFound))?,
                &user.home.join(".codex"),
            );
            let descriptor = std::iter::once(&status.default_slot)
                .chain(&status.managed_slots)
                .find(|slot| slot.slot_id == slot_id)
                .ok_or_else(|| block(Reason::SlotNotFound))?;
            if matches!(
                descriptor.collection.relationship,
                Some(
                    ottto_protocol::CodexAccountSlotRelationshipV1::ShadowedByAnchor
                        | ottto_protocol::CodexAccountSlotRelationshipV1::DuplicateAnchor
                )
            ) {
                return Err(block(Reason::AccountMismatch));
            }
            match descriptor.collection.state {
                CodexState::NeedsLogin => return Err(block(Reason::SlotNeedsLogin)),
                CodexState::IdentityMismatch | CodexState::DuplicateAccount => {
                    return Err(block(Reason::AccountMismatch))
                }
                CodexState::Fresh => {}
                _ => return Err(block(Reason::SlotNotVerified)),
            }
            let (root, trust) = if slot_id == "default" {
                (user.home.join(".codex"), CodexHomeTrust::ProviderDefault)
            } else {
                let approved = store
                    .registered_bindings()
                    .map_err(|_| block(Reason::SlotNotVerified))?
                    .into_iter()
                    .find(|slot| slot.slot_id == slot_id && slot.accepted)
                    .ok_or_else(|| block(Reason::SlotNotVerified))?;
                if approved.account_identifier_hash != account
                    || approved.workspace_identifier_hash != organization
                {
                    return Err(block(Reason::AccountMismatch));
                }
                (
                    store
                        .slot_home(slot_id)
                        .map_err(|_| block(Reason::SlotNotFound))?,
                    CodexHomeTrust::Managed,
                )
            };
            let current = crate::agent_status::session_launch_codex_identity(&root, trust)
                .ok_or_else(|| block(Reason::SlotNeedsLogin))?;
            if current.0 != account
                || current.1 != organization
                || descriptor.collection.account_identifier_hash.as_deref() != Some(account)
                || descriptor
                    .collection
                    .workspace_identifier_hash
                    .as_deref()
                    .unwrap_or("")
                    != organization
            {
                return Err(block(Reason::AccountMismatch));
            }
            (root, None)
        }
        Provider::Unknown => return Err(block(Reason::Unknown)),
    };
    if !root.is_absolute() {
        return Err(block(Reason::SlotNotVerified));
    }
    Ok(Binding {
        provider,
        slot_id: slot_id.into(),
        account: account.into(),
        organization: organization.into(),
        root,
        claude_slot,
        user,
    })
}

pub(super) fn recheck(binding: &Binding) -> Result<(), Block> {
    let current = resolve(
        binding.provider,
        &binding.slot_id,
        &binding.account,
        &binding.organization,
        binding.user.clone(),
    )?;
    if &current != binding {
        return Err(block(Reason::AccountMismatch));
    }
    Ok(())
}
