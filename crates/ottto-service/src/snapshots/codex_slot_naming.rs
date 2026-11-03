//! Codex sessions named from their own creator record. Codex rollouts record
//! no login mode, so the per-row `auth_mode` proof never holds for them. A
//! session is also proven a subscription session when its complete
//! `codex_creator_header:v1` pair matches exactly one accepted registered
//! Ottto slot binding whose saved login is a subscription login when the
//! session is named. The owner is that binding. The evidence is sent
//! unchanged and no row gains an `auth_mode`.

use super::{SessionAccountBinding, SnapshotItem};
use serde::Serialize;

/// Why a matched slot's saved login does not prove a subscription login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotLoginRefusal {
    /// `auth.json` is absent or unreadable, or its `auth_mode` is not `chatgpt`.
    ModeUnreadable,
    /// `config.toml` is absent or unreadable, or lacks Ottto's
    /// `forced_login_method = "chatgpt"`.
    NotForcedChatgpt,
    /// A non-null API key in `auth.json`, or in the service's environment.
    ApiKey,
}

/// One accepted registered Ottto Codex slot binding and its login check.
#[derive(Debug, Clone)]
pub(crate) struct RegisteredSlotLogin {
    pub account_identifier_hash: String,
    pub workspace_identifier_hash: String,
    pub login: Result<(), SlotLoginRefusal>,
}

/// Local per-scan counts of sessions named from their creator record, and of
/// those refused, by cause. A session without a complete creator pair, or
/// already proven by its rows, is not counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct CreatorSlotNamingCounts {
    pub named: u64,
    pub no_match: u64,
    pub multi_match: u64,
    pub mode_unreadable: u64,
    pub not_forced_chatgpt: u64,
    pub api_key: u64,
}

impl CreatorSlotNamingCounts {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

crate::heap_layout_bound::fields!(CreatorSlotNamingCounts; named, no_match, multi_match, mode_unreadable, not_forced_chatgpt, api_key);

/// One scan's registered slots, read once before binding, and its counts.
/// The default has no slots, so nothing is named this way.
#[derive(Debug, Default)]
pub(crate) struct CreatorSlotNaming {
    pub slots: Vec<RegisteredSlotLogin>,
    pub counts: CreatorSlotNamingCounts,
}

impl CreatorSlotNaming {
    pub(crate) fn new(slots: Vec<RegisteredSlotLogin>) -> Self {
        Self {
            slots,
            counts: CreatorSlotNamingCounts::default(),
        }
    }

    /// The owner proven by `item`'s own complete creator pair, with each
    /// refusal counted by cause. Never a guess: no matching slot, several, or
    /// a matched slot whose saved login is not a subscription login names
    /// nothing. The caller counts `named` only when this owner is used.
    pub(super) fn owner(&mut self, item: &SnapshotItem) -> Option<SessionAccountBinding> {
        let (account, workspace) = creator_pair(item)?;
        let mut matches = self.slots.iter().filter(|slot| {
            slot.account_identifier_hash == account && slot.workspace_identifier_hash == workspace
        });
        let counts = &mut self.counts;
        let slot = match (matches.next(), matches.next()) {
            (None, _) => {
                counts.no_match += 1;
                return None;
            }
            (Some(_), Some(_)) => {
                counts.multi_match += 1;
                return None;
            }
            (Some(slot), None) => slot,
        };
        let refused = match slot.login {
            Ok(()) => {
                return Some(SessionAccountBinding {
                    account_identifier_hash: account.to_string(),
                    workspace_identifier_hash: Some(workspace.to_string()),
                });
            }
            Err(SlotLoginRefusal::ModeUnreadable) => &mut counts.mode_unreadable,
            Err(SlotLoginRefusal::NotForcedChatgpt) => &mut counts.not_forced_chatgpt,
            Err(SlotLoginRefusal::ApiKey) => &mut counts.api_key,
        };
        *refused += 1;
        None
    }
}

/// `item`'s own complete positive creator pair: (account, workspace).
pub(super) fn creator_pair(item: &SnapshotItem) -> Option<(&str, &str)> {
    let evidence = item.session_account_evidence.as_ref().filter(|evidence| {
        evidence.evidence_source == "codex_creator_header:v1"
            && !matches!(evidence.identity_disposition, Some("missing" | "conflict"))
    })?;
    Some((
        evidence.account_identifier_hash.as_deref()?,
        evidence.provider_workspace_hash.as_deref()?,
    ))
}
