//! Claude status collection modules.
//! Called by the agent-status facade and sibling provider stages.
//! Declares the existing provider-specific collection boundaries.

pub(super) mod collect;
pub(super) mod desktop;
pub(super) mod login;
pub(super) mod oauth_cache;
pub(super) mod oauth_schedule;
pub(super) mod oauth_state;
pub(super) mod oauth_usage;
pub(super) mod selection;
pub(super) mod slot_state;
pub(super) mod slot_status;
pub(super) mod slots;
pub(super) mod statusline;
pub(super) mod upkeep;
