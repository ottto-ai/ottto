//! Codex status collection modules.
//! Called by the agent-status facade and sibling provider stages.
//! Declares the existing provider-specific collection boundaries.

pub(super) mod app_server;
pub(super) mod bindings;
pub(super) mod collect;
pub(super) mod login;
pub(super) mod quota;
