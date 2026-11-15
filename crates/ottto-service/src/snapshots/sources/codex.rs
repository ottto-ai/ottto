//! Codex: runtime config defaults, rollout and creator identity helpers, the
//! usage readers of one rollout line, the recovery capture settlement, the
//! rollout header checks and the sidecar title metadata rows.

pub(in crate::snapshots) mod config_defaults;
pub(in crate::snapshots) mod counting;
pub(crate) mod dictionary_slots;
pub(crate) mod eof_fragment;
pub(in crate::snapshots) mod identity;
pub(in crate::snapshots) mod line;
pub(crate) mod mcp_version;
pub(in crate::snapshots) mod recovery_capture;
pub(in crate::snapshots) mod rollout_header;
pub(crate) mod root_copies;
pub(in crate::snapshots) mod sidecar;
pub(crate) mod sqlite_read;
#[cfg(test)]
pub(in crate::snapshots) mod tests;
