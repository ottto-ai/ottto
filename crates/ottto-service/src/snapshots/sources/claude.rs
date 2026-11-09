//! Claude Code: context posture, settings defaults, the usage census,
//! desktop session titles, subagent identity, agent metadata and the
//! usage-field readers of one transcript record.

pub(in crate::snapshots) mod account;
pub(in crate::snapshots) mod census;
pub(crate) mod context_file_birth;
pub(in crate::snapshots) mod context_posture;
pub(in crate::snapshots) mod desktop_titles;
pub(in crate::snapshots) mod line;
pub(crate) mod response_records;
pub(in crate::snapshots) mod settings_defaults;
pub(in crate::snapshots) mod subagent_identity;
#[cfg(test)]
pub(in crate::snapshots) mod tests;
