//! Applying one parsed transcript line to the scan accumulator.
//!
//! `apply` holds the content callbacks (titles, first prompts, workspaces,
//! the Codex agent label) and the Codex session envelope.

pub(in crate::snapshots) mod apply;
