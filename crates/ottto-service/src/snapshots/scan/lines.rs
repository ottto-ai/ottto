//! Parsing JSONL transcript files and applying each parsed line to the scan
//! accumulator.
//!
//! `parser` owns the native JSONL file parser and its per-source parse
//! wrappers; `apply` holds the content callbacks (titles, first prompts,
//! workspaces, the Codex agent label) and the Codex session envelope;
//! `selectors` captures each line's selector fields and bounds the activity
//! and tool-usage counters.

pub(in crate::snapshots) mod apply;
pub(in crate::snapshots) mod parser;
pub(in crate::snapshots) mod selectors;
