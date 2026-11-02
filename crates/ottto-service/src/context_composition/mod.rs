//! Context composition for Claude Code and Codex transcripts.
//!
//! Production uses the kinds_version 2 incremental reader in `v2`: per-file
//! checkpoints retain parse state, per-scope aggregates feed changed-day
//! uploads, and daily runs retain their existing repair and audit budgets.
//! `measure` and the shared MCP decoder in `codex` provide measurement helpers;
//! `discovery` preserves transcript-copy identity and `harvest` owns the
//! scheduler entry point and shared opt-out and destination helpers.
//!
//! The kinds_version 1 Claude/Codex parsers and `report` accumulator compile
//! only in tests, as an independent oracle for V2 fixture comparisons. Their
//! methodology started as a Python port and has since diverged in copied
//! history and Codex per-block labels. The shared wire fixture
//! (`fixtures/context-composition/kinds-v2.json`) checks classification.
//! Numbers are estimates (chars/4 and a nominal per-image cost), not provider
//! tokenizer counts.
//!
//! Privacy: uploads contain aggregates, never message bodies. File names are
//! repository-relative or bare basenames; session ids are hashed. Workspace
//! identity uses the same scoping as `context_footprint`.

#[cfg(test)]
mod claude;
mod codex;
mod discovery;
mod harvest;
mod measure;
#[cfg(test)]
mod report;
mod v2;
pub(crate) use v2::recent_scopes;

pub use harvest::spawn_context_composition_sync;
pub use v2::run_context_composition_worker;

/// The kinds_version 1 name of a composition kind.
#[cfg(test)]
use crate::composition_kinds::Kind as Category;

// The golden tests read the whole collector through `use super::*`.
#[cfg(test)]
use {
    self::{claude::*, codex::*, measure::*, report::*},
    serde_json::Value,
    std::fs,
    std::path::PathBuf,
    time::Date,
};

// -------------------------------------------------------------------------
// Methodology knobs.
// -------------------------------------------------------------------------

/// Tokenizer proxy: ~4 chars per token. ESTIMATE ONLY.
const CHARS_PER_TOKEN: usize = 4;
/// Images bill by DIMENSIONS, never by base64 byte length. A single image block
/// is charged a nominal cost (real range ~1,100-1,600, capped near ~1,600).
const IMAGE_NOMINAL_TOKENS: u64 = 1300;

const COUNTER_SOURCE: &str = "context_composition_v1";
/// Aggregate rows bucket by the UTC calendar day. `time` in this crate has no
/// timezone database (formatting/parsing features only) and local-offset lookup
/// is unsound in a multithreaded daemon, so UTC is the deterministic,
/// explicit day boundary. The backend stores this so the boundary is never
/// guessed at read time.
const BUCKET_TIMEZONE: &str = "UTC";

const LOCAL_DISABLE_ENV: &str = "OTTTO_CONTEXT_COMPOSITION_HARVEST_DISABLED";

#[cfg(test)]
mod tests;

pub(crate) use v2::thread_cpu_micros;
