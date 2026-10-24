//! Context-composition harvest for Claude Code and Codex transcripts.
//!
//! This is a low-cadence, per-workspace collector that answers "what kinds of
//! content flowed INTO the agent's context window over a capture window" --
//! harness attachments, shell output, file reads, docs, memory notes,
//! browser/images, web fetch/search, agent results, and other tool output.
//!
//! Unlike `context_footprint` (a point-in-time `/context` snapshot of static
//! config), this surface is a per-day *composition* aggregate derived from a
//! deterministic scan of the local transcript files under the same roots the
//! session sink reads (`~/.claude/projects` plus registered Claude config
//! folders; `~/.codex/sessions`, `archived_sessions` and accepted Codex slot
//! homes).
//!
//! The kinds_version 1 methodology started as a port of an earlier Python
//! reference script, and the golden tests pin its hand-computed numbers. The
//! two have since diverged (this collector skips copied history and reads
//! Codex's per-block content labels; the script does neither), and the
//! kinds_version 2 classification in `composition_kinds` exists only here.
//! The shared wire fixture (`fixtures/context-composition/kinds-v2.json`), not
//! the script, is the cross-check. Every number is an ESTIMATE (chars/4
//! tokenizer proxy; nominal per-image cost); nothing here reproduces a
//! provider tokenizer.
//!
//! Privacy: aggregates only, never message bodies. Top-file names are made
//! repo-relative or reduced to a bare basename; session ids are hashed with
//! sha256. Identity fields (machine_id, workspace_hash, repository_hash,
//! labels) reuse the exact values `context_footprint` computes for the same
//! workspace so backend scoping joins line up.

//! Layout: `measure` (text and token measurement, residency, line dates),
//! `report` (the per-workspace accumulator), `claude` and `codex` (transcript
//! parsers), `payload` (the upload contract), `discovery` (workspaces and
//! their transcripts), `cache` (rescan and upload cache) and `harvest` (the
//! daily loop). Classification lives in `composition_kinds`.

mod cache;
mod claude;
mod codex;
mod discovery;
mod harvest;
mod measure;
mod payload;
mod report;
mod v2;

pub use harvest::spawn_context_composition_sync;
pub use v2::run_context_composition_worker;

/// The kinds_version 1 name of a composition kind.
use crate::composition_kinds::Kind as Category;
use std::time::Duration;

// The golden tests read the whole collector through `use super::*`.
#[cfg(test)]
use {
    self::{
        cache::*, claude::*, codex::*, discovery::*, harvest::*, measure::*, payload::*, report::*,
    },
    crate::composition_kinds::{
        classify_by_read_path, codex_mcp_category, codex_tool_category, is_memory_path,
    },
    crate::context_footprint::{sha256_hex, transcript_file_metadata},
    crate::snapshot_client::SnapshotApiClient,
    crate::snapshots::SnapshotSource,
    ottto_core::LocalDeviceBinding,
    serde_json::Value,
    std::collections::BTreeMap,
    std::fs,
    std::path::{Path, PathBuf},
    std::time::{Instant, SystemTime},
    time::{Date, OffsetDateTime},
};

// -------------------------------------------------------------------------
// Methodology knobs.
// -------------------------------------------------------------------------

/// Tokenizer proxy: ~4 chars per token. ESTIMATE ONLY.
const CHARS_PER_TOKEN: usize = 4;
/// Images bill by DIMENSIONS, never by base64 byte length. A single image block
/// is charged a nominal cost (real range ~1,100-1,600, capped near ~1,600).
const IMAGE_NOMINAL_TOKENS: u64 = 1300;

const COLLECTOR_VERSION: &str = "context-composition-0.1.0";
const COUNTER_SOURCE: &str = "context_composition_v1";
/// Local cache identity only. Bump when parsing/classification/ordering changes
/// without a methodology or collector-version change; never a wire field.
const COMPOSITION_PARSER_VERSION: &str = "context-composition-parser-v3";
/// Aggregate rows bucket by the UTC calendar day. `time` in this crate has no
/// timezone database (formatting/parsing features only) and local-offset lookup
/// is unsound in a multithreaded daemon, so UTC is the deterministic,
/// explicit day boundary. The backend stores this so the boundary is never
/// guessed at read time.
const BUCKET_TIMEZONE: &str = "UTC";

// -------------------------------------------------------------------------
// Cadence / bounds.
// -------------------------------------------------------------------------

/// Daily cadence. The slow harvest loop wakes once a day.
const CONTEXT_COMPOSITION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Per-cycle wall-clock budget so one slow disk never wedges the loop.
const CONTEXT_COMPOSITION_CYCLE_BUDGET: Duration = Duration::from_secs(5 * 60);
/// A single very large transcript is skipped to bound per-file work.
const MAX_TRANSCRIPT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_WORKSPACES_PER_CYCLE: usize = 12;
/// A live session appends to its transcript every few seconds, so one such
/// file would fence its whole workspace on every cycle. Files modified this
/// recently wait for a later cycle.
const SETTLE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Capture window (inclusive) must not exceed the backend cap (92 days).
const MAX_WINDOW_DAYS: i64 = 92;
const MAX_TOP_FILES: usize = 100;
const MAX_SESSIONS: usize = 200;
/// Re-upload at least this often even when nothing changed, so a stale row
/// eventually refreshes.
const CONTEXT_MAX_STALENESS_SECS: i64 = 7 * 24 * 60 * 60;

const LOCAL_DISABLE_ENV: &str = "OTTTO_CONTEXT_COMPOSITION_HARVEST_DISABLED";

#[cfg(test)]
mod tests;
