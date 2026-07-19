use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use toml_edit::{DocumentMut, Item};

pub fn collector_version() -> String {
    ottto_core::compiled_release_version()
}

#[cfg(test)]
mod collector_version_tests {
    use super::*;

    #[test]
    fn collector_version_uses_packaged_release_version() {
        assert_eq!(collector_version(), ottto_core::compiled_release_version());
    }
}

pub const SNAPSHOT_SCHEMA_VERSION: u16 = 6;
// SnapshotStatusRequest endpoint stayed at v5; only the batch endpoint
// cut over to v6 in this change. Backend's AgentSessionSnapshotStatusRequest
// is still Literal[5] (backend/app/schemas/agent_session_snapshots.py).
pub const SNAPSHOT_STATUS_SCHEMA_VERSION: u16 = 5;
// Parser versions bumped together with the schema cutover so the on-disk scan
// index treats every previously-scanned file as fresh and re-emits at the v6
// shape; pending-backfill tracking re-runs the retroactive walk for the same
// reason.
// v16: the Codex state-only fallback now treats a session whose rollout was
// parsed in ANY prior scan run (tracked in the persisted scan index) as
// covered, instead of only sessions parsed in the current run. The version
// bump re-walks every rollout once so the backend supersedes the stale
// unattributed "Other" totals that the previous (run-scoped) check produced
// on every incremental scan.
// claude_code v8: every Claude Code usage row now carries a derived
// `context_bucket` (long/short) selector so turns that ran on the "(1M
// context)" window are attributed separately (see
// CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS). The per-row selector shape
// changed, so the bump re-walks every Claude session once to re-emit at v8.
// v17: Codex per-model usage now carries per-turn reasoning_effort
// claude_code v9: each Claude Code session origin now carries
// `used_workflow_orchestration` (true when the local
// `<session>/workflows/wf_*.json` footprint is present, i.e. the Workflow tool
// / dynamic multi-agent orchestration ran). The bump re-walks every Claude
// session once so already-scanned sessions re-emit with the new origin field.
// claude_code v10: Claude Code `type=ai-title` rows now feed
// `session_display_name_source=ai_title`, which the private API normalizes to
// `local_transcript_title`. The bump re-walks existing project JSONL files so
// sessions that previously only had first-prompt/fallback names can be
// superseded by Claude's generated title.
// claude_code v11: captured Claude Code work-attribution keys now ride inside
// selector_context so already-scanned sessions re-emit with subagent, skill,
// plugin, and MCP server selector rows. `attribution_mcp_tool` stays stripped
// because it is too high-cardinality for the first contract.
// claude_code v12: each Claude Code session now carries session-level latency
// aggregates (`avg_duration_ms` / `max_duration_ms`) derived from per-turn
// wall-clock durations — each assistant API response's first content-block
// timestamp minus the preceding `type=user` record (prompt or tool_result).
// Claude Code transcripts carry ms-precision RFC3339 timestamps on every record
// but no first-token marker, so TTFT stays absent (unlike Codex `task_complete`,
// which supplies both). The bump re-walks existing Claude sessions once so
// already-scanned sessions re-emit with the duration aggregates populated.
// claude_code v13: Task-tool subagent transcripts (`<sessionId>/subagents/
// agent-<agentId>.jsonl`) carry the parent's `sessionId` on every line, so they
// used to collapse onto the human parent session. They now re-key to a distinct
// `<parentSessionId>_<agentFileStem>` id (see `claude_subagent_source_session_id`)
// and stand up as their own `isSidechain=true` -> ai_agent sessions. The bump
// re-walks existing project JSONL once so already-scanned subagent files re-emit
// under the new id instead of remaining folded into their parent.
// claude_code v14: Claude Code session titles now also come from the Claude
// desktop app's per-session store (`~/Library/Application Support/Claude/
// claude-code-sessions/<accountCtx>/<workspace>/*.json`, `cliSessionId` ->
// `title`), emitted as `session_display_name_source=desktop_title`, plus a
// Codex-style first-user-prompt fallback (`first_prompt`) for pure-CLI
// sessions. Transcripts almost never carry `ai-title`/`summary` records, so
// most Claude sessions previously uploaded with no title at all. The store is
// folded into the scan fingerprint (see `ClaudeTitleMetadata`) so a title
// arriving after the transcript was scanned still re-emits, and the bump
// re-walks every Claude session once so existing sessions pick up titles.
// claude_code v15: local OTLP reasoning-effort enrichment no longer treats
// Claude's aggregate cache-creation count as a 5-minute TTL. The one-shot
// backfill re-enriches transcripts indexed by v0.1.77 from their existing
// content-free effort sidecars after upgrade.
// claude_code v16: derive per-session first-turn/peak context and compaction
// watermarks. The bump is required in addition to fingerprinting the new
// fields: the incremental scanner must revisit already-indexed transcripts
// before their new fingerprint can trigger a one-time backend re-upload and
// seed the machine-local posture cache.
// codex v19: extend those same context-posture watermarks to Codex rollouts
// (first-turn/peak context from `last_token_usage`, compactions from the
// `compacted` records). Same one-shot rationale as claude_code v16 — the
// incremental scanner must revisit already-indexed rollouts before their new
// fingerprint can trigger the one-time backend re-upload.
// v20/v17/v9: attach privacy-safe git repository identity locally. Raw paths
// and remotes never enter the snapshot payload.
// Direct attribution derivation is currently dark and non-persistent: facts
// are computed for changed sessions but skipped by serde and the snapshot
// fingerprint. Deliberately do NOT bump these versions yet, because reparsing
// all history would compute and immediately discard the same dark facts. The
// backend activation change must enable serialization/fingerprinting and bump
// all three versions atomically to perform the one-time historical backfill.
pub const CODEX_SNAPSHOT_PARSER_VERSION: &str = "codex_jsonl:v20";
pub const CLAUDE_CODE_SNAPSHOT_PARSER_VERSION: &str = "claude_code_jsonl:v17";
pub const PI_SNAPSHOT_PARSER_VERSION: &str = "pi_jsonl:v9";

/// Effective per-turn input context (uncached input + cache reads + cache
/// writes) above which a Claude turn could only have run with the "(1M
/// context)" window enabled — the regular Claude context cap is 200K tokens.
/// Turns strictly over this boundary tag `context_bucket=long`; everything at
/// or below tags `short`. 1M usage bills at standard per-token rates but drives
/// cost via token VOLUME, so the product analyzes it separately.
///
/// MUST stay in lockstep with the backend pricing catalog's
/// `context_bucket_threshold_tokens` for the 1M-capable Claude models and the
/// cost projector's `_derive_context_bucket`, which honors this daemon-supplied
/// bucket ahead of its own (request_count==1-gated) derivation. See
/// coding-agents-observability backend/app/services/telemetry_cost_projector.py
/// and backend/app/domain/pricing/selector_context.py.
pub const CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS: u64 = 200_000;
// Generous ceilings: scanning is incremental (per-file fingerprint) and
// streaming, so a larger history is a one-time backfill cost with bounded
// memory. The finite caps still guard a pathological ~/.codex.
pub const MAX_BACKFILL_FILES_PER_SOURCE: usize = 10_000;
const REPOSITORY_IDENTITY_CACHE_MAX_ENTRIES: usize = 512;
const REPOSITORY_IDENTITY_CACHE_TTL_SECONDS: u64 = 6 * 60 * 60;
pub const BACKFILL_WINDOW_DAYS: u64 = 730;
// Defensive size ceilings for the streaming JSONL read path. The scan caps the
// file COUNT and an mtime window, but the per-file/-line byte lengths were
// previously unbounded: a transcript whose monitored tool output embeds a huge
// blob (one multi-hundred-MB/GB physical line) would be materialized whole in
// RAM by the line reader (and cloned again by the artifact scraper), OOM-killing
// the per-user daemon. Codex is source-special: long active sessions can exceed
// the default file cap while still being safe to parse because its parser is
// line-bounded and streaming. Keep the stricter cap for sources with heavier
// artifact/session paths, and use the line cap as the real Codex OOM guard.
pub const MAX_JSONL_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CODEX_JSONL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_JSONL_LINE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    Codex,
    ClaudeCode,
    Pi,
}

impl SnapshotSource {
    pub fn api_slug(self) -> &'static str {
        match self {
            SnapshotSource::Codex => "codex",
            SnapshotSource::ClaudeCode => "claude_code",
            SnapshotSource::Pi => "pi",
        }
    }

    pub fn parser_version(self) -> &'static str {
        match self {
            SnapshotSource::Codex => CODEX_SNAPSHOT_PARSER_VERSION,
            SnapshotSource::ClaudeCode => CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
            SnapshotSource::Pi => PI_SNAPSHOT_PARSER_VERSION,
        }
    }

    /// Whether this source's parser derives context-posture watermarks (see the
    /// `SnapshotItem` posture field docs). Keeps the emit gate and the
    /// fingerprint gate from drifting apart: a source that fingerprints the
    /// posture keys but never fills them — or the reverse — would either churn
    /// every fingerprint for nothing or silently stop re-uploading real
    /// posture. Pi has no derivation, so it stays out of both.
    fn derives_context_posture(self) -> bool {
        match self {
            SnapshotSource::Codex | SnapshotSource::ClaudeCode => true,
            SnapshotSource::Pi => false,
        }
    }

    pub fn default_roots(self, home: &Path) -> Vec<PathBuf> {
        match self {
            SnapshotSource::Codex => vec![
                home.join(".codex").join("sessions"),
                home.join(".codex").join("archived_sessions"),
            ],
            SnapshotSource::ClaudeCode => vec![home.join(".claude").join("projects")],
            SnapshotSource::Pi => {
                if let Some(override_dir) = std::env::var_os("PI_CODING_AGENT_DIR") {
                    vec![PathBuf::from(override_dir).join("sessions")]
                } else {
                    vec![home.join(".pi").join("agent").join("sessions")]
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotBatchRequest {
    pub schema_version: u16,
    pub source: String,
    pub machine_id: String,
    pub collector_version: Option<String>,
    pub snapshots: Vec<SnapshotItem>,
}

// Hoisted onto each SnapshotModelUsage row in v6: these participate in the
// backend's billing_hash (one of the two row-key dimensions). Names match
// `_usage_row_key` in backend/app/schemas/agent_session_snapshots.py.
const ROW_BILLING_FIELDS: &[&str] = &[
    "auth_mode",
    "billing_channel",
    "billing_provider",
    "gateway_provider",
    "model_provider",
    "subscription_product",
];

/// Raw, *unclassified* session-origin signals read from the Codex `session_meta`
/// and the Claude Code JSONL header. Forwarded so the BACKEND derives the
/// initiator itself (single source of truth) -- mirrors the backend
/// `AgentSessionSnapshotOrigin`. Every field optional; a source fills what it exposes.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct SnapshotOrigin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_source: Option<String>, // Codex: user/subagent/automation (authoritative)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>, // Codex: cli/vscode/exec/mcp (string form)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_subagent: Option<bool>, // true when Codex `source` was the subagent object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub originator: Option<String>, // Codex: surface label (weak signal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>, // Claude: claude-desktop/cli/sdk-cli
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_sidechain: Option<bool>, // Claude: subagent (Task tool)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_kind: Option<String>, // Claude: "bg"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_workflow_orchestration: Option<bool>, // Claude: Workflow tool ran (local wf_*.json footprint)
    // Dark until the backend fact schema is deployed. This raw provider id is
    // used only to build the local parent-session fact.
    #[serde(skip)]
    pub parent_session_ref: Option<String>, // Provider-native parent session id when present
}

impl SnapshotOrigin {
    fn is_empty(&self) -> bool {
        self.thread_source.is_none()
            && self.source.is_none()
            && self.source_subagent.is_none()
            && self.originator.is_none()
            && self.agent_role.is_none()
            && self.entrypoint.is_none()
            && self.is_sidechain.is_none()
            && self.session_kind.is_none()
            && self.used_workflow_orchestration.is_none()
            && self.parent_session_ref.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotItem {
    pub source_session_id: String,
    pub snapshot_fingerprint: String,
    pub status: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub unattributed_total_tokens: u64,
    pub request_count: u64,
    // Session-level Codex latency (avg across the session's `task_complete`
    // turns). Codex emits duration/ttft only in the rollout `task_complete`
    // event (never over OTLP), so the daemon aggregates them here. Absent for
    // Claude Code / Pi (which surface per-turn latency via OTLP) and for Codex
    // sessions with no completed turns. Backend schema must accept these.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_time_to_first_token_ms: Option<u64>,
    // Slowest single turn of the session (max), the tail the average smooths
    // over. Same availability as the avg fields above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_to_first_token_ms: Option<u64>,
    // Per-session context posture, derived from each transcript's per-response
    // usage records. `peak_context_fill_tokens` is the largest effective input
    // context any counted response saw — the session's high-water context fill.
    // `first_turn_context_tokens` is the same measure for the session's FIRST
    // counted response: the first-turn baseline (system prompt + tools + memory
    // + first user input), not a claim of purely static context.
    // `compaction_count` counts compaction events, auto or manual.
    //
    // Claude Code and Codex both derive these, from different records and with
    // DIFFERENT input scopes (see `apply_claude_code_line` /
    // `apply_codex_line`): a Claude response reports uncached input, so its
    // effective context is input + cache reads + cache writes, whereas Codex
    // `input_tokens` already includes the cached prefix and IS the effective
    // context on its own. Both therefore land here as the same
    // window-comparable measure — the prompt volume the model actually saw —
    // which is what the backend divides by the model's context window.
    //
    // None for Pi (no posture derivation) and for Codex state-only snapshots
    // (no rollout parsed, so nothing was observed). `compaction_count` is
    // Some(0) wherever a transcript WAS parsed: Some(0) = "observed, none"
    // vs None = "daemon can't tell". Backend schema must accept these as
    // optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_context_fill_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_turn_context_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_count: Option<u64>,
    pub model_usage: Vec<SnapshotModelUsage>,
    pub usage_buckets: Vec<SnapshotUsageBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<SnapshotCost>,
    pub session_display_name: Option<String>,
    pub session_display_name_source: Option<String>,
    pub source_started_at: Option<String>,
    pub source_ended_at: Option<String>,
    pub source_last_activity_at: Option<String>,
    pub collected_at: String,
    pub workspace_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_display_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_kind: Option<String>,
    pub source_file_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub session_artifacts: Vec<SessionArtifact>,
    pub provenance: SnapshotProvenance,
    /// Raw session-origin signals; the backend re-derives the initiator from these.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<SnapshotOrigin>,
    /// Compact evidence-first facts. Phase 2 computes these locally; Phase 4
    /// enables wire serialization only after the backend fact contract exists.
    #[serde(skip)]
    pub attribution_facts: Vec<crate::session_attribution::SessionAttributionFact>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotUsageBucket {
    pub bucket_start: String,
    pub model_usage: Vec<SnapshotModelUsage>,
    pub first_activity_at: Option<String>,
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotModelUsage {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub unattributed_total_tokens: u64,
    pub request_count: u64,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_cost_usd: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotCost {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_cost_usd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_cost_usd: Option<String>,
    pub evidence_source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotProvenance {
    pub collector: String,
    pub source_file_count: u64,
    pub input_token_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_archived: Option<bool>,
}

/// A VCS artifact (PR / issue / commit) referenced in a session, scraped locally
/// from transcript tool output. Scope is any PR/issue/MR URL or `git commit`
/// summary that appears in tool output (not only artifacts the session authored
/// — e.g. a `gh pr view` of someone else's PR also counts). Opt-in (stripped
/// before upload unless the backend activity hint enabled it); values are
/// canonical and content-free by construction (clean authority, no credentials/
/// query/percent-encoding, path truncated at the numeric id) so the backend
/// accepts them unchanged.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionArtifact {
    pub kind: String,
    pub value: String,
}

/// Maximum VCS artifacts retained per session (runaway-transcript guard).
const MAX_SESSION_ARTIFACTS: usize = 50;

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanIndex {
    pub files: BTreeMap<String, ScanIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    pub source_file_fingerprint: String,
    pub last_snapshot_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceScanResult {
    pub source: SnapshotSource,
    pub backfill_window_days: u64,
    pub backfill_file_limit: usize,
    pub discovered_file_count: usize,
    pub skipped_file_count_due_to_limit: usize,
    pub scan_cap_hit: bool,
    pub scanned_file_count: usize,
    pub scanned_session_count: usize,
    pub snapshots: Vec<SnapshotItem>,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotUploadPolicy {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
    pub session_artifacts_enabled: bool,
}

impl Default for SnapshotUploadPolicy {
    fn default() -> Self {
        Self {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
            // Opt-in: artifacts are stripped before upload unless the backend
            // activity hint explicitly enables them for the org.
            session_artifacts_enabled: false,
        }
    }
}

pub fn apply_upload_policy(
    source: SnapshotSource,
    snapshots: &mut [SnapshotItem],
    policy: SnapshotUploadPolicy,
) {
    for item in snapshots {
        let mut fingerprint_needs_refresh = false;
        if !policy.session_titles_enabled
            && (item.session_display_name.is_some() || item.session_display_name_source.is_some())
        {
            item.session_display_name = None;
            item.session_display_name_source = None;
            fingerprint_needs_refresh = true;
        }
        if !policy.workspace_labels_enabled
            && (item.workspace_display_label.is_some()
                || item.workspace_label_source.is_some()
                || item.repository_label.is_some()
                || item.repository_label_source.is_some())
        {
            item.workspace_display_label = None;
            item.workspace_label_source = None;
            item.repository_label = None;
            item.repository_label_source = None;
            fingerprint_needs_refresh = true;
        }
        if !policy.session_artifacts_enabled && !item.session_artifacts.is_empty() {
            item.session_artifacts.clear();
            fingerprint_needs_refresh = true;
        }
        if fingerprint_needs_refresh {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
}

/// Split Claude transcript bucket rows by exact locally-reduced OTLP effort.
///
/// The transcript remains authoritative for total tokens. Evidence is applied
/// only when one transcript row unambiguously owns the model/hour and every
/// observed component fits inside it. Any uncovered remainder stays as an
/// effort-unknown row, preserving byte-exact totals under partial collection.
pub fn apply_claude_effort_evidence(
    snapshots: &mut [SnapshotItem],
    evidence_by_session: &BTreeMap<String, Vec<crate::claude_effort::ClaudeEffortEvidence>>,
) {
    for item in snapshots {
        let Some(evidence) = evidence_by_session.get(&item.source_session_id) else {
            continue;
        };
        let mut grouped: BTreeMap<(String, String, String), UsageTotals> = BTreeMap::new();
        for observed in evidence {
            let Some((bucket_start, _)) = activity_bucket_from_timestamp(&observed.observed_at)
            else {
                continue;
            };
            let totals = UsageTotals {
                input_tokens: observed.input_tokens,
                output_tokens: observed.output_tokens,
                cache_read_tokens: observed.cache_read_tokens,
                cache_creation_5m_tokens: observed.cache_creation_5m_tokens,
                cache_creation_1h_tokens: observed.cache_creation_1h_tokens,
                reasoning_output_tokens: observed.reasoning_output_tokens,
                unattributed_total_tokens: 0,
                request_count: observed.request_count,
                costs: UsageCosts::default(),
            };
            grouped
                .entry((
                    bucket_start,
                    normalized_evidence_model(&observed.model),
                    observed.effort.clone(),
                ))
                .or_default()
                .add(&totals);
        }

        let mut changed = false;
        for bucket in &mut item.usage_buckets {
            let mut model_indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (index, row) in bucket.model_usage.iter().enumerate() {
                model_indices
                    .entry(normalized_evidence_model(&row.model))
                    .or_default()
                    .push(index);
            }
            let mut replacements: BTreeMap<usize, Vec<SnapshotModelUsage>> = BTreeMap::new();
            for (model, indices) in model_indices {
                if indices.len() != 1 {
                    continue;
                }
                let index = indices[0];
                let base = &bucket.model_usage[index];
                if model_usage_has_cost(base) {
                    continue;
                }
                let mut effort_rows: Vec<(String, UsageTotals)> = grouped
                    .iter()
                    .filter(|((observed_bucket, observed_model, _effort), _totals)| {
                        observed_bucket == &bucket.bucket_start && observed_model == &model
                    })
                    .map(|((_observed_bucket, _observed_model, effort), totals)| {
                        (effort.clone(), totals.clone())
                    })
                    .collect();
                if effort_rows.is_empty() {
                    continue;
                }
                let base_totals = usage_totals_from_model_usage(base);
                let Some(observed_totals) =
                    reconcile_effort_cache_creation(&mut effort_rows, &base_totals)
                else {
                    continue;
                };

                let mut split = Vec::new();
                for (effort, totals) in effort_rows {
                    if !usage_totals_has_usage(&totals) {
                        continue;
                    }
                    split.push(model_usage_with_totals(base, &totals, Some(effort)));
                }
                let residual = base_totals.delta_from(&observed_totals);
                if usage_totals_has_usage(&residual) {
                    split.push(model_usage_with_totals(base, &residual, None));
                }
                if !split.is_empty() {
                    replacements.insert(index, split);
                }
            }
            if replacements.is_empty() {
                continue;
            }
            let mut rows = Vec::new();
            for (index, row) in bucket.model_usage.drain(..).enumerate() {
                if let Some(split) = replacements.remove(&index) {
                    rows.extend(split);
                } else {
                    rows.push(row);
                }
            }
            rows.sort_by_key(row_key_from_model_usage);
            bucket.model_usage = rows;
            changed = true;
        }
        if changed {
            rebuild_snapshot_model_usage(item);
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        }
    }
}

fn normalized_evidence_model(model: &str) -> String {
    model.trim().to_ascii_lowercase()
}

fn model_usage_has_cost(row: &SnapshotModelUsage) -> bool {
    row.cost_usd.is_some()
        || row.input_cost_usd.is_some()
        || row.output_cost_usd.is_some()
        || row.cache_read_cost_usd.is_some()
        || row.cache_creation_cost_usd.is_some()
}

fn usage_totals_fit(observed: &UsageTotals, base: &UsageTotals) -> bool {
    base.is_monotonic_after(observed)
}

fn sum_effort_totals(rows: &[(String, UsageTotals)]) -> UsageTotals {
    let mut total = UsageTotals::default();
    for (_, row) in rows {
        total.add(row);
    }
    total
}

/// Reconcile legacy cache evidence against the transcript's authoritative TTLs.
///
/// Stable v0.1.77 placed Claude's unscoped aggregate cache-creation count in
/// the 5m field. New evidence stores that aggregate separately and never enters
/// these totals. For old rows, retain each TTL component when its aggregate
/// independently fits the transcript and discard only a conflicting component;
/// this preserves genuinely scoped evidence without inventing a billing TTL.
fn reconcile_effort_cache_creation(
    rows: &mut [(String, UsageTotals)],
    base: &UsageTotals,
) -> Option<UsageTotals> {
    let observed = sum_effort_totals(rows);
    if usage_totals_fit(&observed, base) {
        return Some(observed);
    }

    let mut non_cache = observed.clone();
    non_cache.cache_creation_5m_tokens = 0;
    non_cache.cache_creation_1h_tokens = 0;
    if !usage_totals_fit(&non_cache, base) {
        return None;
    }
    if observed.cache_creation_5m_tokens > base.cache_creation_5m_tokens {
        for (_, totals) in rows.iter_mut() {
            totals.cache_creation_5m_tokens = 0;
        }
    }
    if observed.cache_creation_1h_tokens > base.cache_creation_1h_tokens {
        for (_, totals) in rows.iter_mut() {
            totals.cache_creation_1h_tokens = 0;
        }
    }
    let reconciled = sum_effort_totals(rows);
    usage_totals_fit(&reconciled, base).then_some(reconciled)
}

fn model_usage_with_totals(
    base: &SnapshotModelUsage,
    totals: &UsageTotals,
    effort: Option<String>,
) -> SnapshotModelUsage {
    let mut row = base.clone();
    row.input_tokens = totals.input_tokens;
    row.output_tokens = totals.output_tokens;
    row.cache_read_tokens = totals.cache_read_tokens;
    row.cache_creation_5m_tokens = totals.cache_creation_5m_tokens;
    row.cache_creation_1h_tokens = totals.cache_creation_1h_tokens;
    row.reasoning_output_tokens = totals.reasoning_output_tokens;
    row.unattributed_total_tokens = totals.unattributed_total_tokens;
    row.request_count = totals.request_count;
    row.reasoning_effort = effort;
    row.cost_usd = None;
    row.input_cost_usd = None;
    row.output_cost_usd = None;
    row.cache_read_cost_usd = None;
    row.cache_creation_cost_usd = None;
    row
}

fn rebuild_snapshot_model_usage(item: &mut SnapshotItem) {
    let mut session_rows: BTreeMap<RowKey, BucketRowAccumulator> = BTreeMap::new();
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            merge_session_row(
                &mut session_rows,
                key,
                BucketRowAccumulator {
                    selector_context: row.selector_context.clone(),
                    selector_sources: row.selector_sources.clone(),
                    usage: usage_totals_from_model_usage(row),
                    reasoning_effort: row.reasoning_effort.clone(),
                },
            );
        }
    }
    item.model_usage = session_rows
        .iter()
        .map(|(key, row)| model_usage_from_row(key, row))
        .collect();
}

fn snapshot_fingerprint(source: SnapshotSource, item: &SnapshotItem) -> String {
    let mut fingerprint_payload = json!({
        "source": source.api_slug(),
        "source_session_id": &item.source_session_id,
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "cache_read_tokens": item.cache_read_tokens,
        "cache_creation_5m_tokens": item.cache_creation_5m_tokens,
        "cache_creation_1h_tokens": item.cache_creation_1h_tokens,
        "reasoning_output_tokens": item.reasoning_output_tokens,
        "unattributed_total_tokens": item.unattributed_total_tokens,
        "request_count": item.request_count,
        "model_usage": &item.model_usage,
        "usage_buckets": &item.usage_buckets,
        "title": &item.session_display_name,
        "title_source": &item.session_display_name_source,
        "workspace_display_label": &item.workspace_display_label,
        "workspace_label_source": &item.workspace_label_source,
        "repository_hash": &item.repository_hash,
        "repository_label": &item.repository_label,
        "repository_label_source": &item.repository_label_source,
        "repository_identity_source": &item.repository_identity_source,
        "workspace_kind": &item.workspace_kind,
        "session_artifacts": &item.session_artifacts,
        // Including origin makes a one-time re-upload happen when the collector
        // starts forwarding it, so the backend can re-derive the initiator for
        // already-uploaded sessions (otherwise the fingerprint is unchanged and
        // the snapshot is never re-sent).
        "origin": &item.origin,
    });
    // Same one-time re-upload rationale as `origin`, scoped to the sources that
    // actually derive posture. Including a source here is what makes its
    // already-uploaded sessions re-send once with the new fields; Pi derives
    // nothing, so adding null posture keys there would churn every Pi
    // fingerprint for an unrelated re-upload burst that carries no new data.
    if source.derives_context_posture() {
        let payload = fingerprint_payload
            .as_object_mut()
            .expect("snapshot fingerprint payload is an object");
        payload.insert(
            "peak_context_fill_tokens".to_string(),
            json!(item.peak_context_fill_tokens),
        );
        payload.insert(
            "first_turn_context_tokens".to_string(),
            json!(item.first_turn_context_tokens),
        );
        payload.insert("compaction_count".to_string(), json!(item.compaction_count));
    }
    sha256_hex(&[&fingerprint_payload.to_string()])
}

#[derive(Debug, Clone, Default)]
struct UsageTotals {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_5m_tokens: u64,
    cache_creation_1h_tokens: u64,
    reasoning_output_tokens: u64,
    unattributed_total_tokens: u64,
    request_count: u64,
    costs: UsageCosts,
}

const USD_PICO_SCALE: u128 = 1_000_000_000_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UsageCosts {
    observed: bool,
    reported: bool,
    total: Option<u128>,
    input: Option<u128>,
    output: Option<u128>,
    cache_read: Option<u128>,
    cache_creation: Option<u128>,
}

impl UsageCosts {
    fn add(&mut self, other: &Self) {
        if !other.observed {
            return;
        }
        if !self.observed {
            *self = other.clone();
            return;
        }
        self.reported &= other.reported;
        if !self.reported {
            self.total = None;
            self.input = None;
            self.output = None;
            self.cache_read = None;
            self.cache_creation = None;
            return;
        }
        self.total = add_complete_cost(self.total, other.total);
        self.input = add_complete_cost(self.input, other.input);
        self.output = add_complete_cost(self.output, other.output);
        self.cache_read = add_complete_cost(self.cache_read, other.cache_read);
        self.cache_creation = add_complete_cost(self.cache_creation, other.cache_creation);
    }

    fn is_monotonic_after(&self, previous: &Self) -> bool {
        (!previous.observed || self.observed)
            && (!previous.reported || self.reported)
            && cost_is_monotonic(self.total, previous.total)
            && cost_is_monotonic(self.input, previous.input)
            && cost_is_monotonic(self.output, previous.output)
            && cost_is_monotonic(self.cache_read, previous.cache_read)
            && cost_is_monotonic(self.cache_creation, previous.cache_creation)
    }

    fn delta_from(&self, previous: &Self) -> Self {
        Self {
            observed: self.observed,
            reported: self.reported,
            total: cost_delta(self.total, previous.total),
            input: cost_delta(self.input, previous.input),
            output: cost_delta(self.output, previous.output),
            cache_read: cost_delta(self.cache_read, previous.cache_read),
            cache_creation: cost_delta(self.cache_creation, previous.cache_creation),
        }
    }

    fn snapshot_cost(&self) -> Option<SnapshotCost> {
        self.reported.then(|| SnapshotCost {
            total_cost_usd: self.total.map(usd_picos_string),
            input_cost_usd: self.input.map(usd_picos_string),
            output_cost_usd: self.output.map(usd_picos_string),
            cache_read_cost_usd: self.cache_read.map(usd_picos_string),
            cache_creation_cost_usd: self.cache_creation.map(usd_picos_string),
            evidence_source: "pi_usage_cost".to_string(),
        })
    }
}

fn add_complete_cost(left: Option<u128>, right: Option<u128>) -> Option<u128> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left + right),
        _ => None,
    }
}

fn cost_is_monotonic(current: Option<u128>, previous: Option<u128>) -> bool {
    match (current, previous) {
        (Some(current), Some(previous)) => current >= previous,
        (Some(_), None) | (None, None) => true,
        (None, Some(_)) => false,
    }
}

fn cost_delta(current: Option<u128>, previous: Option<u128>) -> Option<u128> {
    current.map(|current| current - previous.unwrap_or_default())
}

impl UsageTotals {
    fn is_zero(&self) -> bool {
        self.total_tokens() == 0 && self.reasoning_output_tokens == 0
    }

    fn total_tokens(&self) -> u64 {
        self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_creation_5m_tokens
            + self.cache_creation_1h_tokens
            + self.unattributed_total_tokens
    }

    /// Effective input context for one turn: the prompt size the model actually
    /// saw — uncached input + cache reads + cache writes (5m + 1h TTL). Output
    /// and reasoning tokens are excluded. Mirrors the backend cost projector's
    /// `context_length` (input + cache_read + cache_creation). Drives the
    /// `context_bucket` selector: a value above the 200K regular-context cap
    /// could only have come from the 1M-context window.
    fn effective_input_context(&self) -> u64 {
        self.input_tokens
            + self.cache_read_tokens
            + self.cache_creation_5m_tokens
            + self.cache_creation_1h_tokens
    }

    fn add(&mut self, other: &UsageTotals) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_read_tokens += other.cache_read_tokens;
        self.cache_creation_5m_tokens += other.cache_creation_5m_tokens;
        self.cache_creation_1h_tokens += other.cache_creation_1h_tokens;
        self.reasoning_output_tokens += other.reasoning_output_tokens;
        self.unattributed_total_tokens += other.unattributed_total_tokens;
        self.request_count += other.request_count;
        self.costs.add(&other.costs);
    }

    fn is_monotonic_after(&self, previous: &UsageTotals) -> bool {
        self.input_tokens >= previous.input_tokens
            && self.output_tokens >= previous.output_tokens
            && self.cache_read_tokens >= previous.cache_read_tokens
            && self.cache_creation_5m_tokens >= previous.cache_creation_5m_tokens
            && self.cache_creation_1h_tokens >= previous.cache_creation_1h_tokens
            && self.reasoning_output_tokens >= previous.reasoning_output_tokens
            && self.unattributed_total_tokens >= previous.unattributed_total_tokens
            && self.request_count >= previous.request_count
            && self.costs.is_monotonic_after(&previous.costs)
    }

    fn delta_from(&self, previous: &UsageTotals) -> UsageTotals {
        UsageTotals {
            input_tokens: self.input_tokens - previous.input_tokens,
            output_tokens: self.output_tokens - previous.output_tokens,
            cache_read_tokens: self.cache_read_tokens - previous.cache_read_tokens,
            cache_creation_5m_tokens: self.cache_creation_5m_tokens
                - previous.cache_creation_5m_tokens,
            cache_creation_1h_tokens: self.cache_creation_1h_tokens
                - previous.cache_creation_1h_tokens,
            reasoning_output_tokens: self.reasoning_output_tokens
                - previous.reasoning_output_tokens,
            unattributed_total_tokens: self.unattributed_total_tokens
                - previous.unattributed_total_tokens,
            request_count: self.request_count - previous.request_count,
            costs: self.costs.delta_from(&previous.costs),
        }
    }
}

pub fn validate_snapshot_batch_request(request: &SnapshotBatchRequest) -> Result<(), String> {
    if request.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "schema_version {} does not match daemon SNAPSHOT_SCHEMA_VERSION {}",
            request.schema_version, SNAPSHOT_SCHEMA_VERSION
        ));
    }
    if request.snapshots.is_empty() {
        return Err("snapshots must not be empty".to_string());
    }
    for (index, item) in request.snapshots.iter().enumerate() {
        validate_snapshot_item(index, item)?;
    }
    Ok(())
}

fn validate_snapshot_item(index: usize, item: &SnapshotItem) -> Result<(), String> {
    let expected = usage_totals_from_item(item);
    let expected_has_usage = usage_totals_has_usage(&expected);
    if expected_has_usage && item.usage_buckets.is_empty() {
        return Err(format!(
            "snapshot[{index}] has usage totals but no usage_buckets"
        ));
    }

    let mut top_rows: BTreeMap<RowKey, UsageTotals> = BTreeMap::new();
    for row in &item.model_usage {
        let row_key = row_key_from_model_usage(row);
        if top_rows
            .insert(row_key, usage_totals_from_model_usage(row))
            .is_some()
        {
            return Err(format!(
                "snapshot[{index}] has duplicate top-level model_usage rows"
            ));
        }
    }

    let mut bucket_totals = UsageTotals::default();
    let mut bucket_rows: BTreeMap<RowKey, UsageTotals> = BTreeMap::new();
    for (bucket_index, bucket) in item.usage_buckets.iter().enumerate() {
        if bucket.model_usage.is_empty() {
            return Err(format!(
                "snapshot[{index}].usage_buckets[{bucket_index}] has no model_usage rows"
            ));
        }
        let mut seen_bucket_rows = BTreeSet::new();
        for row in &bucket.model_usage {
            let row_key = row_key_from_model_usage(row);
            if !seen_bucket_rows.insert(row_key.clone()) {
                return Err(format!(
                    "snapshot[{index}].usage_buckets[{bucket_index}] has duplicate model_usage rows"
                ));
            }
            let totals = usage_totals_from_model_usage(row);
            bucket_totals.add(&totals);
            bucket_rows.entry(row_key).or_default().add(&totals);
        }
    }

    if !usage_totals_equal(&bucket_totals, &expected) {
        return Err(format!(
            "snapshot[{index}] usage_buckets totals do not match snapshot totals"
        ));
    }

    if !bucket_rows.is_empty() {
        if top_rows.keys().collect::<Vec<_>>() != bucket_rows.keys().collect::<Vec<_>>() {
            return Err(format!(
                "snapshot[{index}] usage_buckets model rows do not match top-level model_usage rows"
            ));
        }
        for (row_key, top_totals) in &top_rows {
            let bucket_row = bucket_rows.get(row_key).expect("checked key set");
            if !usage_totals_equal(bucket_row, top_totals) {
                return Err(format!(
                    "snapshot[{index}] usage_buckets model row totals do not match top-level model_usage"
                ));
            }
        }
    }

    Ok(())
}

fn usage_totals_from_item(item: &SnapshotItem) -> UsageTotals {
    UsageTotals {
        input_tokens: item.input_tokens,
        output_tokens: item.output_tokens,
        cache_read_tokens: item.cache_read_tokens,
        cache_creation_5m_tokens: item.cache_creation_5m_tokens,
        cache_creation_1h_tokens: item.cache_creation_1h_tokens,
        reasoning_output_tokens: item.reasoning_output_tokens,
        unattributed_total_tokens: item.unattributed_total_tokens,
        request_count: item.request_count,
        costs: UsageCosts::default(),
    }
}

fn usage_totals_from_model_usage(row: &SnapshotModelUsage) -> UsageTotals {
    UsageTotals {
        input_tokens: row.input_tokens,
        output_tokens: row.output_tokens,
        cache_read_tokens: row.cache_read_tokens,
        cache_creation_5m_tokens: row.cache_creation_5m_tokens,
        cache_creation_1h_tokens: row.cache_creation_1h_tokens,
        reasoning_output_tokens: row.reasoning_output_tokens,
        unattributed_total_tokens: row.unattributed_total_tokens,
        request_count: row.request_count,
        costs: UsageCosts::default(),
    }
}

fn usage_totals_has_usage(totals: &UsageTotals) -> bool {
    !totals.is_zero() || totals.request_count > 0
}

fn usage_totals_equal(left: &UsageTotals, right: &UsageTotals) -> bool {
    left.input_tokens == right.input_tokens
        && left.output_tokens == right.output_tokens
        && left.cache_read_tokens == right.cache_read_tokens
        && left.cache_creation_5m_tokens == right.cache_creation_5m_tokens
        && left.cache_creation_1h_tokens == right.cache_creation_1h_tokens
        && left.reasoning_output_tokens == right.reasoning_output_tokens
        && left.unattributed_total_tokens == right.unattributed_total_tokens
        && left.request_count == right.request_count
}

fn row_key_from_model_usage(row: &SnapshotModelUsage) -> RowKey {
    let selector_hash = if row.selector_context.is_empty() {
        "base".to_string()
    } else {
        let payload =
            serde_json::to_string(&row.selector_context).unwrap_or_else(|_| "{}".to_string());
        sha256_hex(&[payload.as_str()])[..16].to_string()
    };
    RowKey {
        model: row.model.clone(),
        selector_hash,
        reasoning_effort: row.reasoning_effort.clone(),
        auth_mode: row.auth_mode.clone(),
        billing_channel: row.billing_channel.clone(),
        billing_provider: row.billing_provider.clone(),
        gateway_provider: row.gateway_provider.clone(),
        model_provider: row.model_provider.clone(),
        subscription_product: row.subscription_product.clone(),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SelectorCapture {
    context: BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
}

impl SelectorCapture {
    fn is_empty(&self) -> bool {
        self.context.is_empty()
    }

    fn insert(&mut self, field: &str, value: String, source: &str) {
        self.context.insert(field.to_string(), value);
        self.sources.insert(field.to_string(), source.to_string());
    }

    fn merge(&mut self, other: SelectorCapture) {
        for (field, value) in other.context {
            self.context.insert(field, value);
        }
        for (field, source) in other.sources {
            self.sources.insert(field, source);
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CodexTitleMetadata {
    titles: BTreeMap<String, CodexTitleCandidate>,
    state_threads: BTreeMap<String, CodexStateThread>,
    sidecar_fingerprint: String,
    default_selector: SelectorCapture,
}

#[derive(Debug, Clone)]
struct CodexTitleCandidate {
    title: String,
    source: String,
}

#[derive(Debug, Clone, Default)]
struct CodexStateThread {
    title: Option<String>,
    tokens_used: u64,
    archived: bool,
    created_at: Option<String>,
    updated_at: Option<String>,
    model: Option<String>,
}

/// Claude Code sidecar title metadata read from the Claude desktop app's
/// per-session store — the Claude analogue of `CodexTitleMetadata`.
///
/// The desktop app persists one JSON file per session under
/// `~/Library/Application Support/Claude/claude-code-sessions/<accountCtx>/
/// <workspace>/*.json` whose `cliSessionId` field equals the transcript file
/// stem under `~/.claude/projects/**` and whose `title` field is the
/// human-readable session title shown in the app (LLM-generated
/// `titleSource=auto` or user-renamed `titleSource=user`). Transcripts almost
/// never carry `ai-title`/`summary` records, so this store is the only local
/// source of the real title for most Claude Code sessions — including
/// CLI-launched sessions later opened in the app.
///
/// Privacy: only `cliSessionId`, `title`, and `titleSource` are read; the rest
/// of the file (MCP tool catalogs, permission state) is never retained. Title
/// upload stays governed by the org/user `session_titles_enabled` policy via
/// `apply_upload_policy`, exactly like Codex titles.
///
/// `sidecar_fingerprint` is derived from the extracted title CONTENT (not file
/// stats): the store files are rewritten on every session activity, so a stat
/// fingerprint would churn every cycle and force full re-parses; the content
/// fingerprint changes only when a title actually appears or changes, which is
/// exactly when unchanged transcripts must re-emit.
#[derive(Debug, Clone, Default)]
struct ClaudeTitleMetadata {
    titles: BTreeMap<String, ClaudeTitleCandidate>,
    sidecar_fingerprint: String,
}

#[derive(Debug, Clone)]
struct ClaudeTitleCandidate {
    title: String,
    /// True when the desktop `titleSource` is `user` (an explicit rename). A
    /// user-set title overrides transcript-derived titles; an auto title only
    /// fills absences.
    user_set: bool,
}

// The desktop store holds one ~80KB JSON per session; both caps are far above
// anything observed and exist only to bound a pathological store.
const MAX_CLAUDE_DESKTOP_SESSION_FILES: usize = 5_000;
const MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CLAUDE_DESKTOP_STORE_DEPTH: usize = 3;

impl ClaudeTitleMetadata {
    fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut store_dirs = BTreeSet::new();
        for root in roots {
            // root is `<home>/.claude/projects`; the desktop store lives under
            // `<home>/Library/Application Support/Claude/claude-code-sessions`.
            let Some(home) = root.parent().and_then(Path::parent) else {
                continue;
            };
            store_dirs.insert(
                home.join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude-code-sessions"),
            );
        }
        Self::load_from_store_dirs(&store_dirs)
    }

    fn load_from_store_dirs(store_dirs: &BTreeSet<PathBuf>) -> Self {
        let mut metadata = Self::default();
        let mut session_files = Vec::new();
        for dir in store_dirs {
            collect_claude_desktop_session_files(dir, 0, &mut session_files);
        }
        session_files.sort();
        session_files.truncate(MAX_CLAUDE_DESKTOP_SESSION_FILES);
        for path in &session_files {
            load_claude_desktop_session_title(path, &mut metadata.titles);
        }
        let sidecar_parts: Vec<String> = metadata
            .titles
            .iter()
            .map(|(id, candidate)| format!("{id}:{}:{}", candidate.user_set, candidate.title))
            .collect();
        metadata.sidecar_fingerprint = sha256_hex_owned(&sidecar_parts);
        metadata
    }
}

fn collect_claude_desktop_session_files(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > MAX_CLAUDE_DESKTOP_STORE_DEPTH {
        return;
    }
    // Best-effort: a missing/unreadable store (non-macOS, app not installed)
    // yields no titles and is never load-bearing for collection.
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(entry_metadata) = entry.metadata() else {
            continue;
        };
        if entry_metadata.is_dir() {
            collect_claude_desktop_session_files(&path, depth + 1, files);
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if entry_metadata.len() > MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES {
            continue;
        }
        files.push(path);
    }
}

fn load_claude_desktop_session_title(
    path: &Path,
    titles: &mut BTreeMap<String, ClaudeTitleCandidate>,
) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    // Non-session JSONs in the store (e.g. scheduled-tasks.json) lack these
    // fields and fall out here.
    let Some(cli_session_id) = string_at(&value, &["cliSessionId"]) else {
        return;
    };
    let Some(title) = string_at(&value, &["title"]) else {
        return;
    };
    let user_set = string_at(&value, &["titleSource"]).as_deref() == Some("user");
    // The same cliSessionId can appear in several store files (session reopened
    // in another workspace); a user-set title wins over an auto one.
    match titles.get(cli_session_id.as_str()) {
        Some(existing) if existing.user_set && !user_set => {}
        _ => {
            titles.insert(cli_session_id, ClaudeTitleCandidate { title, user_set });
        }
    }
}

/// Per-turn fast-mode signal lifted from Codex's undocumented `logs_2.sqlite`
/// debug DB.
///
/// Codex fast mode is "request-is-cost": a turn whose `response.create`
/// websocket request asked for `service_tier="priority"` is billed at the
/// priority (fast) rate regardless of what the server served — and that request
/// tier is the ONLY reliable fast-mode signal. The rollout jsonl carries no
/// service_tier, and the served tier on `response.completed` is always
/// `"default"`. So we read the requested tier out of `logs_2.sqlite`.
///
/// Keyed by `turn_id` (a globally-unique UUIDv7 from the request's `turn.id`
/// tracing span), which matches `turn_context.payload.turn_id` in the rollout
/// jsonl. Because turn ids are globally unique, one map joins per turn across
/// every session without any session scoping. Only priority (fast) turns are
/// retained; an absent turn is standard, so the set stays tiny.
#[derive(Debug, Clone, Default)]
struct CodexTurnTraceMap {
    priority_turns: BTreeSet<String>,
}

impl CodexTurnTraceMap {
    fn is_priority_turn(&self, turn_id: &str) -> bool {
        self.priority_turns.contains(turn_id)
    }
}

/// Local opt-out for the experimental Codex fast-mode trace read. Defaults on;
/// set `OTTTO_CODEX_FAST_MODE_TRACE=off` (also accepts `0`/`false`/`no`/
/// `disabled`) to skip the `logs_2.sqlite` read entirely, after which every
/// Codex turn classifies as standard. The master local-usage switch
/// (`local_usage_reconciliation_enabled`) already gates all collection; this is
/// a finer opt-out specific to reading the undocumented debug DB.
fn codex_fast_mode_trace_enabled() -> bool {
    codex_fast_mode_trace_enabled_from(std::env::var("OTTTO_CODEX_FAST_MODE_TRACE").ok().as_deref())
}

fn codex_fast_mode_trace_enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no" | "disabled"
        ),
        None => true,
    }
}

/// Finer opt-out (mirrors `codex_fast_mode_trace_enabled`) for the per-session
/// Claude Code `workflows/` directory stat that detects dynamic workflow
/// orchestration. `OTTTO_CLAUDE_WORKFLOW_DETECT=off` (or 0/false/no/disabled)
/// skips the filesystem probe entirely, after which every Claude session
/// reports no workflow-orchestration signal.
fn claude_workflow_detect_enabled() -> bool {
    claude_workflow_detect_enabled_from(
        std::env::var("OTTTO_CLAUDE_WORKFLOW_DETECT")
            .ok()
            .as_deref(),
    )
}

fn claude_workflow_detect_enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no" | "disabled"
        ),
        None => true,
    }
}

/// Local opt-IN for capturing Claude Code per-turn work-attribution
/// (`attributionAgent`/`Skill`/`Plugin`/`McpServer`/`McpTool`) off each
/// assistant+usage line into the per-turn `SelectorCapture`. Subagent
/// attribution (`attributionAgent`) is the priority dimension.
///
/// Defaults OFF: only `OTTTO_CLAUDE_ATTRIBUTION_CAPTURE` set to one of
/// `on`/`1`/`true`/`yes`/`enabled` turns capture on. Approved attribution keys
/// on `SELECTOR_CONTEXT_ALLOWED` reach `reduced_context`/`selector_hash` and
/// cross the wire; `attribution_mcp_tool` intentionally stays off the allowlist
/// for this first contract because of cardinality risk.
fn claude_attribution_capture_enabled() -> bool {
    claude_attribution_capture_enabled_from(
        std::env::var("OTTTO_CLAUDE_ATTRIBUTION_CAPTURE")
            .ok()
            .as_deref(),
    )
}

fn claude_attribution_capture_enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "on" | "1" | "true" | "yes" | "enabled"
        ),
        None => false,
    }
}

/// True when `dir` (a Claude Code session's `workflows/` sibling directory)
/// contains at least one `wf_*.json` orchestration manifest. The Workflow tool
/// writes one manifest per run; manifest filenames are truncated
/// (e.g. `wf_60f3dab6-4fa.json`), so match on the `wf_`/`.json` affixes rather
/// than an exact name. Best-effort: a missing directory or any read error
/// yields `false` and never disrupts collection.
fn claude_workflows_dir_has_manifest(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("wf_") && name.ends_with(".json"))
    })
}

// v6 row identity. Mirrors the backend's `_usage_row_key`
// (model, selector_hash, billing_hash) tuple so daemon-side aggregation
// dedupes the same rows the backend would have deduped on receipt. Without
// this, two rows that differ only in plan_window_bucket would distinct on
// the daemon, then collide on the backend (which strips plan_window_bucket
// during normalization) and trip "duplicate model selector rows".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey {
    model: String,
    selector_hash: String,
    reasoning_effort: Option<String>,
    auth_mode: Option<String>,
    billing_channel: Option<String>,
    billing_provider: Option<String>,
    gateway_provider: Option<String>,
    model_provider: Option<String>,
    subscription_product: Option<String>,
}

#[derive(Debug, Clone)]
struct BucketRowAccumulator {
    selector_context: BTreeMap<String, String>,
    selector_sources: BTreeMap<String, String>,
    usage: UsageTotals,
    // Per-turn reasoning effort tier (Codex transcript or Claude local OTLP).
    // Also present in RowKey so mixed-effort buckets never collapse.
    reasoning_effort: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct UsageBucketState {
    rows: BTreeMap<RowKey, BucketRowAccumulator>,
    first_activity_at: Option<String>,
    last_activity_at: Option<String>,
}

impl UsageBucketState {
    fn note_activity_at(&mut self, timestamp: &str) {
        match self.first_activity_at.as_ref() {
            Some(current) if timestamp < current.as_str() => {
                self.first_activity_at = Some(timestamp.to_string())
            }
            None => self.first_activity_at = Some(timestamp.to_string()),
            _ => {}
        }
        match self.last_activity_at.as_ref() {
            Some(current) if timestamp > current.as_str() => {
                self.last_activity_at = Some(timestamp.to_string())
            }
            None => self.last_activity_at = Some(timestamp.to_string()),
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
struct SnapshotAccumulator {
    source: SnapshotSource,
    source_session_id: Option<String>,
    title: Option<String>,
    title_source: Option<String>,
    first_prompt_title: Option<String>,
    // In-memory only: bounded first-user text used to derive opaque template,
    // schedule, and explicit slash-skill facts. Never copied into SnapshotItem.
    first_prompt_material: Option<String>,
    // In-memory only: provider-native skill names. HMACed before facts are
    // produced and never serialized in plaintext.
    provider_skills: BTreeSet<String>,
    started_at: Option<String>,
    ended_at: Option<String>,
    last_activity_at: Option<String>,
    workspace_hash: Option<String>,
    // In-memory only: used to derive privacy-safe repository identity. The raw
    // path is never copied into SnapshotItem or uploaded.
    workspace_path: Option<PathBuf>,
    latest_model: Option<String>,
    // Most-recently-observed Codex per-turn reasoning effort tier. Updated as
    // lines stream past so the next usage row picks up the effort co-located
    // with that turn's token_count.
    latest_reasoning_effort: Option<String>,
    // Most-recently-observed Codex turn id (from `turn_context.payload.turn_id`).
    // The token_count event carries no turn id, so the running turn id is what
    // joins each usage row to its `logs_2` fast-mode signal.
    latest_turn_id: Option<String>,
    // Per-turn fast-mode signal read once per scan from `logs_2.sqlite`. Shared
    // read-only across every session file in the cycle via `Arc`.
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    current_selector: SelectorCapture,
    session_cumulative_usage: Option<UsageTotals>,
    usage_buckets: BTreeMap<String, UsageBucketState>,
    origin: SnapshotOrigin,
    artifacts: Vec<SessionArtifact>,
    /// Whether VCS artifact scraping runs for this session. Defaults to ``true``
    /// (see ``new``); the production scan path sets it from the org upload
    /// policy so the expensive scrape is skipped entirely when the
    /// ``local_usage_session_artifacts_enabled`` setting is off — the common
    /// case. ``apply_upload_policy`` still strips artifacts before upload as
    /// defense-in-depth, so a stray scrape can never leak.
    artifacts_enabled: bool,
    // Codex per-session latency accumulators, summed from rollout
    // `task_complete` events (`duration_ms` + `time_to_first_token_ms`) and
    // averaged in `into_items`. Zero counts mean no latency was observed.
    latency_duration_ms_sum: u64,
    latency_duration_ms_count: u64,
    latency_ttft_ms_sum: u64,
    latency_ttft_ms_count: u64,
    // Max (slowest single turn) alongside the avg — the tail the average hides.
    latency_duration_ms_max: u64,
    latency_ttft_ms_max: u64,
    // Claude Code writes one JSONL record per assistant CONTENT BLOCK, and
    // every record of the same API response repeats the same `message.id` +
    // `requestId` with byte-identical `message.usage`. Counting each record
    // overstates tokens and request_count ~3-6x. This set remembers which
    // API responses already contributed usage so each response counts once.
    // The accumulator is rebuilt per full-file scan (`parse_jsonl_file`), so
    // the set's lifetime matches one scan of one session file exactly.
    seen_claude_usage_keys: BTreeSet<String>,
    // Timestamp of the most recent Claude Code `type=user` record (a real user
    // prompt OR a tool_result — both are "model input available" moments). Each
    // assistant API response's first content-block record subtracts this to
    // derive that turn's wall-clock duration, feeding the shared
    // `latency_duration_ms_*` accumulators. Claude Code stamps every record with
    // an ms-precision RFC3339 timestamp but no first-token marker, so only whole
    // turn duration is derivable this way, never TTFT.
    claude_last_user_ts: Option<String>,
    // Context posture (see the SnapshotItem field docs). Running max /
    // first-seen watermarks over each counted API response's effective input
    // context, plus a count of compaction records. The Claude Code and Codex
    // line parsers each feed these from their own records — the per-source
    // input-scope difference is resolved before it reaches here, so both write
    // the same window-comparable measure. Pi leaves them at their zero values
    // and emits None.
    peak_context_fill_tokens: u64,
    first_turn_context_tokens: Option<u64>,
    compaction_count: u64,
}

impl SnapshotAccumulator {
    fn new(source: SnapshotSource) -> Self {
        Self {
            source,
            source_session_id: None,
            title: None,
            title_source: None,
            first_prompt_title: None,
            first_prompt_material: None,
            provider_skills: BTreeSet::new(),
            started_at: None,
            ended_at: None,
            last_activity_at: None,
            workspace_hash: None,
            workspace_path: None,
            latest_model: None,
            latest_reasoning_effort: None,
            latest_turn_id: None,
            codex_turn_traces: None,
            current_selector: SelectorCapture::default(),
            session_cumulative_usage: None,
            usage_buckets: BTreeMap::new(),
            origin: SnapshotOrigin::default(),
            artifacts: Vec::new(),
            // Default on so direct parse-function callers (mostly tests) keep
            // extracting; the production scan path overrides this from policy.
            artifacts_enabled: true,
            latency_duration_ms_sum: 0,
            latency_duration_ms_count: 0,
            latency_ttft_ms_sum: 0,
            latency_ttft_ms_count: 0,
            latency_duration_ms_max: 0,
            latency_ttft_ms_max: 0,
            seen_claude_usage_keys: BTreeSet::new(),
            claude_last_user_ts: None,
            peak_context_fill_tokens: 0,
            first_turn_context_tokens: None,
            compaction_count: 0,
        }
    }

    /// Merge newly scraped artifacts, deduping and capping at
    /// ``MAX_SESSION_ARTIFACTS``. Encounter order is preserved; ``into_items``
    /// sorts for a deterministic fingerprint.
    fn add_artifacts(&mut self, artifacts: Vec<SessionArtifact>) {
        for artifact in artifacts {
            if self.artifacts.len() >= MAX_SESSION_ARTIFACTS {
                break;
            }
            if !self.artifacts.iter().any(|existing| existing == &artifact) {
                self.artifacts.push(artifact);
            }
        }
    }

    fn with_default_selector(source: SnapshotSource, selector: SelectorCapture) -> Self {
        let mut accumulator = Self::new(source);
        // Default selector (e.g. Codex config defaults) feeds the running
        // display context for usage rows. Row keys are derived per-line
        // from the merged selector at usage time.
        accumulator.current_selector = selector;
        accumulator
    }

    fn note_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| timestamp < *current)
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| timestamp > *current)
        {
            self.last_activity_at = Some(timestamp);
        }
    }

    /// Fold one Claude Code turn's wall-clock duration into the session latency
    /// accumulators: the gap from the most recent `type=user` record (real
    /// prompt or tool_result) to this API response's first content-block record.
    /// Called once per API response (gated by the same usage dedup as token
    /// counting), so each turn contributes exactly one duration sample — the
    /// Claude Code analogue of the Codex `task_complete` latency path. Only whole
    /// turn duration is derivable from Claude transcripts (no first-token
    /// marker), so this never touches the TTFT accumulators. Records with no
    /// preceding user timestamp, unparseable timestamps, or a negative delta
    /// (out-of-order/clock skew) contribute nothing.
    fn note_claude_turn_duration(&mut self, assistant_ts: Option<&str>) {
        let (Some(user_ts), Some(assistant_ts)) =
            (self.claude_last_user_ts.as_deref(), assistant_ts)
        else {
            return;
        };
        let (Ok(user), Ok(assistant)) = (
            OffsetDateTime::parse(user_ts, &Rfc3339),
            OffsetDateTime::parse(assistant_ts, &Rfc3339),
        ) else {
            return;
        };
        let millis = (assistant - user).whole_milliseconds();
        if millis < 0 {
            return;
        }
        let duration_ms = millis as u64;
        self.latency_duration_ms_sum = self.latency_duration_ms_sum.saturating_add(duration_ms);
        self.latency_duration_ms_count += 1;
        self.latency_duration_ms_max = self.latency_duration_ms_max.max(duration_ms);
    }

    fn fallback_bucket_timestamp(&self, collected_at: Option<&str>) -> Option<String> {
        self.last_activity_at
            .clone()
            .or_else(|| self.started_at.clone())
            .or_else(|| collected_at.map(|value| value.to_string()))
    }

    fn set_title(&mut self, title: Option<String>, source: &str) {
        let Some(title) = title.and_then(|value| normalize_display_title(value, source)) else {
            return;
        };
        self.title = Some(title);
        self.title_source = Some(source.to_string());
    }

    fn set_title_if_absent(&mut self, title: Option<String>, source: &str) {
        if self.title.is_some() {
            return;
        }
        self.set_title(title, source);
    }

    fn set_first_prompt_title(&mut self, value: Option<String>) {
        let Some(value) = value else {
            return;
        };
        if self.first_prompt_material.is_none() {
            self.first_prompt_material = Some(value.clone());
        }
        if self.first_prompt_title.is_none() {
            self.first_prompt_title = first_prompt_display_title(value);
        }
    }

    fn note_provider_skill(&mut self, value: Option<String>) {
        let Some(value) = value else {
            return;
        };
        let normalized = value.trim().to_ascii_lowercase();
        if !normalized.is_empty() && normalized.len() <= 128 {
            self.provider_skills.insert(normalized);
        }
    }

    fn apply_codex_title_metadata(&mut self, path: &Path, metadata: &CodexTitleMetadata) {
        if self.title.is_some() {
            return;
        }
        let session_id = self
            .source_session_id
            .clone()
            .or_else(|| codex_session_id_from_path(path));
        let Some(session_id) = session_id else {
            return;
        };
        if let Some(title) = metadata.titles.get(session_id.as_str()) {
            self.set_title_if_absent(Some(title.title.clone()), title.source.as_str());
        }
    }

    fn apply_claude_title_metadata(&mut self, path: &Path, metadata: &ClaudeTitleMetadata) {
        let session_id = self.source_session_id.clone().or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(|value| value.to_string())
        });
        let Some(session_id) = session_id else {
            return;
        };
        // A Task-tool subagent transcript carries its PARENT's sessionId on
        // every line (re-keyed later in into_items); never hand a subagent
        // session its parent's desktop title.
        if claude_subagent_source_session_id(path, &session_id).is_some() {
            return;
        }
        let Some(candidate) = metadata.titles.get(session_id.as_str()) else {
            return;
        };
        if candidate.user_set {
            // An explicit user rename in the desktop app beats any
            // transcript-derived title.
            self.set_title(Some(candidate.title.clone()), "desktop_title");
        } else {
            self.set_title_if_absent(Some(candidate.title.clone()), "desktop_title");
        }
    }

    fn apply_first_prompt_fallback(&mut self) {
        if self.title.is_some() {
            return;
        }
        self.set_title_if_absent(self.first_prompt_title.clone(), "first_prompt");
    }

    fn set_workspace_hash(&mut self, value: Option<String>) {
        if self.workspace_hash.is_none() {
            if let Some(raw) = value {
                self.workspace_hash = Some(sha256_hex(&[raw.as_str()]));
                self.workspace_path = Some(PathBuf::from(raw));
            }
        }
    }

    fn set_model(&mut self, model: Option<String>) {
        if let Some(model) = model.and_then(normalize_title) {
            self.latest_model = Some(model);
        }
    }

    fn set_selector(&mut self, selector: SelectorCapture) {
        if selector.is_empty() {
            return;
        }
        // Running display context for usage rows. Row keys are derived
        // per-line from the merged selector inside add_usage_with_selector.
        self.current_selector.merge(selector);
    }

    /// True when the running turn (`latest_turn_id`) paid for Codex fast mode,
    /// per the `logs_2` request tier. Used to stamp `service_tier=priority` onto
    /// that turn's usage row only — never onto `current_selector`, so the signal
    /// does not bleed into later standard turns of the same session.
    fn current_turn_is_priority(&self) -> bool {
        let (Some(traces), Some(turn_id)) = (
            self.codex_turn_traces.as_ref(),
            self.latest_turn_id.as_ref(),
        ) else {
            return false;
        };
        traces.is_priority_turn(turn_id)
    }

    fn add_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        effort: Option<String>,
    ) {
        if usage.is_zero() {
            return;
        }
        let model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(model.clone());

        // Resolve the hour to bucket into. Lines lacking a timestamp fall back
        // to last-known activity; without that the usage is dropped to avoid
        // synthesizing a misleading bucket.
        let bucket_input = timestamp
            .map(|value| value.to_string())
            .or_else(|| self.fallback_bucket_timestamp(None));
        let Some(bucket_input) = bucket_input else {
            return;
        };
        let Some((bucket_start, normalized_timestamp)) =
            activity_bucket_from_timestamp(&bucket_input)
        else {
            return;
        };

        let mut merged = self.current_selector.clone();
        merged.merge(selector);
        let (row_key, reduced_context, reduced_sources) =
            build_row_identity(&model, &merged, effort.as_deref());

        let bucket = self.usage_buckets.entry(bucket_start).or_default();
        bucket.note_activity_at(&normalized_timestamp);
        match bucket.rows.get_mut(&row_key) {
            Some(row) => {
                for (field, source) in reduced_sources {
                    row.selector_sources.insert(field, source);
                }
                row.usage.add(&usage);
                debug_assert_eq!(row.reasoning_effort, effort);
            }
            None => {
                bucket.rows.insert(
                    row_key,
                    BucketRowAccumulator {
                        selector_context: reduced_context,
                        selector_sources: reduced_sources,
                        usage,
                        reasoning_effort: effort,
                    },
                );
            }
        }
    }

    fn set_cumulative_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        // Override the delta's request_count when the upstream cumulative did
        // not include an explicit request_count. The cumulative-derived delta
        // would otherwise be 0 (since the cumulative request_count was
        // synthetically defaulted to 1 by the parser), losing the per-event
        // request count. v5 implemented this via a separate note_activity
        // call; v6 folds it in here so the row totals reconcile.
        implicit_request_count: Option<u64>,
        // Per-turn reasoning effort tier (Codex), attached to the same usage row.
        effort: Option<String>,
    ) -> Option<UsageTotals> {
        if usage.is_zero() {
            return None;
        }
        let resolved_model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(resolved_model.clone());
        // Codex (the only caller today) emits SESSION-wide cumulative totals.
        // Detect rollover at the session level — a mid-session selector change
        // (e.g. plan_window_bucket rollover) must not be treated as a restart.
        let mut delta = match self.session_cumulative_usage.as_ref() {
            Some(previous) if usage.is_monotonic_after(previous) => usage.delta_from(previous),
            Some(_) => {
                // Non-monotonic: treat as a session restart. Clear all
                // buckets because the cumulative was invalidated.
                self.usage_buckets.clear();
                usage.clone()
            }
            None => usage.clone(),
        };
        self.session_cumulative_usage = Some(usage.clone());
        if let Some(count) = implicit_request_count {
            delta.request_count = count;
        }
        if delta.is_zero() {
            return None;
        }
        self.add_usage_with_selector(
            Some(resolved_model),
            delta.clone(),
            selector,
            timestamp,
            effort,
        );
        Some(delta)
    }

    fn into_items(
        mut self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Vec<SnapshotItem> {
        let Some(source_session_id) = self
            .source_session_id
            .clone()
            .or_else(|| {
                (self.source == SnapshotSource::Codex)
                    .then(|| codex_session_id_from_path(path))
                    .flatten()
            })
            .or_else(|| {
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_string())
            })
        else {
            return Vec::new();
        };
        // A Claude Code Task-tool subagent transcript shares its parent's
        // `sessionId`; re-key it to a distinct id so it ingests as its own
        // `isSidechain=true` (ai_agent) session instead of collapsing into the
        // human parent. Top-level transcripts are unchanged.
        let source_session_id = if self.source == SnapshotSource::ClaudeCode {
            claude_subagent_source_session_id(path, &source_session_id).unwrap_or(source_session_id)
        } else {
            source_session_id
        };
        // Claude Code dynamic workflow orchestration (the Workflow tool, e.g.
        // `ultracode`) leaves a local manifest at
        // `<projectDir>/<sessionId>/workflows/wf_*.json` -- a sibling directory
        // of the `<sessionId>.jsonl` we just parsed. Stat it so the backend can
        // surface a per-session "workflow orchestration ran" signal. Best-effort
        // only: absence/errors -> false, never load-bearing for collection.
        if self.source == SnapshotSource::ClaudeCode && claude_workflow_detect_enabled() {
            let workflows_dir = path.with_extension("").join("workflows");
            self.origin.used_workflow_orchestration =
                Some(claude_workflows_dir_has_manifest(&workflows_dir));
        }
        let repository_identity = self
            .workspace_path
            .as_deref()
            .map(cached_repository_identity);
        let mut attribution_facts = crate::session_attribution::direct_provider_facts(
            self.source,
            Some(&self.origin),
            &source_session_id,
            collected_at,
            self.source.parser_version(),
        );
        if let Some(context) = attribution_context {
            attribution_facts.extend(
                context.grouping_facts(
                    crate::session_attribution::SessionAttributionGroupingInput {
                        source: self.source,
                        origin: Some(&self.origin),
                        source_session_id: &source_session_id,
                        observed_at: collected_at,
                        source_version: self.source.parser_version(),
                        first_prompt: self.first_prompt_material.as_deref(),
                        provider_skills: &self.provider_skills,
                        repository_hash: repository_identity
                            .as_ref()
                            .and_then(|identity| identity.repository_hash.as_deref()),
                        source_started_at: self.started_at.as_deref(),
                        transcript_path: path,
                    },
                ),
            );
            crate::session_attribution::enforce_fact_limits(&mut attribution_facts);
        }
        let collector = match self.source {
            SnapshotSource::Codex => "codex_jsonl".to_string(),
            SnapshotSource::ClaudeCode => "claude_code_jsonl".to_string(),
            SnapshotSource::Pi => "pi_jsonl".to_string(),
        };
        let input_token_scope = match self.source {
            SnapshotSource::Codex => Some("inclusive_cached".to_string()),
            SnapshotSource::ClaudeCode => Some("uncached".to_string()),
            SnapshotSource::Pi => Some("uncached".to_string()),
        };
        // Per-row session-wide aggregation (sum across all buckets keyed by
        // RowKey). Drives the top-level model_usage list and the snapshot
        // totals so the backend validator sees the two reconcile exactly.
        let mut session_rows: BTreeMap<RowKey, BucketRowAccumulator> = BTreeMap::new();
        let mut usage_buckets: Vec<SnapshotUsageBucket> = Vec::new();
        for (bucket_start, bucket) in self.usage_buckets {
            if bucket.rows.is_empty() {
                continue;
            }
            let mut bucket_rows: Vec<SnapshotModelUsage> = Vec::new();
            for (row_key, row) in bucket.rows {
                bucket_rows.push(model_usage_from_row(&row_key, &row));
                merge_session_row(&mut session_rows, row_key, row);
            }
            // Rows in BTreeMap are already RowKey-ordered; emit them so each
            // bucket has at least one model_usage row (backend min_length=1).
            usage_buckets.push(SnapshotUsageBucket {
                bucket_start,
                model_usage: bucket_rows,
                first_activity_at: bucket.first_activity_at,
                last_activity_at: bucket.last_activity_at,
            });
        }
        if session_rows.is_empty() {
            return Vec::new();
        }
        let model_usage: Vec<SnapshotModelUsage> = session_rows
            .iter()
            .map(|(row_key, row)| model_usage_from_row(row_key, row))
            .collect();
        let mut totals = UsageTotals::default();
        for row in session_rows.values() {
            totals.add(&row.usage);
        }
        let mut item = SnapshotItem {
            source_session_id: source_session_id.clone(),
            snapshot_fingerprint: String::new(),
            status: "final".to_string(),
            input_tokens: totals.input_tokens,
            output_tokens: totals.output_tokens,
            cache_read_tokens: totals.cache_read_tokens,
            cache_creation_5m_tokens: totals.cache_creation_5m_tokens,
            cache_creation_1h_tokens: totals.cache_creation_1h_tokens,
            reasoning_output_tokens: totals.reasoning_output_tokens,
            unattributed_total_tokens: totals.unattributed_total_tokens,
            request_count: totals.request_count,
            avg_duration_ms: (self.latency_duration_ms_count > 0)
                .then(|| self.latency_duration_ms_sum / self.latency_duration_ms_count),
            avg_time_to_first_token_ms: (self.latency_ttft_ms_count > 0)
                .then(|| self.latency_ttft_ms_sum / self.latency_ttft_ms_count),
            max_duration_ms: (self.latency_duration_ms_count > 0)
                .then_some(self.latency_duration_ms_max),
            max_time_to_first_token_ms: (self.latency_ttft_ms_count > 0)
                .then_some(self.latency_ttft_ms_max),
            // Posture-deriving sources only (Claude Code, Codex); Pi emits
            // None. A parsed session with no counted context leaves peak/first
            // at None, while compaction_count is always reported for a parsed
            // transcript (Some(0) = "observed, none" vs None = "daemon can't
            // tell") — both sources log compactions explicitly, so a zero here
            // is a real observation rather than a gap.
            peak_context_fill_tokens: (self.source.derives_context_posture()
                && self.peak_context_fill_tokens > 0)
                .then_some(self.peak_context_fill_tokens),
            first_turn_context_tokens: if self.source.derives_context_posture() {
                self.first_turn_context_tokens
            } else {
                None
            },
            compaction_count: self
                .source
                .derives_context_posture()
                .then_some(self.compaction_count),
            model_usage,
            usage_buckets,
            cost: totals.costs.snapshot_cost(),
            session_display_name: self.title.clone(),
            session_display_name_source: self.title_source.clone(),
            source_started_at: self.started_at.clone(),
            source_ended_at: self.ended_at.clone(),
            source_last_activity_at: self.last_activity_at.clone(),
            collected_at: collected_at.to_string(),
            workspace_hash: self.workspace_hash.clone(),
            workspace_display_label: None,
            workspace_label_source: None,
            repository_hash: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_hash.clone()),
            repository_label: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_label.clone()),
            repository_label_source: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_label_source.clone()),
            repository_identity_source: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_identity_source.clone()),
            workspace_kind: repository_identity
                .as_ref()
                .and_then(|identity| identity.workspace_kind.clone()),
            source_file_fingerprint: Some(source_file_fingerprint.clone()),
            session_artifacts: {
                let mut artifacts = self.artifacts.clone();
                artifacts.sort();
                artifacts
            },
            provenance: SnapshotProvenance {
                collector: collector.clone(),
                source_file_count: 1,
                input_token_scope: input_token_scope.clone(),
                state_total_tokens: None,
                state_archived: None,
            },
            origin: (!self.origin.is_empty()).then(|| self.origin.clone()),
            attribution_facts,
        };
        item.snapshot_fingerprint = snapshot_fingerprint(self.source, &item);
        vec![item]
    }
}

fn cached_repository_identity(workspace: &Path) -> crate::context_footprint::RepositoryIdentity {
    type Cache = BTreeMap<PathBuf, (SystemTime, crate::context_footprint::RepositoryIdentity)>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let now = SystemTime::now();
    if let Ok(guard) = cache.lock() {
        if let Some((captured_at, identity)) = guard.get(workspace) {
            if now
                .duration_since(*captured_at)
                .map(|age| age.as_secs() <= REPOSITORY_IDENTITY_CACHE_TTL_SECONDS)
                .unwrap_or(false)
            {
                return identity.clone();
            }
        }
    }

    let identity = crate::context_footprint::resolve_repository_identity(workspace, true);
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= REPOSITORY_IDENTITY_CACHE_MAX_ENTRIES {
            guard.clear();
        }
        guard.insert(workspace.to_path_buf(), (now, identity.clone()));
    }
    identity
}

fn merge_session_row(
    session_rows: &mut BTreeMap<RowKey, BucketRowAccumulator>,
    row_key: RowKey,
    row: BucketRowAccumulator,
) {
    match session_rows.get_mut(&row_key) {
        Some(existing) => {
            for (field, source) in row.selector_sources {
                existing.selector_sources.insert(field, source);
            }
            existing.usage.add(&row.usage);
            debug_assert_eq!(existing.reasoning_effort, row.reasoning_effort);
        }
        None => {
            session_rows.insert(row_key, row);
        }
    }
}

fn model_usage_from_row(row_key: &RowKey, row: &BucketRowAccumulator) -> SnapshotModelUsage {
    SnapshotModelUsage {
        model: row_key.model.clone(),
        input_tokens: row.usage.input_tokens,
        output_tokens: row.usage.output_tokens,
        cache_read_tokens: row.usage.cache_read_tokens,
        cache_creation_5m_tokens: row.usage.cache_creation_5m_tokens,
        cache_creation_1h_tokens: row.usage.cache_creation_1h_tokens,
        reasoning_output_tokens: row.usage.reasoning_output_tokens,
        reasoning_effort: row.reasoning_effort.clone(),
        unattributed_total_tokens: row.usage.unattributed_total_tokens,
        request_count: row.usage.request_count,
        selector_context: row.selector_context.clone(),
        selector_sources: row.selector_sources.clone(),
        auth_mode: row_key.auth_mode.clone(),
        billing_channel: row_key.billing_channel.clone(),
        billing_provider: row_key.billing_provider.clone(),
        gateway_provider: row_key.gateway_provider.clone(),
        model_provider: row_key.model_provider.clone(),
        subscription_product: row_key.subscription_product.clone(),
        cost_usd: row.usage.costs.total.map(usd_picos_string),
        input_cost_usd: row.usage.costs.input.map(usd_picos_string),
        output_cost_usd: row.usage.costs.output.map(usd_picos_string),
        cache_read_cost_usd: row.usage.costs.cache_read.map(usd_picos_string),
        cache_creation_cost_usd: row.usage.costs.cache_creation.map(usd_picos_string),
    }
}

// Hoist the six billing fields out of selector_context into a RowKey, and
// drop any non-allowlist keys (plan_window_bucket, agent_quota_*, etc.) that
// the backend's normalize_selector_context would strip anyway. The remaining
// reduced selector_context drives the row's selector_hash dimension.
fn build_row_identity(
    model: &str,
    merged: &SelectorCapture,
    reasoning_effort: Option<&str>,
) -> (RowKey, BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut hoisted: BTreeMap<&'static str, Option<String>> = BTreeMap::new();
    let mut reduced_context = BTreeMap::new();
    let mut reduced_sources = BTreeMap::new();
    for field in ROW_BILLING_FIELDS {
        hoisted.insert(
            *field,
            merged
                .context
                .get(*field)
                .filter(|value| !value.is_empty())
                .cloned(),
        );
    }
    for (key, value) in &merged.context {
        if ROW_BILLING_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if !SELECTOR_CONTEXT_ALLOWED.contains(&key.as_str()) {
            continue;
        }
        reduced_context.insert(key.clone(), value.clone());
    }
    for (key, value) in &merged.sources {
        if ROW_BILLING_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if !SELECTOR_CONTEXT_ALLOWED.contains(&key.as_str()) {
            continue;
        }
        reduced_sources.insert(key.clone(), value.clone());
    }
    let selector_hash = if reduced_context.is_empty() {
        "base".to_string()
    } else {
        let payload = serde_json::to_string(&reduced_context).unwrap_or_else(|_| "{}".to_string());
        sha256_hex(&[payload.as_str()])[..16].to_string()
    };
    let row_key = RowKey {
        model: model.to_string(),
        selector_hash,
        reasoning_effort: reasoning_effort.map(str::to_string),
        auth_mode: hoisted.get("auth_mode").cloned().unwrap_or(None),
        billing_channel: hoisted.get("billing_channel").cloned().unwrap_or(None),
        billing_provider: hoisted.get("billing_provider").cloned().unwrap_or(None),
        gateway_provider: hoisted.get("gateway_provider").cloned().unwrap_or(None),
        model_provider: hoisted.get("model_provider").cloned().unwrap_or(None),
        subscription_product: hoisted.get("subscription_product").cloned().unwrap_or(None),
    };
    (row_key, reduced_context, reduced_sources)
}

// Mirror of backend SELECTOR_FIELDS (selector_context.py). Daemon-side
// reduction matches the backend's normalize_selector_context so two rows
// that differ only in a key the backend would strip aren't emitted as
// distinct rows here (which would trip "duplicate model selector rows" on
// the backend bucket validator).
const SELECTOR_CONTEXT_ALLOWED: &[&str] = &[
    "service_tier",
    "speed_mode",
    "batch_mode",
    "cache_ttl",
    "region_mode",
    "platform",
    "context_bucket",
    "mode",
    "billing_channel",
    "auth_mode",
    "gateway_provider",
    "subscription_product",
    "attribution_subagent",
    "attribution_skill",
    "attribution_plugin",
    "attribution_mcp_server",
];

pub fn scan_source_roots(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
) -> Result<SourceScanResult> {
    // Convenience entry used by tests and non-policy-aware callers: artifacts
    // are scraped unconditionally. Production sync uses
    // `scan_source_roots_with_artifacts` to honor the org upload policy.
    scan_source_roots_with_artifacts(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        true,
    )
}

/// Production scan entry: `artifacts_enabled` is the org's session-artifacts
/// upload policy. When false, the per-line VCS artifact scrape is skipped for
/// Claude Code transcripts (the expensive path) rather than scraped and then
/// discarded by `apply_upload_policy`.
pub fn scan_source_roots_with_artifacts(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    artifacts_enabled: bool,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        artifacts_enabled,
    )
}

/// Dark-mode attribution-aware scan. It reuses the normal changed-file path;
/// the context only adds in-memory HMAC facts to sessions already selected for
/// parsing and never changes the filesystem polling cadence.
pub fn scan_source_roots_with_attribution(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        artifacts_enabled,
        attribution_context,
    )
}

// Inner form with an injectable file cap so the cap-policy test can exercise
// truncation without materializing `MAX_BACKFILL_FILES_PER_SOURCE` files.
fn scan_source_roots_with_limit(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
    artifacts_enabled: bool,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        file_limit,
        artifacts_enabled,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_source_roots_with_limit_and_attribution(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<SourceScanResult> {
    let backfill_window_days = effective_backfill_window_days(requested_backfill_window_days);
    let codex_title_metadata = if source == SnapshotSource::Codex {
        CodexTitleMetadata::load_from_roots(roots)
    } else {
        CodexTitleMetadata::default()
    };
    let claude_title_metadata = if source == SnapshotSource::ClaudeCode {
        ClaudeTitleMetadata::load_from_roots(roots)
    } else {
        ClaudeTitleMetadata::default()
    };
    // The per-source sidecar fingerprint rides inside every candidate-file
    // fingerprint so an unchanged transcript still re-parses when its sidecar
    // title state changes (Codex: config/state/index files; Claude: desktop
    // store title content).
    let sidecar_fingerprint = match source {
        SnapshotSource::Codex => codex_title_metadata.sidecar_fingerprint.as_str(),
        SnapshotSource::ClaudeCode => claude_title_metadata.sidecar_fingerprint.as_str(),
        SnapshotSource::Pi => "",
    };
    // Read the per-turn fast-mode signal once per cycle (logs_2 is large); share
    // it read-only across every session file via Arc. Skipped when the local
    // opt-out is set.
    let codex_turn_traces = (source == SnapshotSource::Codex && codex_fast_mode_trace_enabled())
        .then(|| {
            Arc::new(CodexTurnTraceMap::load_from_roots(
                roots,
                backfill_window_days,
            ))
        });
    let mut files = Vec::new();
    for root in roots {
        collect_recent_jsonl_files(
            source,
            root,
            &mut files,
            sidecar_fingerprint,
            backfill_window_days,
        )?;
    }
    let discovered_file_count = files.len();
    let skipped_file_count_due_to_limit = discovered_file_count.saturating_sub(file_limit);
    files.sort_by_key(|file| Reverse(file.modified_unix_seconds));
    files.truncate(file_limit);

    let mut snapshots = Vec::new();
    let mut scanned_file_count = 0;
    for candidate in files {
        if !index.should_process(&candidate) {
            continue;
        }
        scanned_file_count += 1;
        let source_file_fingerprint = candidate.source_file_fingerprint.clone();
        let mut parsed = match source {
            SnapshotSource::Codex => parse_codex_jsonl_file_with_title_metadata_and_attribution(
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                &codex_title_metadata,
                codex_turn_traces.clone(),
                attribution_context,
            )?,
            SnapshotSource::ClaudeCode => {
                parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
                    &candidate.path,
                    collected_at,
                    source_file_fingerprint.clone(),
                    &claude_title_metadata,
                    artifacts_enabled,
                    attribution_context,
                )?
            }
            SnapshotSource::Pi => parse_pi_jsonl_file_with_attribution(
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                attribution_context,
            )?,
        };
        if source == SnapshotSource::Codex {
            for snapshot in parsed.iter_mut() {
                apply_codex_state_evidence(snapshot, &codex_title_metadata);
            }
        }
        let last_snapshot_fingerprint = parsed
            .last()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone());
        if source != SnapshotSource::Pi || last_snapshot_fingerprint.is_some() {
            index.record(candidate, last_snapshot_fingerprint);
        }
        snapshots.extend(parsed);
    }
    if source == SnapshotSource::Codex {
        append_codex_state_only_snapshots(
            &mut snapshots,
            &codex_title_metadata,
            collected_at,
            index,
        );
    }
    Ok(SourceScanResult {
        source,
        backfill_window_days,
        backfill_file_limit: file_limit,
        discovered_file_count,
        skipped_file_count_due_to_limit,
        scan_cap_hit: skipped_file_count_due_to_limit > 0,
        scanned_file_count,
        scanned_session_count: snapshots.len(),
        snapshots,
    })
}

fn apply_codex_state_evidence(item: &mut SnapshotItem, metadata: &CodexTitleMetadata) {
    let Some(thread) = metadata.state_threads.get(item.source_session_id.as_str()) else {
        return;
    };
    if thread.tokens_used == 0 {
        return;
    }
    item.provenance.state_total_tokens = Some(thread.tokens_used);
    item.provenance.state_archived = Some(thread.archived);
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::Codex, item);
}

fn append_codex_state_only_snapshots(
    snapshots: &mut Vec<SnapshotItem>,
    metadata: &CodexTitleMetadata,
    collected_at: &str,
    index: &ScanIndex,
) {
    let covered_session_ids: BTreeSet<String> = snapshots
        .iter()
        .map(|snapshot| snapshot.source_session_id.clone())
        .collect();
    // Sessions whose rollout was parsed into a snapshot in a PRIOR scan run.
    // The incremental scan skips unchanged rollout files, so they are absent
    // from this run's `snapshots`, but their split snapshot already reached the
    // backend — re-emitting a state-only total would overwrite it with an
    // unattributed "Other" (the bug this fix targets). We recover those session
    // ids from the persisted scan index. Two correctness points:
    //   * Only entries that actually produced a snapshot count
    //     (`last_snapshot_fingerprint` is set). `index.record` runs for every
    //     scanned file, including a rollout that parsed to zero usage rows; such
    //     a session has no split snapshot, so it MUST still fall through to a
    //     state-only total or its tokens would be dropped entirely.
    //   * Session ids are derived from the rollout filename, so coverage does
    //     not depend on the state DB `rollout_path` matching the scan path
    //     byte-for-byte (home symlinks, relative paths, case differences).
    let covered_in_prior_runs: BTreeSet<String> = index
        .files
        .iter()
        .filter(|(_, entry)| entry.last_snapshot_fingerprint.is_some())
        .filter_map(|(path, _)| codex_session_id_from_path(Path::new(path)))
        .collect();
    for (source_session_id, thread) in &metadata.state_threads {
        if thread.tokens_used == 0
            || covered_session_ids.contains(source_session_id)
            || covered_in_prior_runs.contains(source_session_id)
        {
            continue;
        }
        snapshots.push(codex_state_only_snapshot(
            source_session_id,
            thread,
            collected_at,
        ));
    }
}

fn codex_state_only_snapshot(
    source_session_id: &str,
    thread: &CodexStateThread,
    collected_at: &str,
) -> SnapshotItem {
    let model = thread
        .model
        .clone()
        .and_then(normalize_title)
        .unwrap_or_else(|| "unknown".to_string());
    let display_name = thread
        .title
        .clone()
        .and_then(|title| normalize_display_title(title, "session_index"));
    let row = SnapshotModelUsage {
        model,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        reasoning_effort: None,
        unattributed_total_tokens: thread.tokens_used,
        request_count: 0,
        selector_context: BTreeMap::new(),
        selector_sources: BTreeMap::new(),
        auth_mode: None,
        billing_channel: None,
        billing_provider: None,
        gateway_provider: None,
        model_provider: None,
        subscription_product: None,
        cost_usd: None,
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
    };
    // v6 requires usage_buckets whenever the snapshot reports any usage.
    // State-only snapshots have no per-line activity to bucket on, so we
    // synthesize one bucket at the hour of the most recent state evidence
    // (updated_at), falling back to created_at, then collected_at. If even
    // that fails to parse, the snapshot is emitted without buckets — the
    // backend will then reject it, but that's strictly better than crashing
    // the daemon's snapshot scan.
    let bucket_seed = thread
        .updated_at
        .clone()
        .or_else(|| thread.created_at.clone())
        .unwrap_or_else(|| collected_at.to_string());
    let usage_buckets = match activity_bucket_from_timestamp(&bucket_seed) {
        Some((bucket_start, normalized_timestamp)) => vec![SnapshotUsageBucket {
            bucket_start,
            model_usage: vec![row.clone()],
            first_activity_at: Some(normalized_timestamp.clone()),
            last_activity_at: Some(normalized_timestamp),
        }],
        None => Vec::new(),
    };
    let model_usage = vec![row];
    let has_display_name = display_name.is_some();
    let mut item = SnapshotItem {
        source_session_id: source_session_id.to_string(),
        snapshot_fingerprint: String::new(),
        status: "final".to_string(),
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_creation_5m_tokens: 0,
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: 0,
        unattributed_total_tokens: thread.tokens_used,
        request_count: 0,
        avg_duration_ms: None,
        avg_time_to_first_token_ms: None,
        max_duration_ms: None,
        max_time_to_first_token_ms: None,
        peak_context_fill_tokens: None,
        first_turn_context_tokens: None,
        compaction_count: None,
        model_usage,
        usage_buckets,
        cost: None,
        session_display_name: display_name,
        session_display_name_source: has_display_name.then(|| "session_index".to_string()),
        source_started_at: thread.created_at.clone(),
        source_ended_at: None,
        source_last_activity_at: thread.updated_at.clone(),
        collected_at: collected_at.to_string(),
        workspace_hash: None,
        workspace_display_label: None,
        workspace_label_source: None,
        repository_hash: None,
        repository_label: None,
        repository_label_source: None,
        repository_identity_source: None,
        workspace_kind: None,
        source_file_fingerprint: None,
        session_artifacts: Vec::new(),
        provenance: SnapshotProvenance {
            collector: "codex_state_sqlite".to_string(),
            source_file_count: 1,
            input_token_scope: Some("total_only".to_string()),
            state_total_tokens: Some(thread.tokens_used),
            state_archived: Some(thread.archived),
        },
        // Codex state-index summaries carry no session_meta -> no raw origin.
        origin: None,
        attribution_facts: Vec::new(),
    };
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::Codex, &item);
    item
}

pub fn parse_codex_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_codex_jsonl_file_with_title_metadata(
        path,
        collected_at,
        source_file_fingerprint,
        &CodexTitleMetadata::default(),
        None,
    )
}

fn parse_codex_jsonl_file_with_title_metadata(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
) -> Result<Vec<SnapshotItem>> {
    parse_codex_jsonl_file_with_title_metadata_and_attribution(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        codex_turn_traces,
        None,
    )
}

fn parse_codex_jsonl_file_with_title_metadata_and_attribution(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(title_metadata),
        None,
        codex_turn_traces,
        // Codex lines never feed the artifact scraper; the value is moot.
        true,
        attribution_context,
    )
}

pub fn parse_claude_code_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_artifacts(path, collected_at, source_file_fingerprint, true)
}

/// As ``parse_claude_code_jsonl_file`` but with the artifact-scrape policy
/// threaded in. The production scan path passes ``false`` when the org has
/// session artifacts disabled so the per-line VCS scrape is skipped entirely.
fn parse_claude_code_jsonl_file_with_artifacts(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    artifacts_enabled: bool,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_title_metadata(
        path,
        collected_at,
        source_file_fingerprint,
        &ClaudeTitleMetadata::default(),
        artifacts_enabled,
    )
}

/// Full production form with the desktop-store title metadata threaded in; the
/// scan path loads the store once per cycle and shares it across every session
/// file.
fn parse_claude_code_jsonl_file_with_title_metadata(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
    artifacts_enabled: bool,
) -> Result<Vec<SnapshotItem>> {
    parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        artifacts_enabled,
        None,
    )
}

fn parse_claude_code_jsonl_file_with_title_metadata_and_attribution(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        Some(title_metadata),
        None,
        artifacts_enabled,
        attribution_context,
    )
}

pub fn parse_pi_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_pi_jsonl_file_with_attribution(path, collected_at, source_file_fingerprint, None)
}

fn parse_pi_jsonl_file_with_attribution(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Pi,
        apply_pi_line,
        None,
        None,
        None,
        // Pi lines never feed the artifact scraper; the value is moot.
        true,
        attribution_context,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    source: SnapshotSource,
    apply_line: fn(&Value, &mut SnapshotAccumulator),
    codex_title_metadata: Option<&CodexTitleMetadata>,
    claude_title_metadata: Option<&ClaudeTitleMetadata>,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<Vec<SnapshotItem>> {
    let file = File::open(path).with_context(|| format!("open JSONL {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut accumulator = if let Some(metadata) = codex_title_metadata {
        SnapshotAccumulator::with_default_selector(source, metadata.default_selector.clone())
    } else {
        SnapshotAccumulator::new(source)
    };
    accumulator.artifacts_enabled = artifacts_enabled;
    accumulator.codex_turn_traces = codex_turn_traces;
    read_bounded_jsonl_lines(reader, MAX_JSONL_LINE_BYTES, |value| {
        apply_line(value, &mut accumulator);
    })
    .with_context(|| format!("read JSONL {}", path.display()))?;
    if source == SnapshotSource::Codex {
        if let Some(metadata) = codex_title_metadata {
            accumulator.apply_codex_title_metadata(path, metadata);
        }
        accumulator.apply_first_prompt_fallback();
    }
    if source == SnapshotSource::ClaudeCode {
        if let Some(metadata) = claude_title_metadata {
            accumulator.apply_claude_title_metadata(path, metadata);
        }
        accumulator.apply_first_prompt_fallback();
    }
    if source == SnapshotSource::Pi {
        accumulator.apply_first_prompt_fallback();
    }
    Ok(accumulator.into_items(
        path,
        collected_at,
        source_file_fingerprint,
        attribution_context,
    ))
}

/// Stream a JSONL reader line-by-line with a hard per-line byte ceiling,
/// invoking `on_value` for each line that parses to a JSON value.
///
/// Unlike `BufRead::lines` (and unlike a bare `read_until`, which would still
/// grow its buffer to the full length of an oversized physical line before
/// returning), this never materializes more than `max_line_bytes` of any single
/// line. Bytes are pulled through the reader's own buffer via `fill_buf`/
/// `consume` into a REUSED `buf`; the moment a line would exceed the cap the
/// in-progress bytes are dropped and the remainder of the physical line is
/// read-and-discarded (never buffered) up to the newline or EOF, then the line
/// is skipped. The tolerant per-line semantics of the old loop are preserved
/// exactly for normal lines: an empty/whitespace line is skipped, a line that is
/// not valid UTF-8 is skipped, and a line that does not parse as JSON is skipped
/// — only genuine I/O errors surface as `Err`.
fn read_bounded_jsonl_lines(
    mut reader: impl BufRead,
    max_line_bytes: usize,
    mut on_value: impl FnMut(&Value),
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        // Accumulate one line, bounded to `max_line_bytes`. `line_complete`
        // tracks whether we reached a newline (vs. EOF) so we can stop the
        // outer loop on a trailing partial line.
        let mut line_complete = false;
        let mut overflowed = false;
        let reached_eof = loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                break true;
            }
            match available.iter().position(|&byte| byte == b'\n') {
                Some(offset) => {
                    if !overflowed {
                        let take = (max_line_bytes - buf.len()).min(offset);
                        if take < offset {
                            // Line (up to the newline) exceeds the cap: keep
                            // only what fits, mark it overflowed so it is later
                            // skipped, and never buffer the rest.
                            overflowed = true;
                        }
                        buf.extend_from_slice(&available[..take]);
                    }
                    reader.consume(offset + 1);
                    line_complete = true;
                    break false;
                }
                None => {
                    let len = available.len();
                    if !overflowed {
                        let take = (max_line_bytes - buf.len()).min(len);
                        if take < len {
                            overflowed = true;
                        }
                        buf.extend_from_slice(&available[..take]);
                    }
                    reader.consume(len);
                }
            }
        };
        if !line_complete && buf.is_empty() && !overflowed {
            // Clean EOF with no pending bytes.
            break;
        }
        if overflowed {
            // Drop the oversized line; its retained-capacity buffer is reset to
            // the cap so one huge line does not pin a large allocation.
            buf.clear();
            buf.shrink_to(max_line_bytes);
            if reached_eof {
                break;
            }
            continue;
        }
        // Trim a trailing CR so a CRLF transcript parses identically to LF.
        let mut bytes = buf.as_slice();
        if bytes.last() == Some(&b'\r') {
            bytes = &bytes[..bytes.len() - 1];
        }
        if let Ok(line) = std::str::from_utf8(bytes) {
            if !line.trim().is_empty() {
                if let Ok(value) = serde_json::from_str::<Value>(line) {
                    on_value(&value);
                }
            }
        }
        if reached_eof {
            break;
        }
    }
    Ok(())
}

fn raw_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn normalize_selector_raw(field: &str, value: &Value) -> Option<String> {
    let normalized = match value {
        Value::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_ascii_lowercase().replace([' ', '-'], "_"),
        _ => return None,
    };
    if normalized.is_empty() {
        return None;
    }
    let true_values = ["true", "1", "yes", "y", "on", "enabled"];
    let false_values = ["false", "0", "no", "n", "off", "disabled"];
    let standard_values = ["normal", "default", "base"];
    match field {
        "batch_mode" => {
            if true_values.contains(&normalized.as_str()) {
                Some("true".to_string())
            } else if false_values.contains(&normalized.as_str()) {
                Some("false".to_string())
            } else {
                None
            }
        }
        "mode" => {
            if true_values.contains(&normalized.as_str()) || normalized == "fast" {
                Some("fast".to_string())
            } else if false_values.contains(&normalized.as_str())
                || standard_values.contains(&normalized.as_str())
                || normalized == "standard"
            {
                Some("standard".to_string())
            } else if normalized == "priority" || normalized == "flex" {
                Some(normalized)
            } else {
                None
            }
        }
        "service_tier" | "speed_mode" => {
            if standard_values.contains(&normalized.as_str()) {
                Some("standard".to_string())
            } else {
                Some(normalized)
            }
        }
        "region_mode" => match normalized.as_str() {
            "us" | "usa" | "us_only" | "united_states" | "data_residency_us" => {
                Some("us".to_string())
            }
            "eu" | "eu_only" | "european_union" | "data_residency_eu" => Some("eu".to_string()),
            _ => Some(normalized),
        },
        _ => Some(normalized),
    }
}

fn selector_source_path(path: &[&str]) -> String {
    path.join(".")
}

fn insert_selector_raw(capture: &mut SelectorCapture, field: &str, source: &str, value: &Value) {
    let Some(normalized) = normalize_selector_raw(field, value) else {
        return;
    };
    capture.insert(field, normalized.clone(), source);
    if field == "speed_mode" && normalized == "fast" {
        capture.insert("service_tier", "fast".to_string(), "derived_from_speed");
    }
}

fn insert_selector_at(capture: &mut SelectorCapture, value: &Value, field: &str, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        insert_selector_raw(capture, field, selector_source_path(path).as_str(), raw);
    }
}

fn selector_from_object(value: &Value, source_prefix: &str) -> SelectorCapture {
    let mut capture = SelectorCapture::default();
    let Value::Object(map) = value else {
        return capture;
    };
    let aliases: &[(&str, &[&str])] = &[
        (
            "service_tier",
            &[
                "service_tier",
                "serviceTier",
                "service.tier",
                "actual_service_tier",
                "tier",
            ],
        ),
        ("speed_mode", &["speed_mode", "speedMode", "speed"]),
        ("batch_mode", &["batch_mode", "batchMode", "batch"]),
        (
            "region_mode",
            &[
                "region_mode",
                "regionMode",
                "data_residency",
                "dataResidency",
                "inference_geo",
                "inferenceGeo",
                "region",
            ],
        ),
        (
            "context_bucket",
            &[
                "context_bucket",
                "contextBucket",
                "context.bucket",
                "context_length_bucket",
                "contextLengthBucket",
            ],
        ),
        (
            "cache_ttl",
            &[
                "cache_ttl",
                "cacheTtl",
                "cache.ttl",
                "cache_write_ttl",
                "cache_write_ttl_seconds",
            ],
        ),
        (
            "mode",
            &[
                "mode",
                "service_mode",
                "serviceMode",
                "performance_mode",
                "performanceMode",
                "codex_mode",
                "codexMode",
                "fast_mode",
                "fastMode",
                "is_fast_mode",
                "isFastMode",
                "codex_fast_mode",
                "codexFastMode",
                "openai.fast_mode",
            ],
        ),
        (
            "gateway_provider",
            &["gateway_provider", "gatewayProvider", "api"],
        ),
        (
            "model_provider",
            &["model_provider", "modelProvider", "provider"],
        ),
        ("auth_mode", &["auth_mode", "authMode"]),
        ("billing_channel", &["billing_channel", "billingChannel"]),
        (
            "subscription_product",
            &[
                "subscription_product",
                "subscriptionProduct",
                "plan_type",
                "planType",
            ],
        ),
        (
            "plan_window_bucket",
            &["plan_window_bucket", "planWindowBucket"],
        ),
    ];
    for (field, field_aliases) in aliases {
        for alias in *field_aliases {
            let Some(raw) = map.get(*alias) else {
                continue;
            };
            let source = if source_prefix.is_empty() {
                alias.to_string()
            } else {
                format!("{source_prefix}.{alias}")
            };
            insert_selector_raw(&mut capture, field, source.as_str(), raw);
            break;
        }
    }
    for nested_key in ["selector_context", "selector"] {
        if let Some(nested) = map.get(nested_key) {
            let source = if source_prefix.is_empty() {
                nested_key.to_string()
            } else {
                format!("{source_prefix}.{nested_key}")
            };
            capture.merge(selector_from_object(nested, source.as_str()));
        }
    }
    capture
}

fn merge_selector_object_at(capture: &mut SelectorCapture, value: &Value, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        capture.merge(selector_from_object(
            raw,
            selector_source_path(path).as_str(),
        ));
    }
}

fn codex_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let object_paths: &[&[&str]] = &[
        &[],
        &["payload"],
        &["turn_context", "payload"],
        &["payload", "info"],
        &["token_count", "info"],
        &["payload", "rate_limits"],
        &["token_count", "info", "rate_limits"],
    ];
    for path in object_paths {
        merge_selector_object_at(&mut selector, value, path);
    }
    if let Some(bucket) = codex_plan_window_bucket(value) {
        insert_selector_raw(
            &mut selector,
            "plan_window_bucket",
            "derived_from_rate_limits_secondary_resets_at",
            &Value::Number(bucket.into()),
        );
    }
    codex_extract_quota_window_selectors(value, &mut selector);
    insert_selector_raw(
        &mut selector,
        "model_provider",
        "derived_from_codex_source",
        &Value::String("openai".to_string()),
    );
    let service_tier_paths: &[&[&str]] = &[
        &["token_count", "info", "service_tier"],
        &["payload", "info", "service_tier"],
        &["turn_context", "payload", "service_tier"],
        &["payload", "service_tier"],
        &["service_tier"],
    ];
    for path in service_tier_paths {
        insert_selector_at(&mut selector, value, "service_tier", path);
    }
    let fast_mode_paths: &[&[&str]] = &[
        &["payload", "fast_mode"],
        &["fast_mode"],
        &["codex_fast_mode"],
    ];
    for path in fast_mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let mode_paths: &[&[&str]] = &[&["payload", "mode"], &["mode"]];
    for path in mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let extra_paths: &[(&str, &[&[&str]])] = &[
        (
            "batch_mode",
            &[
                &["payload", "batch_mode"],
                &["payload", "info", "batch_mode"],
                &["batch_mode"],
            ],
        ),
        (
            "region_mode",
            &[
                &["payload", "inference_geo"],
                &["payload", "info", "inference_geo"],
                &["inference_geo"],
            ],
        ),
        (
            "context_bucket",
            &[
                &["payload", "context_bucket"],
                &["payload", "info", "context_bucket"],
                &["context_bucket"],
            ],
        ),
    ];
    for (field, paths) in extra_paths {
        for path in *paths {
            insert_selector_at(&mut selector, value, field, path);
        }
    }
    selector
}

fn claude_code_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let usage_paths: &[&[&str]] = &[&["message", "usage"], &["usage"], &["payload", "usage"]];
    for path in usage_paths {
        if let Some(raw) = raw_value_at(value, path) {
            selector.merge(selector_from_object(
                raw,
                selector_source_path(path).as_str(),
            ));
        }
    }
    selector.merge(selector_from_object(value, ""));
    if let Some(gateway) = detect_claude_gateway_provider(value) {
        let raw = Value::String(gateway);
        insert_selector_raw(
            &mut selector,
            "gateway_provider",
            "derived_from_message_id_prefix",
            &raw,
        );
        insert_selector_raw(
            &mut selector,
            "model_provider",
            "derived_from_claude_code_source",
            &Value::String("anthropic".to_string()),
        );
    }
    capture_claude_attribution(value, &mut selector, claude_attribution_capture_enabled());
    selector
}

/// Lift Claude Code's per-turn work-attribution off this assistant+usage line
/// into the per-turn `SelectorCapture`. Claude Code writes the five attribution
/// markers as TOP-LEVEL string siblings of `message` on each `type=assistant`
/// line that also carries `message.usage` — i.e. exactly the line the usage
/// selector is already built from — so this attributes the same turn's usage.
///
/// Done in `claude_code_selector_from_line` (the per-LINE selector, not the
/// accumulator-merged `current_selector`) so one turn's subagent/skill cannot
/// leak onto later turns, mirroring the per-turn `context_bucket` stamp in
/// `apply_claude_code_line` and the Codex per-turn `service_tier` discipline.
///
/// CONTRACT BOUNDARY: gated OFF by default via
/// `claude_attribution_capture_enabled`. When enabled, the approved canonical
/// snake_case keys below ride inside selector_context after the mirrored
/// backend `SELECTOR_FIELDS`/`SELECTOR_SOURCE_KEYS` contract is in place.
///
/// `attribution_mcp_tool` is captured last and is the highest-cardinality
/// marker; allowlisting it would explode `selector_hash` row counts, so it stays
/// stripped in this first contract.
///
/// `enabled` is threaded in (read from `claude_attribution_capture_enabled` at
/// the call site) so the capture logic is unit-testable without process-global
/// env mutation.
fn capture_claude_attribution(value: &Value, selector: &mut SelectorCapture, enabled: bool) {
    if !enabled {
        return;
    }
    // (raw CC key, canonical selector key). Subagent first (priority dimension).
    const ATTRIBUTION_FIELDS: &[(&str, &str)] = &[
        ("attributionAgent", "attribution_subagent"),
        ("attributionSkill", "attribution_skill"),
        ("attributionPlugin", "attribution_plugin"),
        ("attributionMcpServer", "attribution_mcp_server"),
        ("attributionMcpTool", "attribution_mcp_tool"),
    ];
    for (raw_key, canonical_key) in ATTRIBUTION_FIELDS {
        if let Some(attribution) = string_at(value, &[raw_key]) {
            selector.insert(canonical_key, attribution, "claude_code_attribution_field");
        }
    }
}

fn detect_claude_gateway_provider(value: &Value) -> Option<String> {
    let id = string_at(value, &["message", "id"]).or_else(|| string_at(value, &["requestId"]))?;
    if id.contains("_vrtx_") {
        return Some("vertex".into());
    }
    if id.contains("_bdrk_") {
        return Some("bedrock".into());
    }
    if id.starts_with("msg_") || id.starts_with("req_") {
        return Some("anthropic".into());
    }
    None
}

fn pi_selector_from_custom(value: &Value) -> Option<SelectorCapture> {
    let custom_type = string_at(value, &["customType"])
        .or_else(|| string_at(value, &["custom_type"]))
        .or_else(|| string_at(value, &["name"]))?;
    if custom_type != "ottto-selector" && custom_type != "ottto.selector" {
        return None;
    }
    let mut selector = SelectorCapture::default();
    if let Some(data) = raw_value_at(value, &["data"]) {
        selector.merge(selector_from_object(data, "data"));
    }
    selector.merge(selector_from_object(value, ""));
    (!selector.is_empty()).then_some(selector)
}

fn pi_selector_from_message_end(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    selector.merge(selector_from_object(value, ""));
    if let Some(message) = raw_value_at(value, &["message"]) {
        selector.merge(selector_from_object(message, "message"));
    }
    if let Some(usage) = raw_value_at(value, &["message", "usage"]) {
        selector.merge(selector_from_object(usage, "message.usage"));
    }
    selector
}

fn apply_codex_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = string_at(value, &["session_meta", "payload", "id"])
            .or_else(|| string_at(value, &["payload", "id"]))
            .or_else(|| string_at(value, &["session_id"]))
            .or_else(|| string_at(value, &["sessionId"]));
    }
    // Raw session-origin (siblings of `id` in session_meta.payload). The
    // session_meta line carries these; other lines yield None, so first-seen
    // (guarded by is_none) keeps the authoritative session_meta values.
    if accumulator.origin.thread_source.is_none() {
        accumulator.origin.thread_source =
            string_at(value, &["session_meta", "payload", "thread_source"])
                .or_else(|| string_at(value, &["payload", "thread_source"]));
    }
    if accumulator.origin.source.is_none() && accumulator.origin.source_subagent.is_none() {
        if let Some(src) = raw_value_at(value, &["session_meta", "payload", "source"])
            .or_else(|| raw_value_at(value, &["payload", "source"]))
        {
            if let Some(text) = src.as_str() {
                accumulator.origin.source = Some(text.to_string());
            } else if src.is_object() {
                // Codex subagent form: source = { "subagent": { "thread_spawn": .. } }.
                accumulator.origin.source_subagent = Some(src.get("subagent").is_some());
                accumulator.origin.parent_session_ref =
                    string_at(src, &["subagent", "thread_spawn", "parent_thread_id"]);
            }
        }
    }
    if accumulator.origin.originator.is_none() {
        accumulator.origin.originator =
            string_at(value, &["session_meta", "payload", "originator"])
                .or_else(|| string_at(value, &["payload", "originator"]));
    }
    if accumulator.origin.agent_role.is_none() {
        accumulator.origin.agent_role =
            string_at(value, &["session_meta", "payload", "agent_role"])
                .or_else(|| string_at(value, &["payload", "agent_role"]));
    }
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["time"]))
        .or_else(|| string_at(value, &["created_at"]));
    accumulator.note_time(timestamp.clone());
    accumulator.set_title(codex_transcript_title(value), "transcript_title");
    accumulator.set_first_prompt_title(codex_first_user_prompt(value));
    accumulator.set_model(
        string_at(value, &["turn_context", "payload", "model"])
            .or_else(|| string_at(value, &["payload", "model"]))
            .or_else(|| string_at(value, &["model"])),
    );
    accumulator.set_workspace_hash(
        string_at(value, &["turn_context", "payload", "cwd"])
            .or_else(|| string_at(value, &["payload", "cwd"]))
            .or_else(|| string_at(value, &["cwd"])),
    );
    let selector = codex_selector_from_line(value);
    accumulator.set_selector(selector.clone());
    if let Some(effort) = codex_reasoning_effort(value) {
        accumulator.latest_reasoning_effort = Some(effort);
    }
    // Track the running turn id from `turn_context` (the token_count event that
    // emits usage carries none). It joins each usage row to its `logs_2`
    // fast-mode signal. Lines without a turn id leave the running value intact.
    if let Some(turn_id) = string_at(value, &["turn_context", "payload", "turn_id"])
        .or_else(|| string_at(value, &["payload", "turn_id"]))
    {
        accumulator.latest_turn_id = Some(turn_id);
    }
    // Codex compaction (auto or manual `/compact`) writes a top-level
    // `type=compacted` rollout record carrying the `replacement_history` that
    // supersedes the compacted turns. Codex also emits an
    // `event_msg`/`context_compacted` UI event for the same compaction a few
    // milliseconds later; the two are strictly paired, so count the rollout
    // record only — counting both would double every compaction. The rollout
    // record is the state mutation itself, which makes it the Codex analogue of
    // the `isCompactSummary` record the Claude parser counts.
    if string_eq_at(value, &["type"], "compacted") {
        accumulator.compaction_count += 1;
    }
    // Context posture watermarks for this response. Codex states the per-turn
    // usage directly in `last_token_usage`, so read it off the event rather
    // than reusing the cumulative delta computed below. The delta agrees with
    // `last_token_usage` on a healthy sequence, but not on the two cases that
    // matter here: a duplicated `token_count` event (Codex emits these) yields
    // a zero delta while `last_token_usage` still states the turn's true
    // context, and a non-monotonic cumulative (session restart) makes the delta
    // the whole session's input rather than one turn's — which would post a
    // wildly inflated peak.
    //
    // The value needs no cache adjustment: unlike Claude's `message.usage`,
    // Codex `input_tokens` is INCLUSIVE of `cached_input_tokens` (hence
    // `input_token_scope=inclusive_cached` in this snapshot's provenance), so
    // it already IS the prompt volume the model saw. Adding cache reads on top
    // — the Claude-side `effective_input_context()` formula — would nearly
    // double a cache-heavy turn and report a long session as filling more than
    // its own context window.
    if let Some(context_tokens) = codex_last_turn_input_context(value) {
        // The `token_count` event Codex emits at a compaction reports zero
        // usage; it observed no context, so it must not become the baseline.
        if context_tokens > 0 {
            if accumulator.first_turn_context_tokens.is_none() {
                accumulator.first_turn_context_tokens = Some(context_tokens);
            }
            accumulator.peak_context_fill_tokens =
                accumulator.peak_context_fill_tokens.max(context_tokens);
        }
    }
    if let Some(usage) = codex_total_usage(value) {
        // Codex cumulative totals carry request_count as a session-wide count.
        // When the field is missing the parser defaults it to 1 so deltas
        // would yield 0 requests. Track the implicit case and override the
        // delta's request_count to 1 so the bucket row reflects "one turn
        // observed at this hour" — matching v5's note_activity behavior.
        let implicit_request_count = if codex_total_usage_has_request_count(value) {
            None
        } else {
            Some(1)
        };
        // Stamp the fast-mode tier onto THIS turn's usage row only — passed as
        // the per-line selector, never merged into current_selector — so a fast
        // turn prices at the priority rate without leaking into later standard
        // turns of the same session.
        let mut usage_selector = selector;
        if accumulator.current_turn_is_priority() {
            usage_selector.insert(
                "service_tier",
                "priority".to_string(),
                "derived_from_logs_2",
            );
        }
        accumulator.set_cumulative_usage_with_selector(
            string_at(value, &["token_count", "info", "model"])
                .or_else(|| string_at(value, &["payload", "info", "model"]))
                .or_else(|| string_at(value, &["turn_context", "payload", "model"]))
                .or_else(|| string_at(value, &["payload", "model"])),
            usage,
            usage_selector,
            timestamp.as_deref(),
            implicit_request_count,
            accumulator.latest_reasoning_effort.clone(),
        );
    }
    // Per-turn latency from the rollout `task_complete` event. Codex emits
    // `duration_ms` + `time_to_first_token_ms` only here (never over OTLP), so
    // accumulate them per session for the session-level latency average.
    if string_eq_at(value, &["payload", "type"], "task_complete") {
        if let Some(duration_ms) = u64_at(value, &["payload", "duration_ms"]) {
            accumulator.latency_duration_ms_sum = accumulator
                .latency_duration_ms_sum
                .saturating_add(duration_ms);
            accumulator.latency_duration_ms_count += 1;
            accumulator.latency_duration_ms_max =
                accumulator.latency_duration_ms_max.max(duration_ms);
        }
        if let Some(ttft_ms) = u64_at(value, &["payload", "time_to_first_token_ms"]) {
            accumulator.latency_ttft_ms_sum =
                accumulator.latency_ttft_ms_sum.saturating_add(ttft_ms);
            accumulator.latency_ttft_ms_count += 1;
            accumulator.latency_ttft_ms_max = accumulator.latency_ttft_ms_max.max(ttft_ms);
        }
    }
}

fn codex_plan_window_bucket(value: &Value) -> Option<u64> {
    let rate_limit_paths: &[&[&str]] = &[
        &["payload", "rate_limits"],
        &["token_count", "info", "rate_limits"],
    ];
    for path in rate_limit_paths {
        if let Some(rate_limits) = raw_value_at(value, path) {
            if let Some(resets_at) = u64_at(rate_limits, &["secondary", "resets_at"]) {
                return Some(resets_at / 86_400);
            }
        }
    }
    None
}

fn codex_extract_quota_window_selectors(value: &Value, selector: &mut SelectorCapture) {
    let rate_limits = raw_value_at(value, &["payload", "rate_limits"])
        .or_else(|| raw_value_at(value, &["token_count", "info", "rate_limits"]));
    let Some(rate_limits) = rate_limits else {
        return;
    };
    for window_name in &["primary", "secondary"] {
        let Some(window) = raw_value_at(rate_limits, &[*window_name]) else {
            continue;
        };
        for (field_suffix, source_key, raw) in [
            (
                "used_percent",
                "used_percent",
                window.get("used_percent").cloned(),
            ),
            (
                "window_minutes",
                "window_minutes",
                window.get("window_minutes").cloned(),
            ),
            ("resets_at", "resets_at", window.get("resets_at").cloned()),
        ] {
            let Some(raw) = raw else {
                continue;
            };
            let field = format!("agent_quota_{window_name}_{field_suffix}");
            let source = format!("payload.rate_limits.{window_name}.{source_key}");
            insert_selector_raw(selector, field.as_str(), source.as_str(), &raw);
        }
    }
    if let Some(credits) = raw_value_at(rate_limits, &["credits"]) {
        for (field_suffix, source_key) in [
            ("has_credits", "has_credits"),
            ("unlimited", "unlimited"),
            ("balance", "balance"),
        ] {
            let Some(raw) = credits.get(source_key) else {
                continue;
            };
            let field = format!("agent_quota_credits_{field_suffix}");
            let source = format!("payload.rate_limits.credits.{source_key}");
            insert_selector_raw(selector, field.as_str(), source.as_str(), raw);
        }
    }
}

fn codex_transcript_title(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "thread_name_updated") {
        return string_at(value, &["payload", "thread_name"])
            .or_else(|| string_at(value, &["payload", "name"]))
            .or_else(|| string_at(value, &["payload", "title"]));
    }
    if string_eq_at(value, &["type"], "thread_name_updated") {
        return string_at(value, &["thread_name"])
            .or_else(|| string_at(value, &["name"]))
            .or_else(|| string_at(value, &["title"]));
    }
    string_at(value, &["thread_name_updated", "payload", "name"])
        .or_else(|| string_at(value, &["thread_name_updated", "name"]))
}

fn codex_first_user_prompt(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "user_message") {
        return string_at(value, &["payload", "message"])
            .or_else(|| string_at(value, &["payload", "text"]))
            .or_else(|| text_from_array(value.pointer("/payload/text_elements")));
    }
    if string_eq_at(value, &["type"], "user_message") {
        return string_at(value, &["message"])
            .or_else(|| string_at(value, &["text"]))
            .or_else(|| text_from_array(value.get("text_elements")));
    }
    if string_eq_at(value, &["payload", "type"], "message")
        && string_eq_at(value, &["payload", "role"], "user")
    {
        return text_from_array(value.pointer("/payload/content"));
    }
    None
}

fn text_from_array(value: Option<&Value>) -> Option<String> {
    let Value::Array(items) = value? else {
        return None;
    };
    let mut parts = Vec::new();
    for item in items {
        match item {
            Value::String(text) => parts.push(text.as_str()),
            Value::Object(_) => {
                if let Some(text) = item
                    .get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("input_text").and_then(Value::as_str))
                {
                    parts.push(text);
                }
            }
            _ => {}
        }
    }
    normalize_title(parts.join("\n"))
}

/// First-user-prompt candidate from one Claude Code transcript record — the
/// Claude analogue of `codex_first_user_prompt`, feeding the shared
/// `first_prompt` fallback when no real title exists anywhere (pure-CLI
/// sessions never opened in the desktop app).
///
/// Only genuine human-authored prompts qualify: `type=user` records whose
/// `message.role` is `user`, skipping `isMeta` records, `tool_result` content
/// blocks (which also ride `type=user` records), and harness wrappers
/// (slash-command envelopes, injected system reminders).
fn claude_first_user_prompt(value: &Value) -> Option<String> {
    if !string_eq_at(value, &["type"], "user")
        || value.get("isMeta").and_then(Value::as_bool) == Some(true)
        || !string_eq_at(value, &["message", "role"], "user")
    {
        return None;
    }
    match value.pointer("/message/content") {
        Some(Value::String(text)) => {
            if claude_prompt_is_harness_wrapper(text) {
                return None;
            }
            normalize_title(text.clone())
        }
        Some(content @ Value::Array(_)) => claude_prompt_text_from_content(content),
        _ => None,
    }
}

fn claude_prompt_text_from_content(content: &Value) -> Option<String> {
    let Value::Array(items) = content else {
        return None;
    };
    let mut parts = Vec::new();
    for item in items {
        if !string_eq_at(item, &["type"], "text") {
            continue;
        }
        if let Some(text) = item.get("text").and_then(Value::as_str) {
            if !claude_prompt_is_harness_wrapper(text) {
                parts.push(text);
            }
        }
    }
    normalize_title(parts.join("\n"))
}

/// True for text the Claude Code harness writes into `type=user` records that
/// is not a human prompt: slash-command envelopes, local command output,
/// injected system reminders, and background-task notifications.
fn claude_prompt_is_harness_wrapper(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with("<command-")
        || trimmed.starts_with("<local-command")
        || trimmed.starts_with("<system-reminder")
        || trimmed.starts_with("<task-notification")
        || trimmed.starts_with("[SYSTEM NOTIFICATION")
        || trimmed.starts_with("[Request interrupted")
        || trimmed.starts_with("Caveat: the messages below were generated")
}

fn apply_claude_code_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = string_at(value, &["sessionId"])
            .or_else(|| string_at(value, &["session_id"]))
            .or_else(|| string_at(value, &["conversation_id"]));
    }
    // Raw session-origin from the Claude JSONL header/lines. entrypoint +
    // sessionKind are first-seen; isSidechain is per-line so any true marks the
    // whole session a subagent (Task tool sidechain).
    if accumulator.origin.entrypoint.is_none() {
        accumulator.origin.entrypoint = string_at(value, &["entrypoint"]);
    }
    if accumulator.origin.session_kind.is_none() {
        accumulator.origin.session_kind = string_at(value, &["sessionKind"]);
    }
    if let Some(sidechain) = value.get("isSidechain").and_then(Value::as_bool) {
        accumulator.origin.is_sidechain =
            Some(accumulator.origin.is_sidechain.unwrap_or(false) || sidechain);
    }
    accumulator.note_provider_skill(string_at(value, &["attributionSkill"]));
    // Compaction (auto or manual `/compact`) injects a `type=user` record
    // flagged with a top-level `isCompactSummary: true` boolean (the summary
    // prompt that replaces the compacted history). Count each one: frequent
    // compaction is a context-pressure symptom the backend surfaces.
    if value.get("type").and_then(Value::as_str) == Some("user")
        && value.get("isCompactSummary").and_then(Value::as_bool) == Some(true)
    {
        accumulator.compaction_count += 1;
    }
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["created_at"]))
        .or_else(|| string_at(value, &["message", "created_at"]));
    accumulator.note_time(timestamp.clone());
    // Remember the latest user-input moment so the next assistant response can
    // derive its turn duration. A `type=user` record is either a real prompt or
    // a tool_result; both are "model input available" instants and neither
    // carries `message.usage`, so this never collides with the usage path below.
    if string_eq_at(value, &["type"], "user") {
        if let Some(user_ts) = timestamp.clone() {
            accumulator.claude_last_user_ts = Some(user_ts);
        }
    }
    accumulator.set_title(string_at(value, &["aiTitle"]), "ai_title");
    accumulator.set_title_if_absent(
        string_at(value, &["summary"])
            .or_else(|| string_at(value, &["title"]))
            .or_else(|| string_at(value, &["metadata", "title"])),
        "summary",
    );
    accumulator.set_first_prompt_title(claude_first_user_prompt(value));
    accumulator.set_model(
        string_at(value, &["message", "model"])
            .or_else(|| string_at(value, &["model"]))
            .or_else(|| string_at(value, &["payload", "model"])),
    );
    accumulator.set_workspace_hash(
        string_at(value, &["cwd"])
            .or_else(|| string_at(value, &["projectPath"]))
            .or_else(|| string_at(value, &["workspace"])),
    );
    // One API response can span several JSONL records (one per assistant
    // content block), each repeating the same `message.id` + `requestId` with
    // identical usage. Count usage once per response; duplicate records still
    // contribute every NON-usage signal above (timestamps, model, title,
    // sidechain, workspace) and the artifact scrape below.
    let usage = claude_code_delta_usage(value);
    let usage_first_seen = match (usage.is_some(), claude_code_usage_dedup_key(value)) {
        // Only usage-bearing lines consume the key: a keyed line without
        // usage must not shadow the later record that carries the tokens.
        (true, Some(key)) => accumulator.seen_claude_usage_keys.insert(key),
        // No message.id and no requestId: nothing to dedup on, count the line.
        _ => true,
    };
    if let Some(usage) = usage.filter(|_| usage_first_seen) {
        // First content-block record of this API response: derive the turn's
        // wall-clock duration (this record's timestamp minus the preceding user
        // record) once, aligned with the once-per-response usage count above.
        // Later duplicate content-block records of the same response are gated
        // out here too, so each turn contributes exactly one latency sample.
        accumulator.note_claude_turn_duration(timestamp.as_deref());
        // Context posture watermarks from this counted response's effective
        // input context (the prompt volume the model actually saw). The first
        // counted response with any context becomes the first-turn baseline
        // (including first user input); the running max is the session's peak.
        // Gated by the
        // same once-per-response dedup as the usage count above, so repeated
        // content-block records of one API response contribute one sample.
        let effective_input_context = usage.effective_input_context();
        if effective_input_context > 0 {
            if accumulator.first_turn_context_tokens.is_none() {
                accumulator.first_turn_context_tokens = Some(effective_input_context);
            }
            accumulator.peak_context_fill_tokens = accumulator
                .peak_context_fill_tokens
                .max(effective_input_context);
        }
        let mut selector = claude_code_selector_from_line(value);
        // Tag the 1M-context attribution bucket from this turn's effective input
        // volume. Claude Code logs the BASE model id (e.g. `claude-opus-4-8`)
        // for BOTH the regular and the "(1M context)" picker variants and never
        // persists the `anthropic-beta: context-1m` opt-in (a request header) to
        // the transcript, so per-turn input volume is the only signal: a turn
        // whose effective input context exceeds the regular 200K cap could only
        // have run with the 1M window enabled. A 1M-enabled turn under the
        // threshold is indistinguishable from a regular turn and correctly tags
        // `short`. The bucket rides in selector_context, so the existing
        // RowKey/selector_hash split already emits a session's long and short
        // turns as separate model_usage rows; the backend honors this
        // daemon-supplied bucket ahead of its own (request_count==1-gated)
        // derivation, so aggregated hourly rows still tag `long` accurately. An
        // explicit transcript-supplied bucket (none emitted today) is left as-is.
        let has_explicit_bucket = selector
            .context
            .get("context_bucket")
            .is_some_and(|value| !value.is_empty());
        if !has_explicit_bucket {
            let context_bucket =
                if effective_input_context > CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS {
                    "long"
                } else {
                    "short"
                };
            selector.insert(
                "context_bucket",
                context_bucket.to_string(),
                "derived_from_effective_input_volume",
            );
        }
        accumulator.add_usage_with_selector(
            string_at(value, &["message", "model"])
                .or_else(|| string_at(value, &["model"]))
                .or_else(|| string_at(value, &["payload", "model"])),
            usage,
            selector,
            timestamp.as_deref(),
            // Claude Code surfaces per-turn effort via OTLP, not this snapshot path.
            None,
        );
    }
    // Artifact scraping clones and tokenizes every tool-result blob on the
    // line, so skip it wholesale when the org has the feature off (the default
    // and majority case) rather than scraping then discarding in
    // ``apply_upload_policy``.
    if accumulator.artifacts_enabled {
        let artifacts = extract_session_artifacts(&claude_code_scannable_text(value));
        if !artifacts.is_empty() {
            accumulator.add_artifacts(artifacts);
        }
    }
}

/// Gather tool-output text from one Claude Code transcript line (tool_result
/// content + ``toolUseResult`` stdout/stderr) for artifact scraping. Prompt text
/// and assistant prose are deliberately excluded.
fn claude_code_scannable_text(value: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(tool_use_result) = value.get("toolUseResult") {
        collect_tool_text(tool_use_result, &mut parts);
    }
    if let Some(content) = value.pointer("/message/content").and_then(Value::as_array) {
        for block in content {
            if string_eq_at(block, &["type"], "tool_result") {
                if let Some(inner) = block.get("content") {
                    collect_tool_text(inner, &mut parts);
                }
            }
        }
    }
    parts.join("\n")
}

fn collect_tool_text(value: &Value, parts: &mut Vec<String>) {
    match value {
        Value::String(text) => parts.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_tool_text(item, parts);
            }
        }
        Value::Object(map) => {
            for key in ["stdout", "stderr", "text", "content", "output"] {
                if let Some(child) = map.get(key) {
                    collect_tool_text(child, parts);
                }
            }
        }
        _ => {}
    }
}

/// Scrape canonical, content-free VCS artifacts (PR / issue / commit) from free
/// text. Only clean values survive: clean authority, no credentials, query, or
/// percent-encoding, and the path truncated at the numeric id — so the backend
/// accepts them unchanged and a malformed match can never reject the batch.
fn extract_session_artifacts(text: &str) -> Vec<SessionArtifact> {
    let mut out: Vec<SessionArtifact> = Vec::new();
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '<' | '>' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | '\\' | '|'
            )
    }) {
        if let Some(artifact) = parse_artifact_url(token) {
            push_unique_artifact(&mut out, artifact);
        }
    }
    for line in text.lines() {
        if let Some(sha) = parse_commit_sha_line(line) {
            push_unique_artifact(
                &mut out,
                SessionArtifact {
                    kind: "commit".to_string(),
                    value: sha,
                },
            );
        }
    }
    out
}

fn push_unique_artifact(out: &mut Vec<SessionArtifact>, artifact: SessionArtifact) {
    if out.len() >= MAX_SESSION_ARTIFACTS {
        return;
    }
    if !out.iter().any(|existing| existing == &artifact) {
        out.push(artifact);
    }
}

/// Parse one token as a PR/issue/MR URL, returning its canonical form
/// (`scheme://authority/<repo path>/<marker>/<id>`) or None.
fn parse_artifact_url(token: &str) -> Option<SessionArtifact> {
    let token = token.trim_end_matches(['.', ';', ':', '!', '?']);
    let (scheme, rest) = if let Some(rest) = token.strip_prefix("https://") {
        ("https", rest)
    } else {
        let rest = token.strip_prefix("http://")?;
        ("http", rest)
    };
    let slash = rest.find('/')?;
    let authority = &rest[..slash];
    if !is_clean_authority(authority) {
        return None;
    }
    // Drop any query string / fragment before segmenting the path.
    let path = &rest[slash..];
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (kind, id_index) = find_artifact_marker(&segments)?;
    if !segments[..=id_index]
        .iter()
        .all(|segment| is_clean_path_segment(segment))
    {
        return None;
    }
    let canonical_path = segments[..=id_index].join("/");
    Some(SessionArtifact {
        kind: kind.to_string(),
        value: format!("{scheme}://{authority}/{canonical_path}"),
    })
}

/// Locate the first PR/issue/MR marker in path segments, returning its kind and
/// the index of the numeric-id segment.
fn find_artifact_marker(segments: &[&str]) -> Option<(&'static str, usize)> {
    for i in 0..segments.len() {
        if segments[i] == "-"
            && i + 2 < segments.len()
            && segments[i + 1] == "merge_requests"
            && is_numeric(segments[i + 2])
        {
            return Some(("pull_request", i + 2));
        }
        if (segments[i] == "pull" || segments[i] == "pull-requests")
            && i + 1 < segments.len()
            && is_numeric(segments[i + 1])
        {
            return Some(("pull_request", i + 1));
        }
        if segments[i] == "issues" && i + 1 < segments.len() && is_numeric(segments[i + 1]) {
            return Some(("issue", i + 1));
        }
    }
    None
}

/// Extract a lowercase-hex commit SHA from a `git commit` summary line of the
/// form `[branch sha] message` (or `[branch (root-commit) sha] message`).
fn parse_commit_sha_line(line: &str) -> Option<String> {
    let inner = line.trim_start().strip_prefix('[')?;
    let close = inner.find(']')?;
    let token = inner[..close].split_whitespace().last()?;
    // Require lowercase hex AND at least one a-f letter. Real git short SHAs are
    // virtually always mixed hex; demanding a letter rejects all-numeric log
    // lines like `[INFO 1234567] starting` that would otherwise look like a SHA.
    let is_hex = token.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
    let has_hex_letter = token.chars().any(|c| matches!(c, 'a'..='f'));
    if (7..=40).contains(&token.len()) && is_hex && has_hex_letter {
        Some(token.to_string())
    } else {
        None
    }
}

fn is_clean_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return false;
    }
    match port {
        Some(port) => !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()),
        None => true,
    }
}

fn is_clean_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_numeric(segment: &str) -> bool {
    !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit())
}

fn codex_total_usage(value: &Value) -> Option<UsageTotals> {
    let root = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))?;
    let input_details = root
        .get("input_tokens_details")
        .or_else(|| root.get("prompt_tokens_details"));
    // Keep Codex input inclusive here. Snapshot provenance declares
    // `input_token_scope=inclusive_cached`, and backend ingest subtracts the
    // observed read/write subsets exactly once. Normalizing in both places
    // would undercount fresh input.
    let mut usage = UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens: u64_at(root, &["output_tokens"])
            .or_else(|| u64_at(root, &["outputTokens"]))
            .unwrap_or_default(),
        cache_read_tokens: u64_at(root, &["cache_read_tokens"])
            .or_else(|| u64_at(root, &["cached_input_tokens"]))
            .or_else(|| u64_at(root, &["cachedInputTokens"]))
            .or_else(|| input_details.and_then(|details| u64_at(details, &["cached_tokens"])))
            .unwrap_or_default(),
        // Current Codex JSONL exposes reads but not writes. Accept OpenAI's
        // newer cache-write aliases now so a future CLI can become complete
        // without another wire-contract change.
        cache_creation_5m_tokens: u64_at(root, &["cache_write_tokens"])
            .or_else(|| u64_at(root, &["cacheWriteTokens"]))
            .or_else(|| u64_at(root, &["cache_creation_tokens"]))
            .or_else(|| u64_at(root, &["cacheCreationInputTokens"]))
            .or_else(|| input_details.and_then(|details| u64_at(details, &["cache_write_tokens"])))
            .unwrap_or_default(),
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: u64_at(root, &["reasoning_output_tokens"]).unwrap_or_default(),
        unattributed_total_tokens: 0,
        request_count: u64_at(root, &["request_count"])
            .or_else(|| u64_at(root, &["requests"]))
            .unwrap_or(1),
        costs: UsageCosts::default(),
    };
    if usage.request_count == 0 {
        usage.request_count = 1;
    }
    Some(usage)
}

/// This response's effective input context from a Codex `token_count` event:
/// `last_token_usage.input_tokens`, the usage of the single API response the
/// event reports (the sibling `total_token_usage` is the session-wide running
/// sum). Already includes the cached prefix — `cached_input_tokens` is a subset
/// of `input_tokens`, not an addend — so it is the window-comparable context on
/// its own. `None` for lines carrying no per-response usage, and 0 for the
/// zero-usage event Codex emits at a compaction.
///
/// Pointer fallbacks mirror `codex_total_usage` so both survive the same
/// rollout-shape variations.
fn codex_last_turn_input_context(value: &Value) -> Option<u64> {
    let root = value
        .pointer("/token_count/info/last_token_usage")
        .or_else(|| value.pointer("/payload/info/last_token_usage"))
        .or_else(|| value.pointer("/payload/last_token_usage"))
        .or_else(|| value.pointer("/last_token_usage"))?;
    u64_at(root, &["input_tokens"]).or_else(|| u64_at(root, &["inputTokens"]))
}

fn codex_total_usage_has_request_count(value: &Value) -> bool {
    let Some(root) = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))
    else {
        return false;
    };
    u64_at(root, &["request_count"])
        .or_else(|| u64_at(root, &["requests"]))
        .is_some()
}

fn apply_pi_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    let event_type = string_at(value, &["type"]);
    match event_type.as_deref() {
        Some("custom") => {
            if let Some(selector) = pi_selector_from_custom(value) {
                accumulator.set_selector(selector);
            }
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("session") => {
            if accumulator.source_session_id.is_none() {
                accumulator.source_session_id =
                    string_at(value, &["session_id"]).or_else(|| string_at(value, &["sessionId"]));
            }
            accumulator.set_workspace_hash(string_at(value, &["cwd"]));
            accumulator.note_time(string_at(value, &["timestamp"]));
        }
        Some("message") => {
            // Pi user prompts arrive as `type: "message"` with role: "user". The
            // backend's message_end event omits prompt text, so this is the only
            // chance to grab a first-prompt title fallback.
            if string_eq_at(value, &["role"], "user") {
                accumulator.set_first_prompt_title(pi_message_text(value));
            }
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("message_end") => {
            let timestamp = pi_message_end_timestamp(value);
            let model = string_at(value, &["message", "model"]);
            accumulator.set_model(model.clone());
            if let Some(usage) = pi_message_end_usage(value) {
                let mut selector = accumulator.current_selector.clone();
                selector.merge(pi_selector_from_message_end(value));
                accumulator.add_usage_with_selector(
                    model,
                    usage,
                    selector,
                    timestamp.as_deref(),
                    // Pi does not emit a per-turn reasoning effort tier.
                    None,
                );
            }
            accumulator.note_time(timestamp);
        }
        _ => {}
    }
}

fn pi_message_text(value: &Value) -> Option<String> {
    string_at(value, &["content"])
        .or_else(|| string_at(value, &["text"]))
        .or_else(|| string_at(value, &["message", "content"]))
        .or_else(|| text_from_array(value.get("content")))
}

fn pi_timestamp_field(value: &Value) -> Option<String> {
    string_at(value, &["timestamp"])
        .or_else(|| pi_ms_timestamp(value.get("timestamp")))
        .or_else(|| pi_ms_timestamp(value.pointer("/message/timestamp")))
}

fn pi_message_end_timestamp(value: &Value) -> Option<String> {
    pi_ms_timestamp(value.pointer("/message/timestamp"))
        .or_else(|| string_at(value, &["message", "timestamp"]))
        .or_else(|| string_at(value, &["timestamp"]))
}

fn pi_ms_timestamp(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let ms = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    }?;
    Some(format_rfc3339_millis(ms))
}

fn format_rfc3339_millis(ms: i64) -> String {
    let total_secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000) as u32;
    let days = total_secs.div_euclid(86_400);
    let time_of_day = total_secs.rem_euclid(86_400) as u32;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn activity_bucket_from_timestamp(value: &str) -> Option<(String, String)> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    let bucket_seconds = utc.unix_timestamp().div_euclid(3600) * 3600;
    let bucket_start = OffsetDateTime::from_unix_timestamp(bucket_seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()?;
    let normalized_timestamp = utc.format(&Rfc3339).ok()?;
    Some((bucket_start, normalized_timestamp))
}

// Howard Hinnant's civil_from_days. Returns (year, month, day) from days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn pi_message_end_usage(value: &Value) -> Option<UsageTotals> {
    let usage = value.pointer("/message/usage")?;
    // Pi is multi-provider (Anthropic / OpenAI / Gemini). When the underlying
    // model is Anthropic and Pi exposes the nested `cacheCreation` object with
    // ephemeral_5m / ephemeral_1h, prefer that. Otherwise the flat `cacheWrite`
    // total routes to the 5m bucket (Anthropic default TTL, and the safer guess
    // for non-Anthropic providers where the distinction does not apply).
    let (cache_5m, cache_1h) = pi_cache_creation_split(usage);
    let totals = UsageTotals {
        input_tokens: u64_at(usage, &["input"]).unwrap_or_default(),
        output_tokens: u64_at(usage, &["output"]).unwrap_or_default(),
        cache_read_tokens: u64_at(usage, &["cacheRead"])
            .or_else(|| u64_at(usage, &["cache_read"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: u64_at(usage, &["reasoning"]).unwrap_or_default(),
        unattributed_total_tokens: 0,
        request_count: 1,
        costs: pi_usage_costs(usage),
    };
    Some(totals)
}

fn pi_cache_creation_split(usage: &Value) -> (u64, u64) {
    if let Some(nested) = usage
        .get("cacheCreation")
        .or_else(|| usage.get("cache_creation"))
    {
        let cache_5m = u64_at(nested, &["ephemeral_5m_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
            .unwrap_or_default();
        let cache_1h = u64_at(nested, &["ephemeral_1h_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
            .unwrap_or_default();
        if cache_5m > 0 || cache_1h > 0 {
            return (cache_5m, cache_1h);
        }
    }
    let flat = u64_at(usage, &["cacheWrite"])
        .or_else(|| u64_at(usage, &["cache_write"]))
        .unwrap_or_default();
    let cache_1h = u64_at(usage, &["cacheWrite1h"])
        .or_else(|| u64_at(usage, &["cache_write_1h"]))
        .unwrap_or_default()
        .min(flat);
    (flat.saturating_sub(cache_1h), cache_1h)
}

fn pi_usage_costs(usage: &Value) -> UsageCosts {
    let Some(cost) = usage.get("cost") else {
        return UsageCosts {
            observed: true,
            ..UsageCosts::default()
        };
    };
    let total = usd_picos_at(cost, &["total"]);
    let input = usd_picos_at(cost, &["input"]);
    let output = usd_picos_at(cost, &["output"]);
    let cache_read = usd_picos_at(cost, &["cacheRead", "cache_read"]);
    let cache_creation = usd_picos_at(cost, &["cacheWrite", "cache_write"]);
    let reported = [total, input, output, cache_read, cache_creation]
        .iter()
        .any(Option::is_some);
    if !reported {
        return UsageCosts {
            observed: true,
            ..UsageCosts::default()
        };
    }
    UsageCosts {
        observed: true,
        reported: true,
        total,
        input,
        output,
        cache_read,
        cache_creation,
    }
}

fn usd_picos_at(value: &Value, keys: &[&str]) -> Option<u128> {
    let raw = keys.iter().find_map(|key| value.get(*key))?;
    let parsed = match raw {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse::<f64>().ok(),
        _ => None,
    }?;
    if !parsed.is_finite() || parsed < 0.0 {
        return None;
    }
    Some((parsed * USD_PICO_SCALE as f64).round() as u128)
}

fn usd_picos_string(value: u128) -> String {
    let whole = value / USD_PICO_SCALE;
    let fraction = value % USD_PICO_SCALE;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut fraction_text = format!("{fraction:012}");
    while fraction_text.ends_with('0') {
        fraction_text.pop();
    }
    format!("{whole}.{fraction_text}")
}

/// Identity of the API response behind one Claude Code JSONL record, used to
/// count `message.usage` once per response instead of once per content-block
/// record. Keyed on the (`message.id`, `requestId`) PAIR when both exist —
/// conservative: if either differs, the line is treated as a distinct
/// response — falling back to whichever is present alone. `None` (neither id)
/// means no dedup is possible and the caller counts the line.
fn claude_code_usage_dedup_key(value: &Value) -> Option<String> {
    let message_id = string_at(value, &["message", "id"]);
    let request_id = string_at(value, &["requestId"]).or_else(|| string_at(value, &["request_id"]));
    match (message_id, request_id) {
        (Some(message_id), Some(request_id)) => {
            Some(format!("p\u{1f}{message_id}\u{1f}{request_id}"))
        }
        (Some(message_id), None) => Some(format!("m\u{1f}{message_id}")),
        (None, Some(request_id)) => Some(format!("r\u{1f}{request_id}")),
        (None, None) => None,
    }
}

fn claude_code_delta_usage(value: &Value) -> Option<UsageTotals> {
    let root = value
        .pointer("/message/usage")
        .or_else(|| value.pointer("/usage"))
        .or_else(|| value.pointer("/payload/usage"))?;
    let (cache_5m, cache_1h) = claude_code_cache_creation_split(root);
    let usage = UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens: u64_at(root, &["output_tokens"])
            .or_else(|| u64_at(root, &["outputTokens"]))
            .unwrap_or_default(),
        cache_read_tokens: u64_at(root, &["cache_read_input_tokens"])
            .or_else(|| u64_at(root, &["cache_read_tokens"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: u64_at(root, &["reasoning_output_tokens"]).unwrap_or_default(),
        unattributed_total_tokens: 0,
        request_count: 1,
        costs: UsageCosts::default(),
    };
    Some(usage)
}

// Anthropic exposes prompt-cache writes as `usage.cache_creation.ephemeral_5m_input_tokens`
// and `ephemeral_1h_input_tokens` (the 5m / 1h TTL split). The pricing page rates those
// at 1.25x and 2x base input respectively, so the split is load-bearing for cost. If only
// the flat `cache_creation_input_tokens` is present (older transcripts), default to the
// 5m bucket which is Anthropic's default TTL.
fn claude_code_cache_creation_split(root: &Value) -> (u64, u64) {
    if let Some(nested) = root
        .get("cache_creation")
        .or_else(|| root.get("cacheCreation"))
    {
        let cache_5m = u64_at(nested, &["ephemeral_5m_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
            .unwrap_or_default();
        let cache_1h = u64_at(nested, &["ephemeral_1h_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
            .unwrap_or_default();
        if cache_5m > 0 || cache_1h > 0 {
            return (cache_5m, cache_1h);
        }
    }
    let flat = u64_at(root, &["cache_creation_input_tokens"])
        .or_else(|| u64_at(root, &["cache_creation_tokens"]))
        .unwrap_or_default();
    (flat, 0)
}

#[derive(Debug, Clone)]
struct CandidateFile {
    path: PathBuf,
    size_bytes: u64,
    modified_unix_seconds: u64,
    source_file_fingerprint: String,
}

impl CodexTitleMetadata {
    fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut metadata = Self::default();
        let mut sidecar_parts = Vec::new();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }

        for codex_dir in codex_dirs {
            let config_path = codex_dir.join("config.toml");
            sidecar_parts.push(sidecar_stat_fingerprint(&config_path));
            metadata
                .default_selector
                .merge(load_codex_config_selector(&config_path));

            let state_path = codex_dir.join("state_5.sqlite");
            sidecar_parts.push(sidecar_stat_fingerprint(&state_path));
            load_codex_sqlite_titles(&state_path, &mut metadata.titles);
            load_codex_sqlite_state_threads(&state_path, &mut metadata.state_threads);

            let index_path = codex_dir.join("session_index.jsonl");
            sidecar_parts.push(sidecar_stat_fingerprint(&index_path));
            load_codex_session_index_titles(&index_path, &mut metadata.titles);
        }

        metadata.sidecar_fingerprint = sha256_hex_owned(&sidecar_parts);
        metadata
    }
}

// `logs_2.sqlite` can be ~1GB+ with a live WAL and a concurrent writer (Codex
// itself). The read is best-effort, read-only, time-bounded, and row-capped so
// it can never disrupt Codex or stall the snapshot cycle. Any error (missing
// file, locked DB, schema churn) yields an empty map and every turn then
// classifies as standard — the read is never load-bearing for collection.
const CODEX_LOGS2_MAX_ROWS: i64 = 50_000;
const CODEX_LOGS2_BUSY_TIMEOUT_MS: u64 = 400;
// The trace read window pads the session backfill window so a turn near a
// window edge still finds its request row. Capped so a stale/huge DB can never
// widen the scan unboundedly.
const CODEX_LOGS2_WINDOW_PAD_DAYS: u64 = 1;
const CODEX_LOGS2_MAX_WINDOW_DAYS: u64 = 14;

impl CodexTurnTraceMap {
    fn load_from_roots(roots: &[PathBuf], backfill_window_days: u64) -> Self {
        let mut map = Self::default();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }
        let since_epoch = codex_logs2_since_epoch(backfill_window_days);
        for codex_dir in codex_dirs {
            // The live DB lives directly under ~/.codex; a `sqlite/` subdir copy
            // exists on some installs. Read whichever is present.
            for db_path in [
                codex_dir.join("logs_2.sqlite"),
                codex_dir.join("sqlite").join("logs_2.sqlite"),
            ] {
                load_codex_logs2_priority_turns(&db_path, since_epoch, &mut map.priority_turns);
            }
        }
        map
    }
}

fn codex_logs2_since_epoch(backfill_window_days: u64) -> i64 {
    let window_days = backfill_window_days
        .saturating_add(CODEX_LOGS2_WINDOW_PAD_DAYS)
        .min(CODEX_LOGS2_MAX_WINDOW_DAYS);
    let span = window_days.saturating_mul(86_400);
    let now = unix_seconds(SystemTime::now()).unwrap_or(0);
    now.saturating_sub(span) as i64
}

fn load_codex_logs2_priority_turns(
    path: &Path,
    since_epoch: i64,
    priority_turns: &mut BTreeSet<String>,
) {
    if !path.exists() {
        return;
    }
    // URI `mode=ro` so a WAL database with a concurrent writer is safe to read.
    let uri = format!("file:{}?mode=ro", path.to_string_lossy());
    let Ok(connection) = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    ) else {
        return;
    };
    let _ = connection.busy_timeout(std::time::Duration::from_millis(
        CODEX_LOGS2_BUSY_TIMEOUT_MS,
    ));
    // Only `response.create` request rows carry the *requested* service_tier.
    // The `idx_logs_ts` index bounds the scan to the recent window; the LIKE
    // then filters to the sparse request rows (hundreds, not the full table).
    let Ok(mut statement) = connection.prepare(
        "SELECT feedback_log_body FROM logs \
         WHERE ts >= ?1 AND feedback_log_body LIKE '%websocket request:%' \
         ORDER BY ts DESC LIMIT ?2",
    ) else {
        return;
    };
    let Ok(rows) = statement.query_map(
        rusqlite::params![since_epoch, CODEX_LOGS2_MAX_ROWS],
        |row| row.get::<_, String>(0),
    ) else {
        return;
    };
    for body in rows.flatten() {
        if let Some(turn_id) = codex_logs2_priority_turn_from_body(&body) {
            priority_turns.insert(turn_id);
        }
    }
}

/// Parse one `feedback_log_body` row. Returns the `turn_id` when the row is a
/// `response.create` request that asked for `service_tier="priority"`.
///
/// Privacy: the row's JSON payload contains the full prompt (`input`,
/// `instructions`, `tools`). We read ONLY the `type` and `service_tier` fields
/// and the `turn.id` tracing span; no prompt or output content is retained.
fn codex_logs2_priority_turn_from_body(body: &str) -> Option<String> {
    const MARKER: &str = "websocket request:";
    let idx = body.rfind(MARKER)?;
    let prefix = &body[..idx];
    let json_text = body[idx + MARKER.len()..].trim();
    let value: Value = serde_json::from_str(json_text).ok()?;
    if value.get("type").and_then(Value::as_str) != Some("response.create") {
        return None;
    }
    let tier = value.get("service_tier").and_then(Value::as_str)?;
    if !tier.eq_ignore_ascii_case("priority") {
        return None;
    }
    codex_logs2_span_field(prefix, "turn.id")
        .or_else(|| codex_logs2_span_field(prefix, "turn_id"))
        .filter(|turn_id| !turn_id.is_empty())
}

/// Extract a `key=value` field from a tracing-span prefix, where the value is
/// terminated by whitespace, `,`, `{`, or `}`. The key must sit on an
/// identifier boundary so `turn_id` does not match inside `parent_turn_id`.
fn codex_logs2_span_field(prefix: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let mut search_start = 0;
    while let Some(rel) = prefix[search_start..].find(&needle) {
        let at = search_start + rel;
        let boundary = at == 0
            || !prefix[..at]
                .chars()
                .next_back()
                .map(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                .unwrap_or(false);
        let value_start = at + needle.len();
        if boundary {
            let value: String = prefix[value_start..]
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, ',' | '{' | '}'))
                .collect();
            if !value.is_empty() {
                return Some(value);
            }
        }
        search_start = value_start;
    }
    None
}

fn load_codex_session_index_titles(
    path: &Path,
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(|line| line.ok()) {
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = string_at(&value, &["id"]) else {
            continue;
        };
        insert_codex_sidecar_title(
            titles,
            id,
            string_at(&value, &["thread_name"])
                .or_else(|| string_at(&value, &["title"]))
                .or_else(|| string_at(&value, &["name"])),
            "session_index",
            true,
        );
    }
}

fn load_codex_sqlite_titles(path: &Path, titles: &mut BTreeMap<String, CodexTitleCandidate>) {
    let Ok(connection) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return;
    };
    let Ok(mut statement) =
        connection.prepare("SELECT id, title FROM threads WHERE title IS NOT NULL AND title != ''")
    else {
        return;
    };
    let Ok(rows) = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) else {
        return;
    };
    for row in rows.flatten() {
        insert_codex_sidecar_title(titles, row.0, Some(row.1), "session_index", false);
    }
}

fn load_codex_sqlite_state_threads(
    path: &Path,
    state_threads: &mut BTreeMap<String, CodexStateThread>,
) {
    let Ok(connection) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return;
    };
    let columns = sqlite_table_columns(&connection, "threads");
    if !columns.contains("id") || !columns.contains("tokens_used") {
        return;
    }

    let sql = format!(
        "SELECT id, {}, {}, {}, {}, {}, {}, {}, {} FROM threads WHERE tokens_used > 0",
        sqlite_select_expr(&columns, "title", "NULL"),
        sqlite_select_expr(&columns, "tokens_used", "0"),
        sqlite_select_expr(&columns, "archived", "0"),
        sqlite_select_expr(&columns, "created_at", "NULL"),
        sqlite_select_expr(&columns, "updated_at", "NULL"),
        sqlite_select_expr(&columns, "created_at_ms", "NULL"),
        sqlite_select_expr(&columns, "updated_at_ms", "NULL"),
        sqlite_select_expr(&columns, "model", "NULL"),
    );
    let Ok(mut statement) = connection.prepare(sql.as_str()) else {
        return;
    };
    let Ok(rows) = statement.query_map([], |row| {
        let id: String = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let tokens_used = non_negative_i64_to_u64(row.get::<_, i64>(2).unwrap_or_default());
        let archived = row.get::<_, i64>(3).unwrap_or_default() != 0;
        let created_at =
            codex_state_timestamp(row.get(6).ok().flatten(), row.get(4).ok().flatten());
        let updated_at =
            codex_state_timestamp(row.get(7).ok().flatten(), row.get(5).ok().flatten());
        let model: Option<String> = row.get(8)?;
        Ok((
            id,
            CodexStateThread {
                title,
                tokens_used,
                archived,
                created_at,
                updated_at,
                model,
            },
        ))
    }) else {
        return;
    };
    for (id, thread) in rows.flatten() {
        state_threads.insert(id, thread);
    }
}

fn sqlite_table_columns(connection: &Connection, table_name: &str) -> BTreeSet<String> {
    let Ok(mut statement) = connection.prepare(format!("PRAGMA table_info({table_name})").as_str())
    else {
        return BTreeSet::new();
    };
    let Ok(rows) = statement.query_map([], |row| row.get::<_, String>(1)) else {
        return BTreeSet::new();
    };
    rows.flatten().collect()
}

fn sqlite_select_expr(columns: &BTreeSet<String>, column: &str, fallback: &str) -> String {
    if columns.contains(column) {
        column.to_string()
    } else {
        format!("{fallback} AS {column}")
    }
}

fn non_negative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn codex_state_timestamp(ms: Option<i64>, seconds: Option<i64>) -> Option<String> {
    let timestamp_ms = ms.or_else(|| seconds.map(|value| value.saturating_mul(1_000)))?;
    Some(format_rfc3339_millis(timestamp_ms))
}

fn load_codex_config_selector(path: &Path) -> SelectorCapture {
    let Ok(file) = File::open(path) else {
        return SelectorCapture::default();
    };
    let mut raw = String::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            return SelectorCapture::default();
        };
        raw.push_str(line.as_str());
        raw.push('\n');
    }
    let Ok(document) = raw.parse::<DocumentMut>() else {
        return SelectorCapture::default();
    };
    let mut selector = SelectorCapture::default();
    if let Some(service_tier) = document
        .get("service_tier")
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())
    {
        let value = Value::String(service_tier.to_string());
        insert_selector_raw(
            &mut selector,
            "service_tier",
            "codex.config.service_tier",
            &value,
        );
    }
    if let Some(fast_mode) = document
        .get("features")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_mode"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
    {
        let value = Value::Bool(fast_mode);
        insert_selector_raw(
            &mut selector,
            "mode",
            "codex.config.features.fast_mode",
            &value,
        );
    }
    let top_level_fast_default_opt_out = document
        .get("fast_default_opt_out")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let notice_fast_default_opt_out = document
        .get("notice")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_default_opt_out"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let fast_default_opt_out_source = if top_level_fast_default_opt_out {
        Some("codex.config.fast_default_opt_out")
    } else if notice_fast_default_opt_out {
        Some("codex.config.notice.fast_default_opt_out")
    } else {
        None
    };
    if selector.is_empty() {
        let Some(source) = fast_default_opt_out_source else {
            return selector;
        };
        let standard = Value::String("standard".to_string());
        insert_selector_raw(&mut selector, "service_tier", source, &standard);
        insert_selector_raw(&mut selector, "mode", source, &standard);
    }
    selector
}

/// Display-safe Codex runtime defaults parsed from `~/.codex/config.toml`.
///
/// These are configured defaults, not evidence a session actually ran with
/// them. `selector_context`/`selector_sources` carry the raw config-derived
/// values with their `codex.config.*` provenance so downstream layers can keep
/// defaults separate from observed selector evidence.
#[derive(Debug, Clone, Default)]
pub(crate) struct CodexConfigDefaults {
    pub model: Option<String>,
    pub service_tier: Option<String>,
    pub reasoning_effort: Option<String>,
    pub approval_policy: Option<String>,
    pub fast_mode: Option<bool>,
    pub fast_default_opt_out: bool,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
}

impl CodexConfigDefaults {
    /// Effective Fast default for display. `service_tier` is authoritative when
    /// set; otherwise fall back to the legacy `[features].fast_mode` flag minus
    /// any fast-default opt-out. Returns `None` when nothing in config implies a
    /// tier, so the UI can stay quiet rather than guess.
    pub(crate) fn display_fast_mode(&self) -> Option<bool> {
        if let Some(tier) = self.service_tier.as_deref() {
            match tier.trim().to_ascii_lowercase().as_str() {
                "priority" | "fast" | "premium" => return Some(true),
                "default" | "standard" | "flex" | "batch" => return Some(false),
                _ => {}
            }
        }
        match self.fast_mode {
            Some(true) => Some(!self.fast_default_opt_out),
            Some(false) => Some(false),
            None => {
                if self.fast_default_opt_out {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }
}

/// Read Codex `config.toml` into display-safe runtime defaults. Returns `None`
/// when the file is missing, unparseable, or carries no relevant keys.
pub(crate) fn load_codex_config_defaults(path: &Path) -> Option<CodexConfigDefaults> {
    // Read line-by-line to satisfy the streaming guard (no whole-file reads in
    // this module); config.toml is small, so the accumulated string is fine.
    let file = File::open(path).ok()?;
    let mut raw = String::new();
    for line in BufReader::new(file).lines() {
        let line = line.ok()?;
        raw.push_str(line.as_str());
        raw.push('\n');
    }
    let document = raw.parse::<DocumentMut>().ok()?;
    let read_top_str = |key: &str| {
        document
            .get(key)
            .and_then(Item::as_value)
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let model = read_top_str("model").or_else(|| read_top_str("default_model"));
    let service_tier = read_top_str("service_tier");
    let reasoning_effort =
        read_top_str("model_reasoning_effort").or_else(|| read_top_str("reasoning_effort"));
    let approval_policy = read_top_str("approval_policy");
    let fast_mode = document
        .get("features")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_mode"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool());
    let top_level_opt_out = document
        .get("fast_default_opt_out")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let notice_opt_out = document
        .get("notice")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_default_opt_out"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let fast_default_opt_out = top_level_opt_out || notice_opt_out;
    let selector = load_codex_config_selector(path);
    let has_any = model.is_some()
        || service_tier.is_some()
        || reasoning_effort.is_some()
        || approval_policy.is_some()
        || fast_mode.is_some()
        || fast_default_opt_out
        || !selector.context.is_empty();
    if !has_any {
        return None;
    }
    Some(CodexConfigDefaults {
        model,
        service_tier,
        reasoning_effort,
        approval_policy,
        fast_mode,
        fast_default_opt_out,
        selector_context: selector.context,
        selector_sources: selector.sources,
    })
}

fn insert_codex_sidecar_title(
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
    id: String,
    title: Option<String>,
    source: &str,
    overwrite: bool,
) {
    let id = id.trim();
    if id.is_empty() {
        return;
    }
    let Some(title) = title.and_then(|value| normalize_display_title(value, source)) else {
        return;
    };
    if !overwrite && titles.contains_key(id) {
        return;
    }
    titles.insert(
        id.to_string(),
        CodexTitleCandidate {
            title,
            source: source.to_string(),
        },
    );
}

fn sidecar_stat_fingerprint(path: &Path) -> String {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            format!(
                "{}:{}:{}",
                path.to_string_lossy(),
                metadata.len(),
                modified_unix_seconds
            )
        }
        Err(_) => format!("{}:missing", path.to_string_lossy()),
    }
}

fn collect_recent_jsonl_files(
    source: SnapshotSource,
    root: &Path,
    files: &mut Vec<CandidateFile>,
    source_fingerprint_context: &str,
    backfill_window_days: u64,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))? {
        let entry = entry.with_context(|| format!("read directory entry {}", root.display()))?;
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            collect_recent_jsonl_files(
                source,
                &path,
                files,
                source_fingerprint_context,
                backfill_window_days,
            )?;
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap_or_default();
        if !is_recent_enough(modified_unix_seconds, backfill_window_days) {
            continue;
        }
        // Skip pathologically large transcripts before they ever reach the
        // parser. metadata.len() is already read for fingerprinting, so this is
        // free; an oversized file is dropped from the candidate set rather than
        // opened, keeping the scan's memory bounded without aborting it.
        if metadata.len() > max_jsonl_file_bytes(source) {
            continue;
        }
        files.push(CandidateFile {
            source_file_fingerprint: source_file_fingerprint_with_context(
                &path,
                metadata.len(),
                modified_unix_seconds,
                source.parser_version(),
                source_fingerprint_context,
            ),
            path,
            size_bytes: metadata.len(),
            modified_unix_seconds,
        });
    }
    Ok(())
}

fn is_recent_enough(modified_unix_seconds: u64, backfill_window_days: u64) -> bool {
    let Some(now) = unix_seconds(SystemTime::now()) else {
        return true;
    };
    is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
}

fn is_recent_enough_at(
    modified_unix_seconds: u64,
    now_unix_seconds: u64,
    backfill_window_days: u64,
) -> bool {
    let window_seconds = effective_backfill_window_days(backfill_window_days) * 24 * 60 * 60;
    modified_unix_seconds >= now_unix_seconds.saturating_sub(window_seconds)
}

fn effective_backfill_window_days(requested_backfill_window_days: u64) -> u64 {
    requested_backfill_window_days.min(BACKFILL_WINDOW_DAYS)
}

fn max_jsonl_file_bytes(source: SnapshotSource) -> u64 {
    match source {
        SnapshotSource::Codex => MAX_CODEX_JSONL_FILE_BYTES,
        SnapshotSource::ClaudeCode | SnapshotSource::Pi => MAX_JSONL_FILE_BYTES,
    }
}

fn unix_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

impl ScanIndex {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let file =
            File::open(path).with_context(|| format!("open scan index {}", path.display()))?;
        match serde_json::from_reader(file) {
            Ok(index) => Ok(index),
            Err(error) if !error.is_io() => {
                // The index is only a local incremental-scan optimization. A
                // crash or overlapping daemon shutdown must not permanently
                // block collection because the JSON was left partial. Start
                // from an empty index; the next successful scan rebuilds it
                // from source files and replaces the bad file atomically.
                eprintln!("local snapshot scan index was invalid; rebuilding");
                Ok(Self::default())
            }
            Err(error) => {
                Err(error).with_context(|| format!("parse scan index {}", path.display()))
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create scan index directory {}", parent.display()))?;
        }
        // Never truncate the live index in place. The process id keeps a
        // briefly overlapping old/new daemon pair from sharing a temp file;
        // in-process snapshot scans are separately serialized.
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file = File::create(&temp_path)
            .with_context(|| format!("create scan index temp {}", temp_path.display()))?;
        serde_json::to_writer_pretty(&mut file, self)
            .with_context(|| format!("write scan index temp {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync scan index temp {}", temp_path.display()))?;
        fs::rename(&temp_path, path)
            .with_context(|| format!("replace scan index {}", path.display()))
    }

    fn should_process(&self, candidate: &CandidateFile) -> bool {
        let key = local_index_key(&candidate.path);
        self.files.get(&key).map_or(true, |entry| {
            entry.size_bytes != candidate.size_bytes
                || entry.modified_unix_seconds != candidate.modified_unix_seconds
                || entry.source_file_fingerprint != candidate.source_file_fingerprint
        })
    }

    fn record(&mut self, candidate: CandidateFile, last_snapshot_fingerprint: Option<String>) {
        self.files.insert(
            local_index_key(&candidate.path),
            ScanIndexEntry {
                size_bytes: candidate.size_bytes,
                modified_unix_seconds: candidate.modified_unix_seconds,
                source_file_fingerprint: candidate.source_file_fingerprint,
                last_snapshot_fingerprint,
            },
        );
    }
}

pub fn source_file_fingerprint(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
) -> String {
    source_file_fingerprint_with_context(
        path,
        size_bytes,
        modified_unix_seconds,
        parser_version,
        "",
    )
}

fn source_file_fingerprint_with_context(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
    source_fingerprint_context: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_seconds.to_string(),
        parser_version,
        source_fingerprint_context,
    ])
}

fn local_index_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn normalize_title(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.chars().take(255).collect())
    }
}

fn normalize_display_title(value: String, source: &str) -> Option<String> {
    let normalized = normalize_title(value)?;
    if is_safe_display_title(&normalized, source) {
        Some(normalized)
    } else {
        None
    }
}

fn first_prompt_display_title(value: String) -> Option<String> {
    let raw = value.trim();
    if raw.is_empty() || contains_blocked_prompt_fragment(raw) {
        return None;
    }
    let first_line = raw.lines().find_map(|line| {
        let trimmed = line
            .trim()
            .trim_start_matches(['#', '-', '*', '>', ' '])
            .trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })?;
    let normalized = normalize_title(first_line.to_string())?;
    if normalized.chars().count() > 80 || normalized.split_whitespace().count() > 12 {
        return None;
    }
    normalize_display_title(normalized, "first_prompt")
}

fn is_safe_display_title(value: &str, source: &str) -> bool {
    let char_count = value.chars().count();
    if char_count == 0 || char_count > 120 {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "assistant"
            | "chat"
            | "codex"
            | "codex session"
            | "conversation"
            | "new chat"
            | "new session"
            | "session"
            | "untitled"
            | "untitled session"
    ) {
        return false;
    }
    if is_codex_tool_call_name(&lowered)
        || looks_like_raw_identifier(value)
        || looks_like_shell_command(&lowered)
        || looks_like_setup_text(&lowered)
        || contains_blocked_prompt_fragment(value)
    {
        return false;
    }
    if source == "first_prompt"
        && lowered.len() <= 8
        && matches!(
            lowered.as_str(),
            "fix" | "fix it" | "help" | "help me" | "question"
        )
    {
        return false;
    }
    true
}

fn contains_blocked_prompt_fragment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<instructions>")
        || lowered.contains("<environment_context>")
        || lowered.contains("agents.md instructions")
        || lowered.contains("a previous agent produced the plan below")
        || (lowered.contains("## summary") && lowered.contains("## test plan"))
        || lowered.contains("knowledge cutoff:")
        || lowered.contains("current date:")
}

fn looks_like_setup_text(lowered: &str) -> bool {
    lowered.starts_with("you are ")
        || lowered.starts_with("system:")
        || lowered.starts_with("developer:")
        || lowered.starts_with("assistant:")
        || lowered.starts_with("tool:")
        || lowered.starts_with("environment_context")
        || lowered.starts_with("<environment_context")
        || lowered.starts_with("<instructions")
}

fn looks_like_shell_command(lowered: &str) -> bool {
    const COMMAND_PREFIXES: &[&str] = &[
        "$ ", "cargo ", "cat ", "cd ", "curl ", "docker ", "gcloud ", "git ", "jq ", "kubectl ",
        "ls ", "npm ", "pnpm ", "python ", "python3 ", "rg ", "sed ", "sqlite3 ", "uv ", "wt ",
        "yarn ",
    ];
    COMMAND_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

fn is_codex_tool_call_name(lowered: &str) -> bool {
    const TOOL_NAMES: &[&str] = &[
        "apply_patch",
        "close_agent",
        "create_goal",
        "exec_command",
        "find",
        "get_goal",
        "imagegen",
        "list_mcp_resource_templates",
        "list_mcp_resources",
        "open",
        "parallel",
        "read_mcp_resource",
        "request_user_input",
        "resume_agent",
        "screenshot",
        "send_input",
        "spawn_agent",
        "tool_search_tool",
        "update_goal",
        "update_plan",
        "view_image",
        "wait_agent",
        "weather",
        "write_stdin",
    ];
    const TOOL_PREFIXES: &[&str] = &[
        "functions.",
        "image_gen.",
        "multi_tool_use.",
        "tool_search.",
        "web.",
    ];
    TOOL_NAMES.contains(&lowered)
        || TOOL_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
}

fn looks_like_raw_identifier(value: &str) -> bool {
    let trimmed = value.trim();
    if is_uuid_like(trimmed) {
        return true;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("rollout-") && lowered.len() >= 44 {
        return true;
    }
    if lowered.starts_with("session_") || lowered.starts_with("sess_") {
        return true;
    }
    let has_space = trimmed.chars().any(char::is_whitespace);
    let ascii_token = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'));
    let has_digit = trimmed.chars().any(|ch| ch.is_ascii_digit());
    !has_space && ascii_token && has_digit && trimmed.len() >= 24
}

fn is_uuid_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn codex_session_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if stem.len() >= 36 {
        let suffix = &stem[stem.len() - 36..];
        if is_uuid_like(suffix) {
            return Some(suffix.to_string());
        }
    }
    None
}

/// Claude Code Task-tool subagents write their transcript to
/// `<projectDir>/<parentSessionId>/subagents/agent-<agentId>.jsonl`, and every
/// line inside is stamped with the *parent's* `sessionId`. Left alone, the
/// subagent's `source_session_id` therefore equals the parent's and it collapses
/// into the human-started parent session -- so its `isSidechain=true` origin
/// never stands up as its own (ai_agent) session on the backend.
///
/// Detect the subagent transcript by its enclosing `subagents` directory and
/// mint a distinct session id `<parentSessionId>_<agentFileStem>`. The id must
/// stay URL-path-safe: the backend uses `source_session_id` verbatim as its
/// `Session.session_id`, which rides in `/sessions/{session_id}/...` routes, so
/// the join uses `_` (never `/`) and every component is already lowercase.
/// Ordinary top-level transcripts return `None` and keep their raw `sessionId`.
fn claude_subagent_source_session_id(path: &Path, parent_session_id: &str) -> Option<String> {
    if path.parent()?.file_name()?.to_str()? != "subagents" {
        return None;
    }
    let agent_file_stem = path.file_stem()?.to_str()?;
    if agent_file_stem.is_empty() {
        return None;
    }
    Some(format!("{parent_session_id}_{agent_file_stem}"))
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn string_eq_at(value: &Value, path: &[&str], expected: &str) -> bool {
    string_at(value, path).is_some_and(|value| value == expected)
}

// Per-turn Codex reasoning effort tier. Codex emits it co-located with the
// turn's `total_token_usage` (token_count.info / payload.info) and also on the
// `turn_context` payload (directly as `effort` or nested under
// collaboration_mode.settings.reasoning_effort). Read the usage-co-located form
// first so the effort attaches to the same turn's usage row.
fn codex_reasoning_effort(value: &Value) -> Option<String> {
    string_at(value, &["token_count", "info", "reasoning_effort"])
        .or_else(|| string_at(value, &["payload", "info", "reasoning_effort"]))
        .or_else(|| string_at(value, &["turn_context", "payload", "effort"]))
        .or_else(|| string_at(value, &["payload", "effort"]))
        .or_else(|| {
            string_at(
                value,
                &[
                    "turn_context",
                    "payload",
                    "collaboration_mode",
                    "settings",
                    "reasoning_effort",
                ],
            )
        })
        // Rollout `turn_context` lines carry `payload` at the top level (no
        // wrapping `turn_context` key) — mirror how the model field is read via
        // both `turn_context.payload.model` and the unwrapped `payload.model`.
        .or_else(|| {
            string_at(
                value,
                &[
                    "payload",
                    "collaboration_mode",
                    "settings",
                    "reasoning_effort",
                ],
            )
        })
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    }
}

fn sha256_hex(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_hex_owned(parts: &[String]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

pub fn paths_from_events(paths: impl IntoIterator<Item = PathBuf>) -> BTreeSet<PathBuf> {
    paths
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("jsonl"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn temp_file(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("ottto-{name}-{unique}.jsonl"))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ottto-{name}-{unique}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn scan_index_recovers_from_truncated_json_and_replaces_it_atomically() {
        let root = temp_dir("scan-index-recovery");
        let path = root.join("codex-scan-index.json");
        fs::write(&path, r#"{"files":{"partial""#).expect("write truncated index");

        let recovered = ScanIndex::load(&path).expect("truncated index should self-heal");
        assert!(recovered.files.is_empty());

        let replacement = ScanIndex {
            files: BTreeMap::from([(
                "content-free-key".to_string(),
                ScanIndexEntry {
                    size_bytes: 42,
                    modified_unix_seconds: 1_700_000_000,
                    source_file_fingerprint: "sha256:test".to_string(),
                    last_snapshot_fingerprint: Some("sha256:snapshot".to_string()),
                },
            )]),
        };
        replacement.save(&path).expect("save replacement index");

        assert_eq!(
            ScanIndex::load(&path)
                .expect("load replacement")
                .files
                .len(),
            1
        );
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        assert!(!temp_path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn backfill_window_defaults_to_two_years_and_starts_from_now_when_zero() {
        let now = 1_800_000_000;
        let day_seconds = 24 * 60 * 60;

        assert_eq!(BACKFILL_WINDOW_DAYS, 730);
        assert!(is_recent_enough_at(
            now - BACKFILL_WINDOW_DAYS * day_seconds,
            now,
            BACKFILL_WINDOW_DAYS,
        ));
        assert!(!is_recent_enough_at(
            now - BACKFILL_WINDOW_DAYS * day_seconds - 1,
            now,
            BACKFILL_WINDOW_DAYS,
        ));
        assert!(is_recent_enough_at(now, now, 0));
        assert!(!is_recent_enough_at(now - 1, now, 0));
    }

    #[test]
    fn scan_policy_caps_recent_files_and_reports_partial_state() {
        let root = temp_dir("scan-policy-cap");
        // Inject a tiny cap so we exercise truncation without writing
        // MAX_BACKFILL_FILES_PER_SOURCE (10k) fixture files.
        let file_limit = 3;
        for index in 0..=file_limit {
            let path = root.join(format!("session-{index:04}.jsonl"));
            fs::write(
                path,
                concat!(
                    "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-4444-7000-9000-dddddddddddd\"}}\n",
                    "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
                ),
            )
            .expect("write fixture");
        }

        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            file_limit,
            true,
        )
        .expect("scan");

        assert_eq!(scan.backfill_window_days, BACKFILL_WINDOW_DAYS);
        assert_eq!(scan.backfill_file_limit, file_limit);
        assert_eq!(scan.discovered_file_count, file_limit + 1);
        assert_eq!(scan.skipped_file_count_due_to_limit, 1);
        assert!(scan.scan_cap_hit);
        assert_eq!(scan.scanned_file_count, file_limit);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_reader_skips_oversized_line_and_keeps_neighbors() {
        // One pathological line that exceeds the (tiny test) cap sits between two
        // valid lines. The oversized line must be dropped while both neighbors
        // still parse and accumulate in order.
        let cap = 32;
        let huge = "x".repeat(cap * 4);
        let input = format!("{{\"n\":1}}\n{{\"big\":\"{huge}\"}}\n{{\"n\":2}}\n",);
        assert!(input.len() > cap * 4, "oversized line must exceed the cap");

        let mut seen = Vec::new();
        read_bounded_jsonl_lines(input.as_bytes(), cap, |value| {
            seen.push(value.clone());
        })
        .expect("bounded read");

        assert_eq!(seen.len(), 2, "only the two valid lines survive");
        assert_eq!(seen[0], json!({ "n": 1 }));
        assert_eq!(seen[1], json!({ "n": 2 }));
        // The dropped line never reaches the callback as a (truncated) value.
        assert!(seen.iter().all(|value| value.get("big").is_none()));
    }

    #[test]
    fn bounded_reader_parses_normal_transcript_unchanged() {
        // A normal multi-line transcript (no line near the cap) parses exactly
        // as the old `lines()` loop would, including a final line without a
        // trailing newline.
        let input = "{\"type\":\"a\",\"v\":1}\n{\"type\":\"b\",\"v\":2}\n{\"type\":\"c\",\"v\":3}";
        let mut seen = Vec::new();
        read_bounded_jsonl_lines(input.as_bytes(), MAX_JSONL_LINE_BYTES, |value| {
            seen.push(value.clone());
        })
        .expect("bounded read");

        assert_eq!(
            seen,
            vec![
                json!({ "type": "a", "v": 1 }),
                json!({ "type": "b", "v": 2 }),
                json!({ "type": "c", "v": 3 }),
            ]
        );
    }

    #[test]
    fn bounded_reader_preserves_empty_and_malformed_line_semantics() {
        // Blank/whitespace lines and unparseable lines are skipped exactly as
        // before; a trailing newline does not emit a spurious empty value.
        let input = "\n   \n{\"ok\":true}\nnot json at all\n\n{\"ok\":false}\n";
        let mut seen = Vec::new();
        read_bounded_jsonl_lines(input.as_bytes(), MAX_JSONL_LINE_BYTES, |value| {
            seen.push(value.clone());
        })
        .expect("bounded read");

        assert_eq!(seen, vec![json!({ "ok": true }), json!({ "ok": false })],);
    }

    #[test]
    fn scan_policy_skips_oversized_non_codex_transcript_files() {
        let root = temp_dir("scan-policy-oversized");
        // Sparse file: logical length over the cap, negligible bytes on disk.
        let oversized_path = root.join("session-oversized.jsonl");
        let oversized = File::create(&oversized_path).expect("create oversized");
        oversized
            .set_len(MAX_JSONL_FILE_BYTES + 1)
            .expect("grow oversized");
        drop(oversized);
        assert!(
            fs::metadata(&oversized_path).expect("stat oversized").len() > MAX_JSONL_FILE_BYTES
        );

        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("scan must not abort on an oversized file");

        // The oversized file is never a candidate, so it is not discovered or
        // scanned; the scan completes without panic.
        assert_eq!(scan.discovered_file_count, 0);
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_allows_larger_streaming_transcripts_than_other_sources() {
        assert!(max_jsonl_file_bytes(SnapshotSource::Codex) > MAX_JSONL_FILE_BYTES);
        assert_eq!(
            max_jsonl_file_bytes(SnapshotSource::ClaudeCode),
            MAX_JSONL_FILE_BYTES,
        );
        assert_eq!(
            max_jsonl_file_bytes(SnapshotSource::Pi),
            MAX_JSONL_FILE_BYTES,
        );
    }

    #[test]
    fn scan_policy_never_expands_past_default_window() {
        assert_eq!(
            effective_backfill_window_days(BACKFILL_WINDOW_DAYS + 30),
            BACKFILL_WINDOW_DAYS,
        );
        assert_eq!(effective_backfill_window_days(30), 30);
    }

    #[test]
    fn codex_default_roots_include_active_and_archived_sessions() {
        let home = temp_dir("codex-default-roots");
        let roots = SnapshotSource::Codex.default_roots(&home);

        assert_eq!(
            roots,
            vec![
                home.join(".codex").join("sessions"),
                home.join(".codex").join("archived_sessions"),
            ]
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn codex_scan_reads_active_and_archived_session_roots() {
        let codex_dir = temp_dir("codex-active-archived");
        let sessions_dir = codex_dir.join("sessions");
        let archived_dir = codex_dir.join("archived_sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        fs::create_dir_all(&archived_dir).expect("create archived dir");
        fs::write(
            sessions_dir.join(
                "rollout-2026-05-14T10-00-00-019e253c-aaaa-7000-9000-aaaaaaaaaaaa.jsonl",
            ),
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-aaaa-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":20,\"output_tokens\":5},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write active fixture");
        fs::write(
            archived_dir.join(
                "rollout-2026-05-14T11-00-00-019e253c-bbbb-7000-9000-bbbbbbbbbbbb.jsonl",
            ),
            concat!(
                "{\"timestamp\":\"2026-05-14T11:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-bbbb-7000-9000-bbbbbbbbbbbb\"}}\n",
                "{\"timestamp\":\"2026-05-14T11:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":30,\"output_tokens\":6},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write archived fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir, archived_dir],
            &mut index,
            "2026-05-14T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        let session_ids: BTreeSet<_> = scan
            .snapshots
            .iter()
            .map(|snapshot| snapshot.source_session_id.as_str())
            .collect();
        assert_eq!(scan.snapshots.len(), 2);
        assert!(session_ids.contains("019e253c-aaaa-7000-9000-aaaaaaaaaaaa"));
        assert!(session_ids.contains("019e253c-bbbb-7000-9000-bbbbbbbbbbbb"));

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_parser_extracts_current_jsonl_shape_without_prompts() {
        let path = temp_file("codex");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-1f58-7580-afe7-e8d4f969b0f7\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_id\":\"019dfb9a-1f58-7580-afe7-e8d4f969b0f7\",\"thread_name\":\"Improve sessions UI\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:02:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\",\"cwd\":\"/Users/example/work\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"reasoning_effort\":\"high\",\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":25,\"reasoning_output_tokens\":7,\"request_count\":3},\"model_context_window\":258400},\"rate_limits\":{\"limit_id\":\"codex\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "019dfb9a-1f58-7580-afe7-e8d4f969b0f7"
        );
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Improve sessions UI")
        );
        assert_eq!(item.input_tokens, 100);
        assert_eq!(item.cache_read_tokens, 40);
        assert_eq!(item.output_tokens, 25);
        assert_eq!(item.reasoning_output_tokens, 7);
        assert_eq!(item.request_count, 3);
        assert_eq!(item.usage_buckets.len(), 1);
        let bucket = &item.usage_buckets[0];
        assert_eq!(bucket.bucket_start, "2026-05-06T10:00:00Z");
        assert_eq!(
            bucket.first_activity_at.as_deref(),
            Some("2026-05-06T10:03:00Z")
        );
        assert_eq!(
            bucket.last_activity_at.as_deref(),
            Some("2026-05-06T10:03:00Z")
        );
        assert_eq!(bucket.model_usage.len(), 1);
        assert_eq!(bucket.model_usage[0].request_count, 3);
        assert_eq!(item.model_usage[0].model, "gpt-5.5");
        // Per-turn reasoning effort tier rides on the model_usage row (item-level
        // aggregate and per-bucket row both carry it).
        assert_eq!(
            item.model_usage[0].reasoning_effort.as_deref(),
            Some("high")
        );
        assert_eq!(
            bucket.model_usage[0].reasoning_effort.as_deref(),
            Some("high")
        );
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("inclusive_cached")
        );
        assert!(item.workspace_hash.is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_forwards_raw_session_origin() {
        // session_meta.payload carries thread_source/source/originator/agent_role
        // (siblings of id). The backend re-derives the initiator from these.
        let path = temp_file("codex");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-origin-codex\",\"source\":\"vscode\",\"originator\":\"Codex Desktop\",\"thread_source\":\"user\",\"agent_role\":\"explorer\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":5,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(&path, "2026-05-06T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        let origin = item.origin.expect("origin forwarded");
        assert_eq!(origin.thread_source.as_deref(), Some("user"));
        assert_eq!(origin.source.as_deref(), Some("vscode"));
        assert_eq!(origin.originator.as_deref(), Some("Codex Desktop"));
        assert_eq!(origin.agent_role.as_deref(), Some("explorer"));
        assert_eq!(origin.source_subagent, None);
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| { fact.field == "provider_surface" && fact.value == "codex_desktop" }));
        assert!(!item
            .attribution_facts
            .iter()
            .any(|fact| fact.value == "vscode" || fact.field == "origin_kind"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_emits_direct_scheduled_and_parent_subagent_facts() {
        let automation_path = temp_file("codex-automation-attribution");
        fs::write(
            &automation_path,
            concat!(
                "{\"timestamp\":\"2026-07-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"automation-session\",\"source\":\"app_server\",\"originator\":\"Codex Desktop\",\"thread_source\":\"automation\"}}\n",
                "{\"timestamp\":\"2026-07-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":5,\"request_count\":1},\"model\":\"gpt-5.6-sol\"}}}\n"
            ),
        )
        .expect("write automation fixture");
        let automation = parse_codex_jsonl_file(
            &automation_path,
            "2026-07-19T10:04:00Z",
            "fp-automation".to_string(),
        )
        .expect("parse automation")
        .into_iter()
        .next()
        .expect("automation snapshot");
        assert!(automation.attribution_facts.iter().any(|fact| {
            fact.field == "origin_kind" && fact.value == "provider_scheduled_task"
        }));
        assert!(automation
            .attribution_facts
            .iter()
            .any(|fact| { fact.field == "scheduler_kind" && fact.value == "codex_scheduled" }));
        let automation_wire = serde_json::to_value(&automation).expect("serialize automation");
        assert!(
            automation_wire.get("attribution_facts").is_none(),
            "dark facts must not cross the v6 wire contract"
        );

        let subagent_path = temp_file("codex-subagent-attribution");
        fs::write(
            &subagent_path,
            concat!(
                "{\"timestamp\":\"2026-07-19T11:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"subagent-session\",\"source\":{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"parent-session\",\"depth\":1}}},\"thread_source\":\"subagent\"}}\n",
                "{\"timestamp\":\"2026-07-19T11:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":8,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.6-sol\"}}}\n"
            ),
        )
        .expect("write subagent fixture");
        let subagent = parse_codex_jsonl_file(
            &subagent_path,
            "2026-07-19T11:04:00Z",
            "fp-subagent".to_string(),
        )
        .expect("parse subagent")
        .into_iter()
        .next()
        .expect("subagent snapshot");
        assert!(subagent
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "origin_kind" && fact.value == "subagent"));
        assert!(subagent
            .attribution_facts
            .iter()
            .any(|fact| { fact.field == "parent_session_ref" && fact.value == "parent-session" }));
        let subagent_wire = serde_json::to_value(&subagent).expect("serialize subagent");
        assert!(subagent_wire.get("attribution_facts").is_none());
        assert!(
            subagent_wire
                .get("origin")
                .and_then(|origin| origin.get("parent_session_ref"))
                .is_none(),
            "dark parent metadata must not extend the v6 origin object"
        );

        let _ = fs::remove_file(automation_path);
        let _ = fs::remove_file(subagent_path);
    }

    #[test]
    fn codex_parser_groups_template_and_schedule_without_serializing_content() {
        let home = temp_dir("codex-attribution-groups");
        let schedule_dir = home.join(".codex/automations/schedule-landing");
        fs::create_dir_all(&schedule_dir).expect("schedule dir");
        let scheduled_prompt =
            "Inspect the landing queue, verify every required check, and report safe results.";
        fs::write(
            schedule_dir.join("automation.toml"),
            format!(
                "id = \"schedule-landing\"\nprompt = \"{scheduled_prompt}\"\nstatus = \"ACTIVE\"\n"
            ),
        )
        .expect("schedule definition");
        let encoded_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11_u8; 32]);
        let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            &home,
            true,
            Some(&encoded_key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .expect("attribution context");
        let path = home.join("session.jsonl");
        fs::write(
            &path,
            format!(
                "{{\"timestamp\":\"2026-07-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"automation-group-session\",\"originator\":\"Codex Desktop\",\"thread_source\":\"automation\"}}}}\n\
                 {{\"timestamp\":\"2026-07-19T10:00:01Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"user_message\",\"message\":\"An automation named Landing has fired. Its prompt is: {scheduled_prompt}\"}}}}\n\
                 {{\"timestamp\":\"2026-07-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":10,\"output_tokens\":5,\"request_count\":1}},\"model\":\"gpt-5.6-sol\"}}}}}}\n"
            ),
        )
        .expect("session");

        let item = parse_codex_jsonl_file_with_title_metadata_and_attribution(
            &path,
            "2026-07-19T10:04:00Z",
            "fp-attribution-groups".to_string(),
            &CodexTitleMetadata::default(),
            None,
            Some(&context),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "template_group_id"));
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "schedule_definition_id"));
        let local_facts = serde_json::to_string(&item.attribution_facts).expect("local facts");
        assert!(!local_facts.contains(scheduled_prompt));
        let wire = serde_json::to_value(&item).expect("snapshot wire");
        assert!(wire.get("attribution_facts").is_none());

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn codex_parser_uses_observed_usage_events_when_request_count_is_missing() {
        let path = temp_file("codex-observed-activity");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-2222-7580-afe7-e8d4f969b0f7\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":25},\"model_context_window\":258400}}}\n",
                "{\"timestamp\":\"2026-05-06T11:04:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":150,\"cached_input_tokens\":60,\"output_tokens\":35},\"model_context_window\":258400}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-06T11:05:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.request_count, 2);
        assert_eq!(item.usage_buckets.len(), 2);
        assert_eq!(item.usage_buckets[0].bucket_start, "2026-05-06T10:00:00Z");
        assert_eq!(
            item.usage_buckets[0].first_activity_at.as_deref(),
            Some("2026-05-06T10:03:00Z")
        );
        assert_eq!(
            item.usage_buckets[0].last_activity_at.as_deref(),
            Some("2026-05-06T10:03:00Z")
        );
        assert_eq!(item.usage_buckets[0].model_usage[0].request_count, 1);
        assert_eq!(item.usage_buckets[1].bucket_start, "2026-05-06T11:00:00Z");
        assert_eq!(
            item.usage_buckets[1].first_activity_at.as_deref(),
            Some("2026-05-06T11:04:00Z")
        );
        assert_eq!(
            item.usage_buckets[1].last_activity_at.as_deref(),
            Some("2026-05-06T11:04:00Z")
        );
        assert_eq!(item.usage_buckets[1].model_usage[0].request_count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_aggregates_task_complete_latency_per_session() {
        let path = temp_file("codex-latency");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-07T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019ea3b2-2186-7c93-b560-bf587a080094\"}}\n",
                "{\"timestamp\":\"2026-06-07T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":25},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-06-07T10:05:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\",\"turn_id\":\"t1\",\"duration_ms\":2000,\"time_to_first_token_ms\":100}}\n",
                "{\"timestamp\":\"2026-06-07T10:09:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\",\"turn_id\":\"t2\",\"duration_ms\":4000,\"time_to_first_token_ms\":300}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(&path, "2026-06-07T10:10:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        // Session-level averages across the two task_complete turns:
        // duration (2000 + 4000) / 2 = 3000; ttft (100 + 300) / 2 = 200.
        assert_eq!(item.avg_duration_ms, Some(3000));
        assert_eq!(item.avg_time_to_first_token_ms, Some(200));
        // Max (slowest turn): duration max(2000, 4000) = 4000; ttft max(100, 300) = 300.
        assert_eq!(item.max_duration_ms, Some(4000));
        assert_eq!(item.max_time_to_first_token_ms, Some(300));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_derives_turn_duration_latency_per_session() {
        // Claude Code has no `task_complete` latency event, but every record
        // carries an ms-precision RFC3339 timestamp. A turn's wall-clock
        // duration is the gap from the preceding `type=user` record (real prompt
        // OR tool_result) to the assistant response's first content-block record.
        // The duration is measured once per API response, deduped exactly like
        // token usage, so the several content-block records of one response
        // contribute a single sample.
        let path = temp_file("claude-turn-duration");
        fs::write(
            &path,
            concat!(
                // Real user prompt at T+0.
                "{\"timestamp\":\"2026-06-30T12:00:00.000Z\",\"type\":\"user\",\"sessionId\":\"claude-latency-1\",\"message\":{\"role\":\"user\",\"content\":\"do the thing\"}}\n",
                // Response 1 spans two content-block records (thinking + text),
                // both repeating msg_A/req_A + usage. First record lands at
                // T+2.000s -> turn 1 duration = 2000ms; the duplicate is deduped.
                "{\"timestamp\":\"2026-06-30T12:00:02.000Z\",\"type\":\"assistant\",\"sessionId\":\"claude-latency-1\",\"requestId\":\"req_A\",\"message\":{\"id\":\"msg_A\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":20}}}\n",
                "{\"timestamp\":\"2026-06-30T12:00:02.750Z\",\"type\":\"assistant\",\"sessionId\":\"claude-latency-1\",\"requestId\":\"req_A\",\"message\":{\"id\":\"msg_A\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":20}}}\n",
                // Tool result comes back as a `type=user` record at T+3.000s; it
                // becomes the input moment for the next response.
                "{\"timestamp\":\"2026-06-30T12:00:03.000Z\",\"type\":\"user\",\"sessionId\":\"claude-latency-1\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}]}}\n",
                // Response 2 lands at T+9.000s -> turn 2 duration measured from
                // the tool_result (not the original prompt) = 6000ms.
                "{\"timestamp\":\"2026-06-30T12:00:09.000Z\",\"type\":\"assistant\",\"sessionId\":\"claude-latency-1\",\"requestId\":\"req_B\",\"message\":{\"id\":\"msg_B\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":50,\"output_tokens\":10}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T12:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        // Session-level average across the two turns: (2000 + 6000) / 2 = 4000.
        assert_eq!(item.avg_duration_ms, Some(4000));
        // Slowest turn (the tail): max(2000, 6000) = 6000.
        assert_eq!(item.max_duration_ms, Some(6000));
        // TTFT is NOT derivable from Claude Code transcripts (no first-token
        // marker), so both TTFT aggregates stay absent.
        assert_eq!(item.avg_time_to_first_token_ms, None);
        assert_eq!(item.max_time_to_first_token_ms, None);
        // Latency measurement rides the same once-per-response gate as usage, so
        // the deduped tokens/request_count are unaffected: response 1 counts
        // once despite its two content-block records.
        assert_eq!(item.input_tokens, 150);
        assert_eq!(item.output_tokens, 30);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_turn_duration_skips_responses_without_preceding_user() {
        // A response with no preceding `type=user` record (e.g. the transcript
        // opens mid-stream after a compaction/resume) has no input moment to
        // measure against and must contribute no latency sample. Only the
        // response that follows a real user record is measured.
        let path = temp_file("claude-turn-duration-noprompt");
        fs::write(
            &path,
            concat!(
                // Leading assistant response with nothing before it -> skipped.
                "{\"timestamp\":\"2026-06-30T13:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"claude-latency-2\",\"requestId\":\"req_A\",\"message\":{\"id\":\"msg_A\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-06-30T13:00:01.000Z\",\"type\":\"user\",\"sessionId\":\"claude-latency-2\",\"message\":{\"role\":\"user\",\"content\":\"continue\"}}\n",
                // Only this response has a preceding user record: 4000ms.
                "{\"timestamp\":\"2026-06-30T13:00:05.000Z\",\"type\":\"assistant\",\"sessionId\":\"claude-latency-2\",\"requestId\":\"req_B\",\"message\":{\"id\":\"msg_B\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T13:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        // Exactly one turn measured, so avg == max == that single sample.
        assert_eq!(item.avg_duration_ms, Some(4000));
        assert_eq!(item.max_duration_ms, Some(4000));
        assert_eq!(item.avg_time_to_first_token_ms, None);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_transcript_title_wins_over_sidecar_titles() {
        let path = temp_file("codex-title-priority");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-1111-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_name\":\"Transcript title wins\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"First prompt fallback should not win\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let mut metadata = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut metadata.titles,
            "019e253c-1111-7000-9000-aaaaaaaaaaaa".to_string(),
            Some("Sidecar title loses".to_string()),
            "session_index",
            true,
        );

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
            None,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Transcript title wins")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("transcript_title")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_session_index_sidecar_supplies_title_without_jsonl_title() {
        let codex_dir = temp_dir("codex-session-index");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        let path = sessions_dir
            .join("rollout-2026-05-14T10-00-00-019e253c-2222-7000-9000-bbbbbbbbbbbb.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":20,\"output_tokens\":5},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        fs::write(
            codex_dir.join("session_index.jsonl"),
            "{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\",\"thread_name\":\"Daily bug scan\",\"updated_at\":1777777777}\n",
        )
        .expect("write session index");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.snapshots.len(), 1);
        let item = &scan.snapshots[0];
        assert_eq!(item.session_display_name.as_deref(), Some("Daily bug scan"));
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("session_index")
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_state_sqlite_sidecar_supplies_title_when_session_index_has_none() {
        let codex_dir = temp_dir("codex-state-sqlite");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        let path = sessions_dir
            .join("rollout-2026-05-14T10-00-00-019e253c-3333-7000-9000-cccccccccccc.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-3333-7000-9000-cccccccccccc\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":30,\"output_tokens\":6},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT NOT NULL)",
                [],
            )
            .expect("create threads");
        connection
            .execute(
                "INSERT INTO threads (id, title) VALUES (?1, ?2)",
                [
                    "019e253c-3333-7000-9000-cccccccccccc",
                    "Pricing Review Guarded Autopilot",
                ],
            )
            .expect("insert thread");
        drop(connection);

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.snapshots.len(), 1);
        let item = &scan.snapshots[0];
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Pricing Review Guarded Autopilot")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("session_index")
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_state_sqlite_supplies_total_only_fallback_snapshots() {
        let codex_dir = temp_dir("codex-state-total-only");
        let sessions_dir = codex_dir.join("sessions");
        let archived_dir = codex_dir.join("archived_sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        fs::create_dir_all(&archived_dir).expect("create archived dir");
        fs::write(
            sessions_dir.join(
                "rollout-2026-05-14T10-00-00-019e253c-7777-7000-9000-aaaaaaaaaaaa.jsonl",
            ),
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-7777-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":30,\"output_tokens\":6},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(
                concat!(
                    "CREATE TABLE threads (",
                    "id TEXT PRIMARY KEY, title TEXT NOT NULL, tokens_used INTEGER NOT NULL, ",
                    "archived INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ",
                    "created_at_ms INTEGER, updated_at_ms INTEGER, model TEXT)",
                ),
                [],
            )
            .expect("create threads");
        connection
            .execute(
                concat!(
                    "INSERT INTO threads (id, title, tokens_used, archived, created_at, updated_at, ",
                    "created_at_ms, updated_at_ms, model) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                ),
                (
                    "019e253c-7777-7000-9000-aaaaaaaaaaaa",
                    "Matched JSONL",
                    37_i64,
                    0_i64,
                    1_777_777_000_i64,
                    1_777_777_100_i64,
                    1_777_777_000_000_i64,
                    1_777_777_100_000_i64,
                    "gpt-5.5",
                ),
            )
            .expect("insert matched thread");
        connection
            .execute(
                concat!(
                    "INSERT INTO threads (id, title, tokens_used, archived, created_at, updated_at, ",
                    "created_at_ms, updated_at_ms, model) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                ),
                (
                    "019e253c-8888-7000-9000-bbbbbbbbbbbb",
                    "Archived State Only",
                    1_234_i64,
                    1_i64,
                    1_777_777_200_i64,
                    1_777_777_300_i64,
                    1_777_777_200_000_i64,
                    1_777_777_300_000_i64,
                    "gpt-5.5",
                ),
            )
            .expect("insert state-only thread");
        drop(connection);

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir, archived_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.snapshots.len(), 2);
        let matched = scan
            .snapshots
            .iter()
            .find(|snapshot| snapshot.source_session_id == "019e253c-7777-7000-9000-aaaaaaaaaaaa")
            .expect("matched snapshot");
        assert_eq!(matched.input_tokens, 30);
        assert_eq!(matched.unattributed_total_tokens, 0);
        assert_eq!(matched.provenance.state_total_tokens, Some(37));
        assert_eq!(matched.provenance.state_archived, Some(false));

        let state_only = scan
            .snapshots
            .iter()
            .find(|snapshot| snapshot.source_session_id == "019e253c-8888-7000-9000-bbbbbbbbbbbb")
            .expect("state-only snapshot");
        assert_eq!(state_only.input_tokens, 0);
        assert_eq!(state_only.output_tokens, 0);
        assert_eq!(state_only.cache_read_tokens, 0);
        assert_eq!(state_only.unattributed_total_tokens, 1_234);
        assert_eq!(state_only.model_usage[0].unattributed_total_tokens, 1_234);
        assert_eq!(
            state_only.provenance.collector.as_str(),
            "codex_state_sqlite"
        );
        assert_eq!(
            state_only.provenance.input_token_scope.as_deref(),
            Some("total_only")
        );
        assert_eq!(state_only.provenance.state_archived, Some(true));
        assert_eq!(state_only.source_file_fingerprint, None);
        assert_eq!(
            state_only.session_display_name.as_deref(),
            Some("Archived State Only")
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    // Standard Codex `threads` schema (no rollout_path column — coverage is
    // derived from the rollout filename, not this column).
    const CODEX_THREADS_DDL: &str = concat!(
        "CREATE TABLE threads (",
        "id TEXT PRIMARY KEY, title TEXT NOT NULL, tokens_used INTEGER NOT NULL, ",
        "archived INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ",
        "created_at_ms INTEGER, updated_at_ms INTEGER, model TEXT)",
    );
    const CODEX_THREADS_INSERT: &str = concat!(
        "INSERT INTO threads (id, title, tokens_used, archived, created_at, updated_at, ",
        "created_at_ms, updated_at_ms, model) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    );

    #[test]
    fn codex_state_only_skips_sessions_already_parsed_in_a_prior_run() {
        // Regression: the incremental scan skips a rollout file it parsed in an
        // earlier run, so the session is absent from the current run's parsed
        // set. The state-only fallback must NOT then re-emit an unattributed
        // "Other" total for it (its split snapshot already reached the backend);
        // coverage is judged against the persisted scan index (session ids of
        // files that produced a snapshot), not just this run.
        let codex_dir = temp_dir("codex-state-incremental");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        fs::write(
            sessions_dir.join(
                "rollout-2026-05-14T10-00-00-019e253c-9999-7000-9000-cccccccccccc.jsonl",
            ),
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-9999-7000-9000-cccccccccccc\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":50,\"output_tokens\":9},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(CODEX_THREADS_DDL, [])
            .expect("create threads");
        connection
            .execute(
                CODEX_THREADS_INSERT,
                (
                    "019e253c-9999-7000-9000-cccccccccccc",
                    "Parsed Then Skipped",
                    59_i64,
                    0_i64,
                    1_777_777_000_i64,
                    1_777_777_100_i64,
                    1_777_777_000_000_i64,
                    1_777_777_100_000_i64,
                    "gpt-5.5",
                ),
            )
            .expect("insert thread");
        drop(connection);

        let roots = [sessions_dir];
        let mut index = ScanIndex::default();

        // First run: the rollout is parsed → split snapshot, no state-only total.
        let first = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first.snapshots[0].input_tokens, 50);
        assert_eq!(first.snapshots[0].unattributed_total_tokens, 0);

        // Second run (same index): the unchanged rollout is skipped, so it is not
        // in this run's parsed set. With the fix, no state-only "Other" is emitted
        // because the session is covered by a prior run in the scan index.
        let second = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T11:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second scan");
        assert!(
            second
                .snapshots
                .iter()
                .all(|snapshot| snapshot.unattributed_total_tokens == 0),
            "incremental re-scan must not re-emit an unattributed Other for an already-parsed session",
        );
        assert!(second.snapshots.iter().all(|snapshot| snapshot
            .provenance
            .input_token_scope
            .as_deref()
            != Some("total_only")));

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_state_only_preserved_when_rollout_parses_to_no_usage() {
        // Regression guard: a rollout that exists but yields zero usage rows
        // (e.g. only session_meta, or a legacy/unknown token payload) is still
        // recorded in the scan index, but it produced NO split snapshot. Such a
        // thread must keep surfacing its tokens as a state-only "Other" — both
        // on the first scan and on incremental re-scans — never be dropped just
        // because the file was scanned.
        let codex_dir = temp_dir("codex-state-empty-rollout");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        // session_meta only — no token_count event, so parsing yields no rows.
        fs::write(
            sessions_dir.join(
                "rollout-2026-05-14T10-00-00-019e253c-aaaa-7000-9000-eeeeeeeeeeee.jsonl",
            ),
            "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-aaaa-7000-9000-eeeeeeeeeeee\"}}\n",
        )
        .expect("write fixture");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(CODEX_THREADS_DDL, [])
            .expect("create threads");
        connection
            .execute(
                CODEX_THREADS_INSERT,
                (
                    "019e253c-aaaa-7000-9000-eeeeeeeeeeee",
                    "Unparseable Rollout",
                    4_321_i64,
                    0_i64,
                    1_777_777_000_i64,
                    1_777_777_100_i64,
                    1_777_777_000_000_i64,
                    1_777_777_100_000_i64,
                    "gpt-5.5",
                ),
            )
            .expect("insert thread");
        drop(connection);

        let roots = [sessions_dir];
        let mut index = ScanIndex::default();

        let assert_state_only = |label: &str, scan: &SourceScanResult| {
            let state_only = scan
                .snapshots
                .iter()
                .find(|s| s.source_session_id == "019e253c-aaaa-7000-9000-eeeeeeeeeeee")
                .unwrap_or_else(|| panic!("{label}: expected a state-only snapshot"));
            assert_eq!(state_only.unattributed_total_tokens, 4_321, "{label}");
            assert_eq!(
                state_only.provenance.input_token_scope.as_deref(),
                Some("total_only"),
                "{label}",
            );
        };

        let first = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_state_only("first scan", &first);

        // Incremental re-scan: file skipped, but it never produced a snapshot, so
        // the tokens must still surface as a state-only Other (not be dropped).
        let second = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T11:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second scan");
        assert_state_only("incremental re-scan", &second);

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn pi_scan_retries_zero_parsed_file_until_usage_arrives() {
        let root = temp_dir("pi-retry-zero-parsed");
        let path = root.join("session-019e2700-1111-7000-9000-111111111111.jsonl");
        fs::write(
            &path,
            "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-05-14T10:00:00Z\"}\n",
        )
        .expect("write empty usage fixture");

        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_eq!(first.snapshots.len(), 0);

        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-05-14T10:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234000000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write usage fixture");

        let second = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second scan");
        assert_eq!(second.snapshots.len(), 1);
        assert_eq!(
            second.snapshots[0].source_session_id,
            "019e2700-1111-7000-9000-111111111111"
        );

        let third = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:07:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("third scan");
        assert_eq!(third.snapshots.len(), 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_scan_reprocesses_v6_zero_parse_index_entries() {
        let root = temp_dir("pi-v6-index");
        let path = root.join("session-019e2700-2222-7000-9000-222222222222.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-2222-7000-9000-222222222222\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-05-14T10:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779235000000,\"usage\":{\"input\":22,\"output\":11,\"cacheRead\":1,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write usage fixture");

        let metadata = fs::metadata(&path).expect("read metadata");
        let size_bytes = metadata.len();
        let modified_unix_seconds = metadata
            .modified()
            .expect("modification time")
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let v6_key =
            source_file_fingerprint(&path, size_bytes, modified_unix_seconds, "pi_jsonl:v6");
        let legacy_entry = ScanIndexEntry {
            size_bytes,
            modified_unix_seconds,
            source_file_fingerprint: v6_key.clone(),
            last_snapshot_fingerprint: None,
        };

        let mut index = ScanIndex {
            files: std::collections::BTreeMap::from([(
                path.to_string_lossy().to_string(),
                legacy_entry,
            )]),
        };

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(
            scan.snapshots[0].source_session_id,
            "019e2700-2222-7000-9000-222222222222"
        );

        let entry = index
            .files
            .get(&path.to_string_lossy().to_string())
            .expect("index entry");
        assert!(entry.last_snapshot_fingerprint.is_some());
        assert_ne!(entry.source_file_fingerprint, v6_key);
        assert_eq!(
            entry.source_file_fingerprint,
            source_file_fingerprint(
                &path,
                size_bytes,
                modified_unix_seconds,
                PI_SNAPSHOT_PARSER_VERSION
            )
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_first_prompt_fallback_is_filtered() {
        let path = temp_file("codex-first-prompt");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-4444-7000-9000-dddddddddddd\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Fix local telemetry upload\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Fix local telemetry upload")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let noisy_path = temp_file("codex-noisy-first-prompt");
        fs::write(
            &noisy_path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-5555-7000-9000-eeeeeeeeeeee\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"# AGENTS.md instructions for /repo\\n\\n<INSTRUCTIONS>Do not use this as a title</INSTRUCTIONS>\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write noisy fixture");

        let noisy_item = parse_codex_jsonl_file(
            &noisy_path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(noisy_item.session_display_name, None);
        assert_eq!(noisy_item.session_display_name_source, None);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(noisy_path);
    }

    #[test]
    fn upload_policy_strips_titles_and_workspace_labels_before_upload() {
        let path = temp_file("codex-upload-policy");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-5555-7000-9000-eeeeeeeeeeef\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_name\":\"Private task title\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let mut item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        item.workspace_display_label = Some("Checkout service".to_string());
        item.workspace_label_source = Some("user_approved".to_string());
        item.repository_label = Some("private-repository".to_string());
        item.repository_label_source = Some("git_root".to_string());
        let original_fingerprint = item.snapshot_fingerprint.clone();
        let mut snapshots = vec![item];

        apply_upload_policy(
            SnapshotSource::Codex,
            &mut snapshots,
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
                session_artifacts_enabled: false,
            },
        );

        let stripped = &snapshots[0];
        assert_eq!(stripped.session_display_name, None);
        assert_eq!(stripped.session_display_name_source, None);
        assert_eq!(stripped.workspace_display_label, None);
        assert_eq!(stripped.workspace_label_source, None);
        assert_eq!(stripped.repository_label, None);
        assert_eq!(stripped.repository_label_source, None);
        assert_ne!(stripped.snapshot_fingerprint, original_fingerprint);
        let serialized = serde_json::to_string(stripped).expect("serialize");
        assert!(!serialized.contains("Private task title"));
        assert!(!serialized.contains("Checkout service"));
        assert!(!serialized.contains("private-repository"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_snapshot_derives_repository_identity_without_uploading_raw_cwd() {
        let repository = temp_dir("codex-repository-identity");
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repository)
            .status()
            .expect("run git init");
        assert!(status.success());
        let path = repository.join("session.jsonl");
        let session_meta = serde_json::json!({
            "timestamp": "2026-05-14T10:00:00Z",
            "type": "session_meta",
            "payload": {
                "id": "019e253c-5555-7000-9000-eeeeeeeeeeea",
                "cwd": repository.to_string_lossy(),
            }
        });
        let usage = serde_json::json!({
            "timestamp": "2026-05-14T10:03:00Z",
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": {
                    "total_token_usage": {"input_tokens": 40, "output_tokens": 8},
                    "model": "gpt-5.5"
                }
            }
        });
        fs::write(&path, format!("{session_meta}\n{usage}\n")).expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(item.repository_hash.as_ref().map(String::len), Some(64));
        assert_eq!(
            item.repository_label.as_deref(),
            repository.file_name().and_then(|value| value.to_str())
        );
        assert_eq!(
            item.repository_identity_source.as_deref(),
            Some("git_common_dir")
        );
        assert_eq!(item.workspace_kind.as_deref(), Some("repository_root"));
        let serialized = serde_json::to_string(&item).expect("serialize");
        assert!(!serialized.contains(repository.to_string_lossy().as_ref()));

        let _ = fs::remove_dir_all(repository);
    }

    #[test]
    fn extract_session_artifacts_collects_clean_pr_issue_commit() {
        let text = concat!(
            "Created PR: https://github.com/ottto-ai/repo/pull/42\n",
            "MR https://gitlab.com/group/sub/proj/-/merge_requests/7 ",
            "and https://bitbucket.org/team/repo/pull-requests/3\n",
            "Issue: https://github.com/ottto-ai/repo/issues/9.\n",
            "[main a1b2c3d] commit message\n",
        );
        let pairs: BTreeSet<(String, String)> = extract_session_artifacts(text)
            .into_iter()
            .map(|artifact| (artifact.kind, artifact.value))
            .collect();
        assert!(pairs.contains(&(
            "pull_request".to_string(),
            "https://github.com/ottto-ai/repo/pull/42".to_string()
        )));
        assert!(pairs.contains(&(
            "pull_request".to_string(),
            "https://gitlab.com/group/sub/proj/-/merge_requests/7".to_string()
        )));
        assert!(pairs.contains(&(
            "pull_request".to_string(),
            "https://bitbucket.org/team/repo/pull-requests/3".to_string()
        )));
        assert!(pairs.contains(&(
            "issue".to_string(),
            "https://github.com/ottto-ai/repo/issues/9".to_string()
        )));
        assert!(pairs.contains(&("commit".to_string(), "a1b2c3d".to_string())));
    }

    #[test]
    fn extract_session_artifacts_canonicalizes_and_rejects_unclean() {
        // Trailing path suffix and query string are dropped to the id.
        let canon = extract_session_artifacts(
            "https://github.com/o/r/pull/42/files https://github.com/o/r/pull/7?w=1",
        );
        let values: BTreeSet<String> = canon.into_iter().map(|a| a.value).collect();
        assert!(values.contains("https://github.com/o/r/pull/42"));
        assert!(values.contains("https://github.com/o/r/pull/7"));
        assert!(values
            .iter()
            .all(|value| !value.contains('?') && !value.contains("/files")));

        // Embedded credentials, percent-encoded local paths, and non-http
        // schemes never produce an artifact (so the batch can never be rejected).
        for unclean in [
            "https://user:pass@github.com/o/r/pull/1",
            "https://github.com/o/%2Fusers%2Fron/pull/1",
            "ftp://github.com/o/r/pull/1",
            "https://github.com/o/r/tree/main",
        ] {
            assert!(
                extract_session_artifacts(unclean).is_empty(),
                "expected no artifact for {unclean}"
            );
        }
        // All-numeric bracketed log lines are not commits (require an a-f digit).
        assert!(extract_session_artifacts("[INFO 1234567] starting").is_empty());
    }

    #[test]
    fn claude_code_artifact_scrape_skipped_when_disabled_and_runs_when_enabled() {
        // Transcript whose tool_result carries a clean PR URL — exactly what the
        // per-line scraper collects when the feature is on.
        let fixture = concat!(
            "{\"timestamp\":\"2026-05-29T00:00:00Z\",\"sessionId\":\"artifact-scan-session\",\"summary\":\"Artifact scan session\"}\n",
            "{\"timestamp\":\"2026-05-29T00:01:00Z\",\"sessionId\":\"artifact-scan-session\",\"message\":{\"id\":\"msg_01artifact\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
            "{\"timestamp\":\"2026-05-29T00:02:00Z\",\"sessionId\":\"artifact-scan-session\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":[{\"type\":\"text\",\"text\":\"Opened https://github.com/ottto-ai/repo/pull/42\"}]}]}}\n",
        );

        // Enabled (public parse default, and the scan path when the org setting
        // is on): the PR URL is scraped into session_artifacts.
        let enabled_path = temp_file("claude-artifacts-enabled");
        fs::write(&enabled_path, fixture).expect("write fixture");
        let enabled = parse_claude_code_jsonl_file(
            &enabled_path,
            "2026-05-29T00:05:00Z",
            "artifacts-enabled-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(
            enabled.session_artifacts,
            vec![SessionArtifact {
                kind: "pull_request".to_string(),
                value: "https://github.com/ottto-ai/repo/pull/42".to_string(),
            }],
            "scrape must run when artifacts are enabled"
        );
        let _ = fs::remove_file(&enabled_path);

        // Disabled (production scan path when the org setting is off): the scrape
        // is skipped wholesale, so no artifacts are produced — the discard in
        // apply_upload_policy never even runs.
        let disabled_path = temp_file("claude-artifacts-disabled");
        fs::write(&disabled_path, fixture).expect("write fixture");
        let disabled = parse_claude_code_jsonl_file_with_artifacts(
            &disabled_path,
            "2026-05-29T00:05:00Z",
            "artifacts-disabled-fingerprint".to_string(),
            false,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert!(
            disabled.session_artifacts.is_empty(),
            "scrape must be skipped when artifacts are disabled"
        );
        let _ = fs::remove_file(&disabled_path);
    }

    #[test]
    fn apply_upload_policy_strips_artifacts_when_disabled() {
        let item = sample_session_artifact_item();
        let original_fingerprint = item.snapshot_fingerprint.clone();
        let mut disabled = vec![item.clone()];
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut disabled,
            SnapshotUploadPolicy {
                session_titles_enabled: true,
                workspace_labels_enabled: true,
                session_artifacts_enabled: false,
            },
        );
        assert!(disabled[0].session_artifacts.is_empty());
        assert_ne!(disabled[0].snapshot_fingerprint, original_fingerprint);

        let mut enabled = vec![item.clone()];
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut enabled,
            SnapshotUploadPolicy {
                session_titles_enabled: true,
                workspace_labels_enabled: true,
                session_artifacts_enabled: true,
            },
        );
        assert_eq!(enabled[0].session_artifacts.len(), 1);
        assert_eq!(enabled[0].snapshot_fingerprint, original_fingerprint);
    }

    fn sample_session_artifact_item() -> SnapshotItem {
        let mut item = SnapshotItem {
            source_session_id: "artifact-session".to_string(),
            snapshot_fingerprint: String::new(),
            status: "final".to_string(),
            input_tokens: 1,
            output_tokens: 1,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: None,
            first_turn_context_tokens: None,
            compaction_count: None,
            model_usage: Vec::new(),
            usage_buckets: Vec::new(),
            cost: None,
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: None,
            source_ended_at: None,
            source_last_activity_at: None,
            collected_at: "2026-05-29T00:00:00Z".to_string(),
            workspace_hash: None,
            workspace_display_label: None,
            workspace_label_source: None,
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: None,
            source_file_fingerprint: None,
            session_artifacts: vec![SessionArtifact {
                kind: "pull_request".to_string(),
                value: "https://github.com/o/r/pull/1".to_string(),
            }],
            provenance: SnapshotProvenance {
                collector: "claude_code_jsonl".to_string(),
                source_file_count: 1,
                input_token_scope: Some("uncached".to_string()),
                state_total_tokens: None,
                state_archived: None,
            },
            origin: None,
            attribution_facts: Vec::new(),
        };
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
        item
    }

    #[test]
    fn codex_title_changes_affect_snapshot_and_source_file_fingerprints() {
        let path = temp_file("codex-title-fingerprint");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-ffffffffffff\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":50,\"output_tokens\":9},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let mut first = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut first.titles,
            "019e253c-6666-7000-9000-ffffffffffff".to_string(),
            Some("First title".to_string()),
            "session_index",
            true,
        );
        let mut second = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut second.titles,
            "019e253c-6666-7000-9000-ffffffffffff".to_string(),
            Some("Second title".to_string()),
            "session_index",
            true,
        );

        let first_item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &first,
            None,
        )
        .expect("parse first")
        .into_iter()
        .next()
        .expect("first snapshot");
        let second_item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &second,
            None,
        )
        .expect("parse second")
        .into_iter()
        .next()
        .expect("second snapshot");
        assert_ne!(
            first_item.snapshot_fingerprint,
            second_item.snapshot_fingerprint
        );

        let source_file = source_file_fingerprint_with_context(
            &path,
            100,
            1_777_777_777,
            CODEX_SNAPSHOT_PARSER_VERSION,
            "sidecar-a",
        );
        let source_file_after_sidecar_change = source_file_fingerprint_with_context(
            &path,
            100,
            1_777_777_777,
            CODEX_SNAPSHOT_PARSER_VERSION,
            "sidecar-b",
        );
        assert_ne!(source_file, source_file_after_sidecar_change);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn source_file_fingerprint_changes_with_parser_version() {
        let path = Path::new("/redacted/session.jsonl");
        let old = source_file_fingerprint(path, 100, 1_777_777_777, "codex_jsonl:v2");
        let current =
            source_file_fingerprint(path, 100, 1_777_777_777, CODEX_SNAPSHOT_PARSER_VERSION);

        assert_ne!(old, current);
    }

    #[test]
    fn codex_parser_ignores_function_call_names_as_titles() {
        let path = temp_file("codex-tool-name");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T09:19:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2523-aa35-7b62-a712-00c2a0fea2ff\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:20:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec_command\",\"call_id\":\"call-1\",\"arguments\":\"{}\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:21:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"write_stdin\",\"call_id\":\"call-2\",\"arguments\":\"{}\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:22:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":25,\"request_count\":3},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T09:23:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.session_display_name, None);
        assert_eq!(item.session_display_name_source, None);
        assert_eq!(item.input_tokens, 100);
        assert_eq!(item.model_usage[0].model, "gpt-5.5");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_splits_cumulative_usage_by_selector() {
        let path = temp_file("codex-selector-split");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-111111111111\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"service_tier\":\"standard\",\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":30,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-05-19T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"service_tier\":\"fast\",\"total_token_usage\":{\"input_tokens\":300,\"output_tokens\":90,\"request_count\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.input_tokens, 300);
        assert_eq!(item.output_tokens, 90);
        assert_eq!(item.request_count, 2);
        assert_eq!(item.usage_buckets.len(), 1);
        let bucket = &item.usage_buckets[0];
        assert_eq!(bucket.bucket_start, "2026-05-19T10:00:00Z");
        assert_eq!(
            bucket.first_activity_at.as_deref(),
            Some("2026-05-19T10:02:00Z")
        );
        assert_eq!(
            bucket.last_activity_at.as_deref(),
            Some("2026-05-19T10:03:00Z")
        );
        // Two distinct service_tier rows aggregate within the same hour.
        let bucket_request_count: u64 = bucket.model_usage.iter().map(|r| r.request_count).sum();
        assert_eq!(bucket_request_count, 2);
        assert_eq!(item.model_usage.len(), 2);
        let standard = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("standard")
            })
            .expect("standard row");
        let fast = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("fast")
            })
            .expect("fast row");
        assert_eq!(standard.input_tokens, 100);
        assert_eq!(standard.output_tokens, 30);
        assert_eq!(fast.input_tokens, 200);
        assert_eq!(fast.output_tokens, 60);

        let _ = fs::remove_file(path);
    }

    // turn ids reused across the logs_2 reader + injection tests.
    const FAST_TURN: &str = "019ee443-7197-7d51-84a0-727a6b2655cb";
    const STD_TURN: &str = "019ee421-1b3b-71c3-a0a8-ec9f645bf521";

    fn priority_request_body(turn_id: &str) -> String {
        format!(
            "session_loop{{thread_id=019ee443-4c18-71c3-843e-847232f694b0}}:\
             turn{{otel.name=\"session_task.turn\" turn.id={turn_id} \
             codex.turn.reasoning_effort=xhigh}}: websocket request: \
             {{\"type\":\"response.create\",\"service_tier\":\"priority\",\
             \"model\":\"gpt-5.5\",\"instructions\":\"REDACTED PROMPT\"}}"
        )
    }

    #[test]
    fn codex_logs2_priority_turn_from_body_extracts_turn_id_for_priority() {
        let body = priority_request_body(FAST_TURN);
        assert_eq!(
            codex_logs2_priority_turn_from_body(&body).as_deref(),
            Some(FAST_TURN)
        );
    }

    #[test]
    fn codex_logs2_priority_turn_from_body_ignores_standard_and_non_request() {
        // No service_tier (standard) -> not a fast turn.
        let standard = "turn{turn.id=019ee421-1b3b-71c3-a0a8-ec9f645bf521}: \
             websocket request: {\"type\":\"response.create\",\"model\":\"gpt-5.5\"}";
        assert_eq!(codex_logs2_priority_turn_from_body(standard), None);
        // service_tier=auto is the default, not priority.
        let auto = "turn{turn.id=019ee421-1b3b-71c3-a0a8-ec9f645bf521}: \
             websocket request: {\"type\":\"response.create\",\"service_tier\":\"auto\"}";
        assert_eq!(codex_logs2_priority_turn_from_body(auto), None);
        // Wrong message type.
        let other = "turn{turn.id=019ee421-1b3b-71c3-a0a8-ec9f645bf521}: \
             websocket request: {\"type\":\"response.cancel\",\"service_tier\":\"priority\"}";
        assert_eq!(codex_logs2_priority_turn_from_body(other), None);
        // No request marker at all.
        assert_eq!(codex_logs2_priority_turn_from_body("nothing here"), None);
    }

    #[test]
    fn codex_logs2_span_field_respects_identifier_boundary() {
        let prefix = "submission.id=XYZ parent_turn_id=AAA turn.id=BBB next=1";
        // `turn.id` sits on a boundary (space before) -> matched.
        assert_eq!(
            codex_logs2_span_field(prefix, "turn.id").as_deref(),
            Some("BBB")
        );
        // `turn_id` appears only inside `parent_turn_id` -> rejected by boundary.
        assert_eq!(codex_logs2_span_field(prefix, "turn_id"), None);
        // Value terminates at brace.
        assert_eq!(
            codex_logs2_span_field("a turn.id=CCC}", "turn.id").as_deref(),
            Some("CCC")
        );
    }

    #[test]
    fn codex_fast_mode_trace_opt_out_defaults_on() {
        assert!(codex_fast_mode_trace_enabled_from(None));
        assert!(codex_fast_mode_trace_enabled_from(Some("on")));
        assert!(codex_fast_mode_trace_enabled_from(Some("1")));
        assert!(codex_fast_mode_trace_enabled_from(Some("")));
        for off in ["off", "0", "false", "no", "disabled", "OFF", " Off "] {
            assert!(
                !codex_fast_mode_trace_enabled_from(Some(off)),
                "expected {off:?} to disable the trace"
            );
        }
    }

    #[test]
    fn claude_attribution_capture_opt_in_defaults_off() {
        // Default OFF: absent env, and any unrecognized/explicit-off value.
        assert!(!claude_attribution_capture_enabled_from(None));
        for off in ["", "off", "0", "false", "no", "disabled", "nonsense"] {
            assert!(
                !claude_attribution_capture_enabled_from(Some(off)),
                "expected {off:?} to leave attribution capture off"
            );
        }
        // Explicit opt-in tokens (case/whitespace tolerant).
        for on in ["on", "1", "true", "yes", "enabled", "ON", " True ", "Yes"] {
            assert!(
                claude_attribution_capture_enabled_from(Some(on)),
                "expected {on:?} to enable attribution capture"
            );
        }
    }

    #[test]
    fn claude_attribution_capture_lifts_all_five_markers_when_enabled() {
        let line: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",\"sessionId\":\"attr-session\",",
            "\"attributionAgent\":\"general-purpose\",",
            "\"attributionSkill\":\"design-sync\",",
            "\"attributionPlugin\":\"anthropic-skills\",",
            "\"attributionMcpServer\":\"claude-in-chrome\",",
            "\"attributionMcpTool\":\"tabs_context_mcp\",",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":100,\"output_tokens\":30}}}"
        ))
        .expect("parse line");

        let mut selector = SelectorCapture::default();
        capture_claude_attribution(&line, &mut selector, true);

        // Subagent is the priority dimension.
        assert_eq!(
            selector
                .context
                .get("attribution_subagent")
                .map(String::as_str),
            Some("general-purpose")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_skill")
                .map(String::as_str),
            Some("design-sync")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_plugin")
                .map(String::as_str),
            Some("anthropic-skills")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_mcp_server")
                .map(String::as_str),
            Some("claude-in-chrome")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_mcp_tool")
                .map(String::as_str),
            Some("tabs_context_mcp")
        );
        // Source tag is uniform for all captured attribution keys.
        assert_eq!(
            selector
                .sources
                .get("attribution_subagent")
                .map(String::as_str),
            Some("claude_code_attribution_field")
        );
    }

    #[test]
    fn claude_attribution_capture_is_noop_when_disabled() {
        let line: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",\"attributionAgent\":\"general-purpose\",",
            "\"attributionMcpServer\":\"claude-in-chrome\",",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}"
        ))
        .expect("parse line");

        let mut selector = SelectorCapture::default();
        capture_claude_attribution(&line, &mut selector, false);

        assert!(
            selector.is_empty(),
            "attribution must not be captured while the opt-in flag is off"
        );
    }

    #[test]
    fn claude_attribution_capture_skips_absent_or_blank_markers() {
        // Enabled, but the line carries no usable attribution: blank string and
        // a non-string value are both ignored (string_at trims + rejects empty).
        let line: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",\"attributionAgent\":\"   \",",
            "\"attributionSkill\":42,",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}"
        ))
        .expect("parse line");

        let mut selector = SelectorCapture::default();
        capture_claude_attribution(&line, &mut selector, true);

        assert!(
            selector.is_empty(),
            "blank/non-string attribution markers must be skipped"
        );
    }

    #[test]
    fn claude_attribution_contract_allows_four_keys_and_strips_tool() {
        // First attribution contract: four approved attribution keys cross the
        // wire inside selector_context. The tool-level marker remains stripped
        // because it is too high-cardinality for the initial selector split.
        for key in [
            "attribution_subagent",
            "attribution_skill",
            "attribution_plugin",
            "attribution_mcp_server",
        ] {
            assert!(
                SELECTOR_CONTEXT_ALLOWED.contains(&key),
                "{key} must be on SELECTOR_CONTEXT_ALLOWED for daemon v11"
            );
        }
        assert!(
            !SELECTOR_CONTEXT_ALLOWED.contains(&"attribution_mcp_tool"),
            "attribution_mcp_tool must stay off SELECTOR_CONTEXT_ALLOWED"
        );

        let mut merged = SelectorCapture::default();
        merged.insert("context_bucket", "long".to_string(), "test");
        merged.insert(
            "attribution_subagent",
            "general-purpose".to_string(),
            "claude_code_attribution_field",
        );
        merged.insert(
            "attribution_mcp_server",
            "claude-in-chrome".to_string(),
            "claude_code_attribution_field",
        );
        merged.insert(
            "attribution_skill",
            "design-sync".to_string(),
            "claude_code_attribution_field",
        );
        merged.insert(
            "attribution_plugin",
            "anthropic-skills".to_string(),
            "claude_code_attribution_field",
        );
        merged.insert(
            "attribution_mcp_tool",
            "tabs_context_mcp".to_string(),
            "claude_code_attribution_field",
        );

        let (_, reduced_context, _) = build_row_identity("claude-opus-4-8", &merged, None);

        assert_eq!(
            reduced_context.get("context_bucket").map(String::as_str),
            Some("long")
        );
        assert_eq!(
            reduced_context
                .get("attribution_subagent")
                .map(String::as_str),
            Some("general-purpose")
        );
        assert_eq!(
            reduced_context
                .get("attribution_mcp_server")
                .map(String::as_str),
            Some("claude-in-chrome")
        );
        assert_eq!(
            reduced_context.get("attribution_skill").map(String::as_str),
            Some("design-sync")
        );
        assert_eq!(
            reduced_context
                .get("attribution_plugin")
                .map(String::as_str),
            Some("anthropic-skills")
        );
        assert!(
            !reduced_context.contains_key("attribution_mcp_tool"),
            "attribution_mcp_tool must be stripped from emitted selector_context"
        );
    }

    #[test]
    fn claude_attribution_capture_lifts_only_present_markers_mixed() {
        // Real-world top-level (non-subagent) transcript shape: the line carries
        // MCP-server/MCP-tool + skill attribution but NO `attributionAgent`
        // (subagent attribution lives in the child `subagents/*.jsonl`
        // transcripts, which the daemon walk already ingests as standalone
        // sidechain sessions). Assert capture lifts exactly the present markers
        // and invents nothing for the absent ones — complements the
        // all-five-present and none-present cases above with the realistic
        // partial shape.
        let line: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",\"sessionId\":\"attr-top-level\",",
            "\"attributionSkill\":\"design-sync\",",
            "\"attributionMcpServer\":\"claude-in-chrome\",",
            "\"attributionMcpTool\":\"tabs_context_mcp\",",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":120,\"output_tokens\":48}}}"
        ))
        .expect("parse line");

        let mut selector = SelectorCapture::default();
        capture_claude_attribution(&line, &mut selector, true);

        assert_eq!(
            selector
                .context
                .get("attribution_skill")
                .map(String::as_str),
            Some("design-sync")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_mcp_server")
                .map(String::as_str),
            Some("claude-in-chrome")
        );
        assert_eq!(
            selector
                .context
                .get("attribution_mcp_tool")
                .map(String::as_str),
            Some("tabs_context_mcp")
        );
        // No subagent / plugin markers on this line: they must be absent, not
        // empty-string placeholders.
        assert!(
            !selector.context.contains_key("attribution_subagent"),
            "absent attributionAgent must not synthesize an attribution_subagent key"
        );
        assert!(
            !selector.context.contains_key("attribution_plugin"),
            "absent attributionPlugin must not synthesize an attribution_plugin key"
        );
    }

    #[test]
    fn claude_attribution_capture_is_per_turn_isolated() {
        // Core per-turn discipline: capture runs on the per-LINE selector, so an
        // attribution marker on one turn's line must NOT bleed onto a later
        // turn's line. Each line gets its own SelectorCapture; the second
        // (unattributed) line must surface no attribution from the first.
        let attributed: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",\"attributionAgent\":\"general-purpose\",",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":80,\"output_tokens\":20}}}"
        ))
        .expect("parse attributed line");
        let unattributed: Value = serde_json::from_str(concat!(
            "{\"type\":\"assistant\",",
            "\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":80,\"output_tokens\":20}}}"
        ))
        .expect("parse unattributed line");

        let mut first = SelectorCapture::default();
        capture_claude_attribution(&attributed, &mut first, true);
        let mut second = SelectorCapture::default();
        capture_claude_attribution(&unattributed, &mut second, true);

        assert_eq!(
            first
                .context
                .get("attribution_subagent")
                .map(String::as_str),
            Some("general-purpose"),
            "the attributed turn must carry its own subagent"
        );
        assert!(
            second.is_empty(),
            "a later unattributed turn must not inherit the prior turn's subagent attribution"
        );
    }

    #[test]
    fn codex_logs2_reader_collects_priority_turns_from_sqlite() {
        let codex_dir = temp_dir("codex-logs2-reader");
        let db_path = codex_dir.join("logs_2.sqlite");
        let now = unix_seconds(SystemTime::now()).expect("now") as i64;
        {
            let connection = Connection::open(&db_path).expect("create db");
            connection
                .execute(
                    "CREATE TABLE logs (id INTEGER PRIMARY KEY, ts INTEGER, feedback_log_body TEXT)",
                    [],
                )
                .expect("create table");
            // In-window priority turn -> collected.
            connection
                .execute(
                    "INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)",
                    rusqlite::params![now, priority_request_body(FAST_TURN)],
                )
                .expect("insert fast");
            // In-window standard turn -> ignored.
            connection
                .execute(
                    "INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)",
                    rusqlite::params![
                        now,
                        "turn{turn.id=019ee421-1b3b-71c3-a0a8-ec9f645bf521}: \
                         websocket request: {\"type\":\"response.create\",\"model\":\"gpt-5.5\"}"
                    ],
                )
                .expect("insert std");
            // Out-of-window priority turn -> excluded by ts bound.
            connection
                .execute(
                    "INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)",
                    rusqlite::params![
                        now - 60 * 86_400,
                        priority_request_body("019e0000-0000-7000-8000-000000000000")
                    ],
                )
                .expect("insert old");
        }

        let roots = vec![codex_dir.join("sessions")];
        let map = CodexTurnTraceMap::load_from_roots(&roots, 7);
        assert!(map.is_priority_turn(FAST_TURN));
        assert!(!map.is_priority_turn(STD_TURN));
        assert!(!map.is_priority_turn("019e0000-0000-7000-8000-000000000000"));

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_logs2_tier_stamps_priority_on_fast_turn_only() {
        // Session-cumulative token_count emits one delta per turn. The fast turn
        // (in the logs_2 priority map) must price as priority; the standard turn
        // must carry no service_tier, proving the signal does not bleed forward.
        let path = temp_file("codex-logs2-inject");
        fs::write(
            &path,
            format!(
                concat!(
                    "{{\"timestamp\":\"2026-06-20T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"019ee443-4c18-71c3-843e-847232f694b0\"}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{{\"model\":\"gpt-5.5\",\"turn_id\":\"{fast}\"}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":300,\"output_tokens\":90,\"request_count\":1}},\"model\":\"gpt-5.5\"}}}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:03:00Z\",\"type\":\"turn_context\",\"payload\":{{\"model\":\"gpt-5.5\",\"turn_id\":\"{std}\"}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:04:00Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":400,\"output_tokens\":120,\"request_count\":2}},\"model\":\"gpt-5.5\"}}}}}}\n"
                ),
                fast = FAST_TURN,
                std = STD_TURN,
            ),
        )
        .expect("write fixture");

        let mut map = CodexTurnTraceMap::default();
        map.priority_turns.insert(FAST_TURN.to_string());

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-06-20T10:05:00Z",
            "file-fingerprint".to_string(),
            &CodexTitleMetadata::default(),
            Some(Arc::new(map)),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        let fast = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
            })
            .expect("priority row");
        assert_eq!(fast.input_tokens, 300);
        assert_eq!(fast.output_tokens, 90);
        assert_eq!(
            fast.selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("derived_from_logs_2")
        );
        let standard = item
            .model_usage
            .iter()
            .find(|row| !row.selector_context.contains_key("service_tier"))
            .expect("standard row");
        assert_eq!(standard.input_tokens, 100);
        assert_eq!(standard.output_tokens, 30);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_logs2_tier_absent_map_leaves_turns_standard() {
        // Same fast turn, but no trace map: the parser is unchanged and stamps
        // no service_tier (regression guard for the default path).
        let path = temp_file("codex-logs2-none");
        fs::write(
            &path,
            format!(
                concat!(
                    "{{\"timestamp\":\"2026-06-20T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"019ee443-4c18-71c3-843e-847232f694b0\"}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{{\"model\":\"gpt-5.5\",\"turn_id\":\"{fast}\"}}}}\n",
                    "{{\"timestamp\":\"2026-06-20T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":300,\"output_tokens\":90,\"request_count\":1}},\"model\":\"gpt-5.5\"}}}}}}\n"
                ),
                fast = FAST_TURN,
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-06-20T10:05:00Z",
            "file-fingerprint".to_string(),
            &CodexTitleMetadata::default(),
            None,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.model_usage.len(), 1);
        assert!(!item.model_usage[0]
            .selector_context
            .contains_key("service_tier"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_reads_nested_selector_aliases_and_captures_reasoning_effort() {
        let path = temp_file("codex-selector-aliases");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-444444444444\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"actual_service_tier\":\"priority\",\"reasoning_effort\":\"high\",\"selector_context\":{\"batchMode\":true,\"dataResidency\":\"US\",\"cache_write_ttl_seconds\":3600},\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":30,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("priority")
        );
        assert_eq!(selector.get("batch_mode").map(String::as_str), Some("true"));
        assert_eq!(selector.get("region_mode").map(String::as_str), Some("us"));
        assert_eq!(selector.get("cache_ttl").map(String::as_str), Some("3600"));
        assert_eq!(selector.get("mode"), None);
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("payload.info.actual_service_tier")
        );
        // The per-turn reasoning_effort co-located with total_token_usage is now
        // captured onto the usage row (previously dropped).
        assert_eq!(
            item.model_usage[0].reasoning_effort.as_deref(),
            Some("high")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_captures_max_reasoning_effort_round_trip() {
        let path = temp_file("codex-effort-max");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-20T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-555555555555\"}}\n",
                "{\"timestamp\":\"2026-05-20T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-20T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"reasoning_effort\":\"max\",\"total_token_usage\":{\"input_tokens\":50,\"output_tokens\":12,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-20T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.model_usage[0].reasoning_effort.as_deref(), Some("max"));
        // Round-trips through serde under the exact wire key the backend reads.
        let value = serde_json::to_value(&item.model_usage[0]).expect("serialize row");
        assert_eq!(value["reasoning_effort"], json!("max"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_mixed_effort_in_one_hour_keeps_distinct_rows() {
        let path = temp_file("codex-mixed-effort");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-20T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-mixed-effort\",\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-20T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"reasoning_effort\":\"high\",\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":20,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-05-20T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"reasoning_effort\":\"low\",\"total_token_usage\":{\"input_tokens\":160,\"output_tokens\":32,\"request_count\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(&path, "2026-05-20T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        assert!(item
            .model_usage
            .iter()
            .any(|row| row.reasoning_effort.as_deref() == Some("high") && row.input_tokens == 100));
        assert!(item
            .model_usage
            .iter()
            .any(|row| row.reasoning_effort.as_deref() == Some("low") && row.input_tokens == 60));
        validate_snapshot_item(0, &item).expect("mixed effort validates");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_reads_reasoning_effort_from_turn_context_collaboration_mode() {
        // No usage-co-located effort; falls back to the turn_context
        // collaboration_mode.settings.reasoning_effort path. The turn_context
        // line precedes the token_count line so latest_reasoning_effort is set
        // before the usage row is built.
        let path = temp_file("codex-effort-collab");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-21T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-666666666666\"}}\n",
                "{\"timestamp\":\"2026-05-21T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\",\"collaboration_mode\":{\"settings\":{\"reasoning_effort\":\"low\"}}}}\n",
                "{\"timestamp\":\"2026-05-21T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-21T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.model_usage[0].reasoning_effort.as_deref(), Some("low"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_uses_config_fast_mode_as_low_confidence_default() {
        let root = temp_dir("codex-config-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "service_tier = \"fast\"\n[features]\nfast_mode = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-222222222222\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
            None,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("fast")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("fast"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.features.fast_mode")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_config_defaults_capture_service_tier_model_and_selectors() {
        let root = temp_dir("codex-config-defaults");
        let codex_dir = root.join(".codex");
        fs::create_dir_all(&codex_dir).expect("create .codex");
        fs::write(
            codex_dir.join("config.toml"),
            concat!(
                "model = \"gpt-5.5\"\n",
                "service_tier = \"default\"\n",
                "model_reasoning_effort = \"high\"\n",
                "fast_default_opt_out = true\n",
                "[features]\n",
                "fast_mode = true\n",
            ),
        )
        .expect("write config");

        let defaults = load_codex_config_defaults(&codex_dir.join("config.toml"))
            .expect("config defaults present");
        assert_eq!(defaults.model.as_deref(), Some("gpt-5.5"));
        assert_eq!(defaults.service_tier.as_deref(), Some("default"));
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(defaults.fast_mode, Some(true));
        assert!(defaults.fast_default_opt_out);
        // Top-level scalar keeps the raw config value; selector_context
        // canonicalizes "default" -> "standard" with its config provenance.
        assert_eq!(
            defaults
                .selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("standard")
        );
        assert_eq!(
            defaults
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.service_tier")
        );
        // service_tier=default is authoritative: the effective default is
        // Standard even though the legacy [features].fast_mode flag is set.
        assert_eq!(defaults.display_fast_mode(), Some(false));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_config_defaults_fast_when_service_tier_priority() {
        let root = temp_dir("codex-config-defaults-priority");
        let codex_dir = root.join(".codex");
        fs::create_dir_all(&codex_dir).expect("create .codex");
        fs::write(
            codex_dir.join("config.toml"),
            "service_tier = \"priority\"\n",
        )
        .expect("write config");

        let defaults = load_codex_config_defaults(&codex_dir.join("config.toml"))
            .expect("config defaults present");
        assert_eq!(defaults.service_tier.as_deref(), Some("priority"));
        assert_eq!(defaults.display_fast_mode(), Some(true));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_config_defaults_absent_without_relevant_keys() {
        let root = temp_dir("codex-config-defaults-empty");
        let codex_dir = root.join(".codex");
        fs::create_dir_all(&codex_dir).expect("create .codex");
        fs::write(
            codex_dir.join("config.toml"),
            "personality = \"pragmatic\"\n",
        )
        .expect("write config");

        assert!(load_codex_config_defaults(&codex_dir.join("config.toml")).is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_uses_fast_default_opt_out_as_standard_default() {
        let root = temp_dir("codex-config-standard-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "model = \"gpt-5.5\"\nfast_default_opt_out = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-333333333333\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
            None,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("standard")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("standard"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.fast_default_opt_out")
        );
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.fast_default_opt_out")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_uses_notice_fast_default_opt_out_as_standard_default() {
        let root = temp_dir("codex-notice-standard-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "model = \"gpt-5.5\"\n[notice]\nfast_default_opt_out = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-444444444444\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
            None,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("standard")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("standard"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.notice.fast_default_opt_out")
        );
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.notice.fast_default_opt_out")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_parser_forwards_raw_session_origin() {
        // Claude JSONL lines carry entrypoint/sessionKind/isSidechain; any
        // sidechain line marks the whole session a subagent.
        let path = temp_file("claude");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"sessionId\":\"claude-origin-1\",\"entrypoint\":\"cli\",\"isSidechain\":false,\"summary\":\"t\"}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-origin-1\",\"isSidechain\":true,\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":4,\"output_tokens\":2}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-05-06T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        let origin = item.origin.expect("origin forwarded");
        assert_eq!(origin.entrypoint.as_deref(), Some("cli"));
        assert_eq!(origin.is_sidechain, Some(true));
        // No sibling `<session>/workflows/wf_*.json` footprint -> detection ran
        // and reported false (not None / unknown).
        assert_eq!(origin.used_workflow_orchestration, Some(false));
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "origin_kind" && fact.value == "subagent"));
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "provider_surface" && fact.value == "claude_cli"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_local_otel_effort_splits_bucket_without_changing_totals() {
        let path = temp_file("claude-effort");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-11T10:00:00Z\",\"sessionId\":\"claude-effort-1\",\"summary\":\"t\"}\n",
                "{\"timestamp\":\"2026-07-11T10:01:00Z\",\"sessionId\":\"claude-effort-1\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-07-11T10:02:00Z\",\"sessionId\":\"claude-effort-1\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":20,\"output_tokens\":7}}}\n"
            ),
        )
        .expect("write fixture");
        let mut items =
            parse_claude_code_jsonl_file(&path, "2026-07-11T10:04:00Z", "fp".to_string())
                .expect("parse");
        let evidence = BTreeMap::from([(
            "claude-effort-1".to_string(),
            vec![
                crate::claude_effort::ClaudeEffortEvidence {
                    fingerprint: "one".to_string(),
                    session_id: "claude-effort-1".to_string(),
                    observed_at: "2026-07-11T10:01:00Z".to_string(),
                    model: "claude-opus-4-7".to_string(),
                    effort: "high".to_string(),
                    input_tokens: 10,
                    output_tokens: 5,
                    request_count: 1,
                    ..Default::default()
                },
                crate::claude_effort::ClaudeEffortEvidence {
                    fingerprint: "two".to_string(),
                    session_id: "claude-effort-1".to_string(),
                    observed_at: "2026-07-11T10:02:00Z".to_string(),
                    model: "claude-opus-4-7".to_string(),
                    effort: "low".to_string(),
                    input_tokens: 20,
                    output_tokens: 7,
                    request_count: 1,
                    ..Default::default()
                },
            ],
        )]);

        apply_claude_effort_evidence(&mut items, &evidence);

        assert_eq!(items[0].input_tokens, 30);
        assert_eq!(items[0].output_tokens, 12);
        assert_eq!(items[0].request_count, 2);
        assert_eq!(items[0].model_usage.len(), 2);
        assert_eq!(items[0].usage_buckets[0].model_usage.len(), 2);
        assert!(items[0]
            .model_usage
            .iter()
            .any(|row| row.reasoning_effort.as_deref() == Some("high") && row.input_tokens == 10));
        assert!(items[0]
            .model_usage
            .iter()
            .any(|row| row.reasoning_effort.as_deref() == Some("low") && row.input_tokens == 20));
        validate_snapshot_item(0, &items[0]).expect("split snapshot remains byte-exact");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_local_otel_effort_keeps_unscoped_cache_creation_on_unknown_residual() {
        let path = temp_file("claude-effort-cache-ttl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-12T15:07:58.000Z\",\"sessionId\":\"claude-effort-cache-1\",\"summary\":\"t\"}\n",
                "{\"timestamp\":\"2026-07-12T15:07:58.785Z\",\"sessionId\":\"claude-effort-cache-1\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":2,\"output_tokens\":9,\"cache_creation_input_tokens\":2014,\"cache_creation\":{\"ephemeral_1h_input_tokens\":2014,\"ephemeral_5m_input_tokens\":0}}}}\n"
            ),
        )
        .expect("write fixture");
        let mut items =
            parse_claude_code_jsonl_file(&path, "2026-07-12T15:08:00Z", "fp".to_string())
                .expect("parse");
        let evidence = BTreeMap::from([(
            "claude-effort-cache-1".to_string(),
            vec![crate::claude_effort::ClaudeEffortEvidence {
                fingerprint: "legacy-v0.1.77".to_string(),
                session_id: "claude-effort-cache-1".to_string(),
                observed_at: "2026-07-12T15:07:58.852Z".to_string(),
                model: "claude-opus-4-8".to_string(),
                effort: "low".to_string(),
                input_tokens: 2,
                output_tokens: 9,
                // v0.1.77 stored Claude's aggregate cache_creation_tokens in
                // the 5m field even when the transcript proved they were 1h.
                cache_creation_5m_tokens: 2014,
                request_count: 1,
                ..Default::default()
            }],
        )]);

        apply_claude_effort_evidence(&mut items, &evidence);

        let rows = &items[0].usage_buckets[0].model_usage;
        assert_eq!(rows.len(), 2);
        let low = rows
            .iter()
            .find(|row| row.reasoning_effort.as_deref() == Some("low"))
            .expect("low effort row");
        assert_eq!(low.input_tokens, 2);
        assert_eq!(low.output_tokens, 9);
        assert_eq!(low.request_count, 1);
        assert_eq!(low.cache_creation_5m_tokens, 0);
        assert_eq!(low.cache_creation_1h_tokens, 0);
        let residual = rows
            .iter()
            .find(|row| row.reasoning_effort.is_none())
            .expect("unknown cache residual");
        assert_eq!(residual.request_count, 0);
        assert_eq!(residual.cache_creation_5m_tokens, 0);
        assert_eq!(residual.cache_creation_1h_tokens, 2014);
        validate_snapshot_item(0, &items[0]).expect("enriched snapshot remains byte-exact");

        let mut scoped_items =
            parse_claude_code_jsonl_file(&path, "2026-07-12T15:08:00Z", "fp".to_string())
                .expect("parse scoped fixture");
        let scoped_evidence = BTreeMap::from([(
            "claude-effort-cache-1".to_string(),
            vec![crate::claude_effort::ClaudeEffortEvidence {
                fingerprint: "explicit-1h".to_string(),
                session_id: "claude-effort-cache-1".to_string(),
                observed_at: "2026-07-12T15:07:58.852Z".to_string(),
                model: "claude-opus-4-8".to_string(),
                effort: "low".to_string(),
                input_tokens: 2,
                output_tokens: 9,
                cache_creation_1h_tokens: 2014,
                request_count: 1,
                ..Default::default()
            }],
        )]);
        apply_claude_effort_evidence(&mut scoped_items, &scoped_evidence);
        let scoped_rows = &scoped_items[0].usage_buckets[0].model_usage;
        assert_eq!(scoped_rows.len(), 1);
        assert_eq!(scoped_rows[0].reasoning_effort.as_deref(), Some("low"));
        assert_eq!(scoped_rows[0].cache_creation_1h_tokens, 2014);
        validate_snapshot_item(0, &scoped_items[0])
            .expect("explicit TTL evidence remains byte-exact");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_effort_cache_reconciliation_drops_only_conflicting_ttl_component() {
        let mut rows = vec![(
            "low".to_string(),
            UsageTotals {
                input_tokens: 2,
                output_tokens: 9,
                cache_creation_5m_tokens: 500,
                cache_creation_1h_tokens: 700,
                request_count: 1,
                ..Default::default()
            },
        )];
        let base = UsageTotals {
            input_tokens: 2,
            output_tokens: 9,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 700,
            request_count: 1,
            ..Default::default()
        };

        let reconciled = reconcile_effort_cache_creation(&mut rows, &base)
            .expect("non-cache totals and explicit 1h cache fit");

        assert_eq!(reconciled.cache_creation_5m_tokens, 0);
        assert_eq!(reconciled.cache_creation_1h_tokens, 700);
        assert_eq!(rows[0].1.cache_creation_5m_tokens, 0);
        assert_eq!(rows[0].1.cache_creation_1h_tokens, 700);
    }

    #[test]
    fn claude_subagent_transcript_ingests_as_its_own_sidechain_session() {
        // Claude Code writes Task-tool subagents to
        // `<projectDir>/<parentSessionId>/subagents/agent-<agentId>.jsonl`, and
        // every line is stamped with the PARENT `sessionId`. The parser must
        // re-key the snapshot to a distinct `<parent>_agent-<agentId>` id so it
        // stands up as its own `isSidechain=true` (ai_agent) session instead of
        // collapsing into the human parent session.
        let root = temp_dir("claude-subagent");
        let parent_session = "52c34dcb-44e4-428f-8def-979dd43b7259";
        let subagents_dir = root.join(parent_session).join("subagents");
        fs::create_dir_all(&subagents_dir).expect("create subagents dir");
        let path = subagents_dir.join("agent-a35bc3648272bc00c.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-29T01:16:00.000Z\",\"type\":\"user\",\"sessionId\":\"52c34dcb-44e4-428f-8def-979dd43b7259\",\"agentId\":\"a35bc3648272bc00c\",\"isSidechain\":true,\"message\":{\"role\":\"user\",\"content\":\"map the recipe\"}}\n",
                "{\"timestamp\":\"2026-06-29T01:16:04.000Z\",\"type\":\"assistant\",\"sessionId\":\"52c34dcb-44e4-428f-8def-979dd43b7259\",\"agentId\":\"a35bc3648272bc00c\",\"isSidechain\":true,\"requestId\":\"req_S\",\"message\":{\"id\":\"msg_S\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":40,\"output_tokens\":12}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-06-29T01:20:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        // Distinct from the parent, and URL-path-safe (no `/`): the backend uses
        // `source_session_id` verbatim as its `Session.session_id`, which rides
        // in `/sessions/{session_id}/...` routes.
        assert_eq!(
            item.source_session_id,
            "52c34dcb-44e4-428f-8def-979dd43b7259_agent-a35bc3648272bc00c"
        );
        assert_ne!(item.source_session_id, parent_session);
        assert!(!item.source_session_id.contains('/'));
        // isSidechain=true rides through -> backend classifies this as ai_agent.
        assert_eq!(
            item.origin.expect("origin forwarded").is_sidechain,
            Some(true)
        );
        // The subagent's own tokens, counted once under this new session (they do
        // not appear in the parent transcript, so nothing is double-counted).
        assert_eq!(item.input_tokens, 40);
        assert_eq!(item.output_tokens, 12);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_top_level_transcript_keeps_raw_session_id() {
        // The human-started top-level transcript lives at `<sessionId>.jsonl`,
        // NOT under a `subagents/` directory. Even when it carries an inline
        // sidechain line (older Claude versions inlined them), its
        // `source_session_id` must stay the raw `sessionId` so the parent session
        // is never re-keyed away from where its prior snapshots landed.
        let root = temp_dir("claude-top-level");
        let path = root.join("claude-top-1.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-29T01:00:00Z\",\"type\":\"user\",\"sessionId\":\"claude-top-1\",\"isSidechain\":false,\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n",
                "{\"timestamp\":\"2026-06-29T01:00:02Z\",\"type\":\"assistant\",\"sessionId\":\"claude-top-1\",\"isSidechain\":true,\"requestId\":\"req_T\",\"message\":{\"id\":\"msg_T\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":9,\"output_tokens\":4}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-06-29T01:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.source_session_id, "claude-top-1");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_subagent_source_session_id_discriminates_by_subagents_dir() {
        // Helper contract: only transcripts whose immediate parent directory is
        // `subagents` are re-keyed; everything else returns None (raw id kept).
        let sub = Path::new("/p/proj/PARENT/subagents/agent-abc123.jsonl");
        assert_eq!(
            claude_subagent_source_session_id(sub, "PARENT").as_deref(),
            Some("PARENT_agent-abc123")
        );
        // Top-level transcript -> None.
        let top = Path::new("/p/proj/PARENT.jsonl");
        assert_eq!(claude_subagent_source_session_id(top, "PARENT"), None);
        // A nested but non-`subagents` sibling dir -> None.
        let other = Path::new("/p/proj/PARENT/workflows/wf.jsonl");
        assert_eq!(claude_subagent_source_session_id(other, "PARENT"), None);
    }

    #[test]
    fn claude_parser_detects_workflow_orchestration_footprint() {
        // The Workflow tool (dynamic orchestration, e.g. `ultracode`) leaves a
        // local manifest at `<projectDir>/<sessionId>/workflows/wf_*.json`, a
        // sibling of the `<sessionId>.jsonl` we parse. Presence -> Some(true).
        let dir = temp_dir("claude-wf");
        let path = dir.join("claude-wf-session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"sessionId\":\"claude-wf-session\",\"entrypoint\":\"cli\",\"summary\":\"t\"}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-wf-session\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":8,\"output_tokens\":3}}}\n"
            ),
        )
        .expect("write fixture");
        let workflows_dir = path.with_extension("").join("workflows");
        fs::create_dir_all(&workflows_dir).expect("create workflows dir");
        // Manifest filenames are truncated in practice (e.g. wf_60f3dab6-4fa.json).
        fs::write(workflows_dir.join("wf_60f3dab6-4fa.json"), "{}").expect("write manifest");

        let item = parse_claude_code_jsonl_file(&path, "2026-05-06T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        let origin = item.origin.expect("origin forwarded");
        assert_eq!(origin.used_workflow_orchestration, Some(true));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn claude_workflow_detect_env_opt_out_parses() {
        assert!(claude_workflow_detect_enabled_from(None));
        assert!(claude_workflow_detect_enabled_from(Some("on")));
        assert!(!claude_workflow_detect_enabled_from(Some("off")));
        assert!(!claude_workflow_detect_enabled_from(Some("0")));
        assert!(!claude_workflow_detect_enabled_from(Some(" Disabled ")));
    }

    #[test]
    fn claude_code_parser_sums_message_usage_and_uses_summary_title() {
        let path = temp_file("claude");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"sessionId\":\"claude-session-1\",\"summary\":\"Fix telemetry labels\"}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-session-1\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":3}}}\n",
                "{\"timestamp\":\"2026-05-06T10:02:00Z\",\"sessionId\":\"claude-session-1\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9,\"cache_creation_input_tokens\":2}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.source_session_id, "claude-session-1");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Fix telemetry labels")
        );
        assert_eq!(item.input_tokens, 17);
        assert_eq!(item.cache_read_tokens, 3);
        // Flat `cache_creation_input_tokens` with no nested split defaults to the 5m bucket
        // (Anthropic's default TTL).
        assert_eq!(item.cache_creation_5m_tokens, 2);
        assert_eq!(item.cache_creation_1h_tokens, 0);
        assert_eq!(item.output_tokens, 14);
        assert_eq!(item.request_count, 2);
        assert_eq!(item.usage_buckets.len(), 1);
        let bucket = &item.usage_buckets[0];
        assert_eq!(bucket.bucket_start, "2026-05-06T10:00:00Z");
        assert_eq!(
            bucket.first_activity_at.as_deref(),
            Some("2026-05-06T10:01:00Z")
        );
        assert_eq!(
            bucket.last_activity_at.as_deref(),
            Some("2026-05-06T10:02:00Z")
        );
        let bucket_request_count: u64 = bucket.model_usage.iter().map(|r| r.request_count).sum();
        assert_eq!(bucket_request_count, 2);
        assert_eq!(item.model_usage[0].model, "claude-sonnet-4-6");
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("uncached")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_duplicate_content_block_records_count_usage_once() {
        // Claude Code writes one JSONL record per assistant content block; all
        // records of one API response share message.id + requestId and repeat
        // byte-identical usage. Only the first may count.
        let path = temp_file("claude-dedup-same-response");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-30T10:01:00Z\",\"sessionId\":\"claude-dedup-1\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":3}}}\n",
                "{\"timestamp\":\"2026-06-30T10:01:01Z\",\"sessionId\":\"claude-dedup-1\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":3}}}\n",
                "{\"timestamp\":\"2026-06-30T10:01:02Z\",\"sessionId\":\"claude-dedup-1\",\"requestId\":\"req_011AAA\",\"isSidechain\":true,\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":3}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.input_tokens, 10);
        assert_eq!(item.output_tokens, 5);
        assert_eq!(item.cache_read_tokens, 3);
        // Dedup fixes request_count implicitly: one counted usage = one request.
        assert_eq!(item.request_count, 1);
        // Duplicate records still contribute NON-usage signals: the sidechain
        // flag rode in on the third (skipped-usage) record.
        assert_eq!(
            item.origin.expect("origin forwarded").is_sidechain,
            Some(true)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_distinct_response_ids_count_separately() {
        let path = temp_file("claude-dedup-distinct-ids");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-30T11:01:00Z\",\"sessionId\":\"claude-dedup-2\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-06-30T11:02:00Z\",\"sessionId\":\"claude-dedup-2\",\"requestId\":\"req_011BBB\",\"message\":{\"id\":\"msg_011BBB\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T11:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.input_tokens, 17);
        assert_eq!(item.output_tokens, 14);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_usage_without_ids_counts_each_line() {
        // No message.id and no requestId: nothing to dedup on, so identical
        // usage on consecutive lines still counts per line (legacy behavior).
        let path = temp_file("claude-dedup-no-ids");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-30T12:01:00Z\",\"sessionId\":\"claude-dedup-3\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-06-30T12:02:00Z\",\"sessionId\":\"claude-dedup-3\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T12:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.input_tokens, 20);
        assert_eq!(item.output_tokens, 10);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_same_message_id_different_request_id_counts_separately() {
        // Conservative pair-keying: identical message.id under different
        // requestIds is treated as two distinct API responses (e.g. a retry).
        let path = temp_file("claude-dedup-pair-key");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-06-30T13:01:00Z\",\"sessionId\":\"claude-dedup-4\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-06-30T13:02:00Z\",\"sessionId\":\"claude-dedup-4\",\"requestId\":\"req_011BBB\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-06-30T13:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.input_tokens, 20);
        assert_eq!(item.output_tokens, 10);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_derives_context_posture_watermarks() {
        // Multi-turn transcript: the first counted response with any effective
        // input context (input + cache reads + cache writes) sets the baseline;
        // the running max across counted responses is the peak. An output-only
        // response (zero effective context) must not claim the baseline, and
        // duplicate content-block records of one response (same message.id +
        // requestId) ride the existing once-per-response dedup.
        let path = temp_file("claude-context-posture");
        fs::write(
            &path,
            concat!(
                // Output-only response: effective context 0 -> no baseline.
                "{\"timestamp\":\"2026-07-01T10:00:00Z\",\"sessionId\":\"claude-posture-1\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":0,\"output_tokens\":4}}}\n",
                // Baseline turn: 100 input + 900 cache read = 1000 effective.
                "{\"timestamp\":\"2026-07-01T10:01:00Z\",\"sessionId\":\"claude-posture-1\",\"requestId\":\"req_011BBB\",\"message\":{\"id\":\"msg_011BBB\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":5,\"cache_read_input_tokens\":900}}}\n",
                // Peak turn: 200 + 4000 read + 800 cache write = 5000 effective,
                // written twice (duplicate content-block records, same ids).
                "{\"timestamp\":\"2026-07-01T10:02:00Z\",\"sessionId\":\"claude-posture-1\",\"requestId\":\"req_011CCC\",\"message\":{\"id\":\"msg_011CCC\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":200,\"output_tokens\":7,\"cache_read_input_tokens\":4000,\"cache_creation\":{\"ephemeral_5m_input_tokens\":800}}}}\n",
                "{\"timestamp\":\"2026-07-01T10:02:01Z\",\"sessionId\":\"claude-posture-1\",\"requestId\":\"req_011CCC\",\"message\":{\"id\":\"msg_011CCC\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":200,\"output_tokens\":7,\"cache_read_input_tokens\":4000,\"cache_creation\":{\"ephemeral_5m_input_tokens\":800}}}}\n",
                // Later smaller turn: 3000 effective, peak must stay 5000.
                "{\"timestamp\":\"2026-07-01T10:03:00Z\",\"sessionId\":\"claude-posture-1\",\"requestId\":\"req_011DDD\",\"message\":{\"id\":\"msg_011DDD\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":3000,\"output_tokens\":2}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-07-01T10:05:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.first_turn_context_tokens, Some(1000));
        assert_eq!(item.peak_context_fill_tokens, Some(5000));
        // No isCompactSummary records: observed-zero, not unknown.
        assert_eq!(item.compaction_count, Some(0));
        // Dedup really gated the duplicate peak records (4 counted responses).
        assert_eq!(item.request_count, 4);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_counts_compaction_records() {
        // Compaction (auto or /compact) injects a type=user record flagged
        // with top-level `isCompactSummary: true`. Each one counts; an
        // explicit `false` does not.
        let path = temp_file("claude-compaction-count");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-01T11:00:00Z\",\"sessionId\":\"claude-compact-1\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":50,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-07-01T11:01:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":true,\"isVisibleInTranscriptOnly\":true,\"message\":{\"role\":\"user\",\"content\":\"summary\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:02:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":false,\"message\":{\"role\":\"user\",\"content\":\"regular prompt\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:03:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":true,\"isVisibleInTranscriptOnly\":true,\"message\":{\"role\":\"user\",\"content\":\"summary again\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:04:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"assistant\",\"isCompactSummary\":true,\"message\":{\"role\":\"assistant\",\"content\":\"not a compaction event\"}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-07-01T11:05:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.compaction_count, Some(2));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_derives_context_posture_watermarks() {
        // Codex reports each response's own usage in `last_token_usage`, so the
        // watermarks come from there. Shapes asserted, in file order:
        //   * turn 1 (22817) sets the first-turn baseline,
        //   * turn 2 (33205) raises the peak,
        //   * a DUPLICATE of turn 2 must be idempotent (max/first, not a sum),
        //   * turn 3 (45272) is the session peak,
        //   * the zero-usage event Codex emits at a compaction is ignored,
        //   * the post-compaction turn (25182) drops well below the peak, which
        //     must retain the pre-compaction high-water mark.
        let path = temp_file("codex-context-posture");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-17T03:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019f6d5f-abbf-7502-9448-a68952e2c988\"}}\n",
                "{\"timestamp\":\"2026-07-17T03:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":22817,\"cached_input_tokens\":9984,\"output_tokens\":440},\"last_token_usage\":{\"input_tokens\":22817,\"cached_input_tokens\":9984,\"output_tokens\":440},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T03:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":56022,\"cached_input_tokens\":32256,\"output_tokens\":921},\"last_token_usage\":{\"input_tokens\":33205,\"cached_input_tokens\":22272,\"output_tokens\":481},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T03:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":56022,\"cached_input_tokens\":32256,\"output_tokens\":921},\"last_token_usage\":{\"input_tokens\":33205,\"cached_input_tokens\":22272,\"output_tokens\":481},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T03:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":101294,\"cached_input_tokens\":75008,\"output_tokens\":1165},\"last_token_usage\":{\"input_tokens\":45272,\"cached_input_tokens\":42752,\"output_tokens\":244},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T03:04:00Z\",\"type\":\"compacted\",\"payload\":{\"message\":\"\",\"replacement_history\":[]}}\n",
                "{\"timestamp\":\"2026-07-17T03:04:01Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":101294,\"cached_input_tokens\":75008,\"output_tokens\":1165},\"last_token_usage\":{\"input_tokens\":0,\"cached_input_tokens\":0,\"output_tokens\":0},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T03:04:02Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"context_compacted\"}}\n",
                "{\"timestamp\":\"2026-07-17T03:05:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":126476,\"cached_input_tokens\":97280,\"output_tokens\":1300},\"last_token_usage\":{\"input_tokens\":25182,\"cached_input_tokens\":22272,\"output_tokens\":135},\"model_context_window\":258400,\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-07-17T03:06:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.first_turn_context_tokens, Some(22817));
        assert_eq!(item.peak_context_fill_tokens, Some(45272));
        // The `compacted` rollout record and its paired `context_compacted` UI
        // event describe ONE compaction; counting both would report two.
        assert_eq!(item.compaction_count, Some(1));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_context_posture_reads_per_turn_usage_not_the_cumulative() {
        // Regression guard for the two ways the cumulative `total_token_usage`
        // misreports per-turn context, both taken from real rollouts:
        //   * the cumulative is a session-wide SUM, so on turn 2 it is 56022
        //     while the turn's actual context is 33205;
        //   * Codex `input_tokens` already includes `cached_input_tokens`, so
        //     adding cache reads (the Claude-side formula) would report
        //     33205 + 22272 = 55477 for a turn that saw 33205.
        // Either mistake inflates the peak, and the backend divides the peak by
        // the model's context window — so an inflated peak reads as a session
        // filling far more of its window than it did.
        let path = temp_file("codex-posture-not-cumulative");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-17T04:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019f6d5f-1111-7502-9448-bbbbbbbbbbbb\"}}\n",
                "{\"timestamp\":\"2026-07-17T04:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":22817,\"cached_input_tokens\":9984,\"output_tokens\":440},\"last_token_usage\":{\"input_tokens\":22817,\"cached_input_tokens\":9984,\"output_tokens\":440},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-17T04:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":56022,\"cached_input_tokens\":32256,\"output_tokens\":921},\"last_token_usage\":{\"input_tokens\":33205,\"cached_input_tokens\":22272,\"output_tokens\":481},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-07-17T04:03:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.peak_context_fill_tokens, Some(33205));
        // The session-wide cumulative and the cache-additive figure must never
        // surface as a context reading.
        assert_ne!(item.peak_context_fill_tokens, Some(56022));
        assert_ne!(item.peak_context_fill_tokens, Some(55477));
        // Usage accounting still reconciles off the cumulative deltas, and
        // stays inclusive-scoped: `input_tokens` is the session-wide total with
        // `cache_read_tokens` as a SUBSET of it, not an addend (the backend
        // subtracts that subset exactly once, per `input_token_scope`). Summing
        // the two here would yield 88278 — the same double-count that must
        // never reach a context reading above.
        assert_eq!(item.input_tokens, 56022);
        assert_eq!(item.cache_read_tokens, 32256);
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("inclusive_cached")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_sessions_without_per_turn_usage_claim_no_context() {
        // A rollout whose `token_count` events carry no `last_token_usage`
        // yields no context reading rather than a guess derived from the
        // cumulative. `compaction_count` is still Some(0): the parser DID read
        // this transcript's compaction records and saw none, which is an
        // observation, not a gap.
        let path = temp_file("codex-no-last-token-usage");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-01T12:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-7777-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-07-01T12:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":50,\"output_tokens\":9},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-07-01T12:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.peak_context_fill_tokens, None);
        assert_eq!(item.first_turn_context_tokens, None);
        assert_eq!(item.compaction_count, Some(0));
        let serialized = serde_json::to_value(&item).expect("serialize");
        assert!(serialized.get("peak_context_fill_tokens").is_none());
        assert!(serialized.get("first_turn_context_tokens").is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_context_posture_fields_change_snapshot_fingerprint() {
        // Codex posture joins the fingerprint payload on purpose: that is what
        // re-uploads every already-collected Codex session once, so the backend
        // can backfill posture for history rather than only new sessions.
        let path = temp_file("codex-posture-fingerprint");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-01T12:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-8888-7000-9000-cccccccccccc\"}}\n",
                "{\"timestamp\":\"2026-07-01T12:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":5000,\"cached_input_tokens\":1000,\"output_tokens\":9},\"last_token_usage\":{\"input_tokens\":5000,\"cached_input_tokens\":1000,\"output_tokens\":9},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-07-01T12:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.peak_context_fill_tokens, Some(5000));
        let mut without_posture = item.clone();
        without_posture.peak_context_fill_tokens = None;
        without_posture.first_turn_context_tokens = None;
        without_posture.compaction_count = None;
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::Codex, &item),
            snapshot_fingerprint(SnapshotSource::Codex, &without_posture)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_sessions_emit_no_context_posture_fields() {
        // Pi derives no posture, so all three fields stay None and serialize
        // away — and posture must not be a Pi fingerprint dimension, or every
        // Pi session would re-upload on upgrade carrying nothing new.
        let path = temp_file("pi-no-context-posture");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-eeee-7000-9000-444444444444\",\"cwd\":\"/Users/example/work\",\"timestamp\":\"2026-05-19T11:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234002000,\"usage\":{\"input\":80,\"output\":20,\"cacheRead\":10,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-19T11:05:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.peak_context_fill_tokens, None);
        assert_eq!(item.first_turn_context_tokens, None);
        assert_eq!(item.compaction_count, None);
        let serialized = serde_json::to_value(&item).expect("serialize");
        assert!(serialized.get("peak_context_fill_tokens").is_none());
        assert!(serialized.get("first_turn_context_tokens").is_none());
        assert!(serialized.get("compaction_count").is_none());

        let fingerprint = snapshot_fingerprint(SnapshotSource::Pi, &item);
        let mut mutated = item.clone();
        mutated.peak_context_fill_tokens = Some(10);
        mutated.first_turn_context_tokens = Some(5);
        mutated.compaction_count = Some(1);
        assert_eq!(
            snapshot_fingerprint(SnapshotSource::Pi, &mutated),
            fingerprint
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn context_posture_fields_change_snapshot_fingerprint() {
        // The posture fields are part of the fingerprint payload on purpose
        // (same one-time backfill rationale as `origin`): a daemon that starts
        // deriving them re-uploads every already-collected Claude session once.
        let path = temp_file("claude-posture-fingerprint");
        fs::write(
            &path,
            "{\"timestamp\":\"2026-07-01T13:00:00Z\",\"sessionId\":\"claude-posture-fp\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":5}}}\n",
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-07-01T13:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        let mut without_posture = item.clone();
        without_posture.peak_context_fill_tokens = None;
        without_posture.first_turn_context_tokens = None;
        without_posture.compaction_count = None;
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &item),
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &without_posture)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_prefers_ai_title_rows() {
        let path = temp_file("claude-ai-title");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"ai-title\",\"sessionId\":\"claude-session-title\",\"aiTitle\":\"Tighten dashboard activity feed\"}\n",
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"sessionId\":\"claude-session-title\",\"summary\":\"Claude Code session\"}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-session-title\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":35,\"output_tokens\":8}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.source_session_id, "claude-session-title");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Tighten dashboard activity feed")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("ai_title")
        );

        let _ = fs::remove_file(path);
    }

    /// Build a fake home with one Claude transcript and one desktop-store
    /// session file, returning (home, transcript_path, projects_root).
    fn claude_desktop_fixture(
        name: &str,
        session_id: &str,
        desktop_json: &str,
        transcript: &str,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let home = temp_dir(name);
        let projects_root = home.join(".claude").join("projects");
        let project_dir = projects_root.join("-Users-dev-repo");
        fs::create_dir_all(&project_dir).expect("create project dir");
        let transcript_path = project_dir.join(format!("{session_id}.jsonl"));
        fs::write(&transcript_path, transcript).expect("write transcript");
        let store_dir = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-ctx")
            .join("workspace");
        fs::create_dir_all(&store_dir).expect("create store dir");
        fs::write(store_dir.join("local_desktop-1.json"), desktop_json).expect("write store");
        (home, transcript_path, projects_root)
    }

    #[test]
    fn claude_desktop_store_title_applies_to_matching_session() {
        let (home, transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-title",
            "11111111-2222-3333-4444-555555555555",
            "{\"sessionId\":\"local_aaa\",\"cliSessionId\":\"11111111-2222-3333-4444-555555555555\",\"title\":\"Cost report export columns\",\"titleSource\":\"auto\"}",
            "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"11111111-2222-3333-4444-555555555555\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":35,\"output_tokens\":8}}}\n",
        );
        let metadata = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_eq!(metadata.titles.len(), 1);

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript_path,
            "2026-07-10T10:04:00Z",
            "fp".to_string(),
            &metadata,
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Cost report export columns")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("desktop_title")
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_desktop_auto_title_does_not_override_transcript_title() {
        let (home, transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-auto-vs-transcript",
            "s-1",
            "{\"cliSessionId\":\"s-1\",\"title\":\"Desktop auto title\",\"titleSource\":\"auto\"}",
            concat!(
                "{\"type\":\"ai-title\",\"sessionId\":\"s-1\",\"aiTitle\":\"Transcript ai title\"}\n",
                "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"s-1\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
            ),
        );
        let metadata = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript_path,
            "2026-07-10T10:04:00Z",
            "fp".to_string(),
            &metadata,
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Transcript ai title")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("ai_title")
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_desktop_user_title_overrides_transcript_title() {
        let (home, transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-user-override",
            "s-2",
            "{\"cliSessionId\":\"s-2\",\"title\":\"My renamed session\",\"titleSource\":\"user\"}",
            concat!(
                "{\"timestamp\":\"2026-07-10T10:00:00Z\",\"sessionId\":\"s-2\",\"summary\":\"Stale summary title\"}\n",
                "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"s-2\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
            ),
        );
        let metadata = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript_path,
            "2026-07-10T10:04:00Z",
            "fp".to_string(),
            &metadata,
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("My renamed session")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("desktop_title")
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_subagent_transcript_never_inherits_parent_desktop_title() {
        let (home, transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-subagent",
            "parent-1",
            "{\"cliSessionId\":\"parent-1\",\"title\":\"Parent session title\",\"titleSource\":\"auto\"}",
            "{\"timestamp\":\"2026-07-10T10:00:00Z\",\"sessionId\":\"parent-1\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
        );
        // The subagent transcript carries the PARENT's sessionId on every line.
        let subagents_dir = transcript_path.with_extension("").join("subagents");
        fs::create_dir_all(&subagents_dir).expect("create subagents dir");
        let subagent_path = subagents_dir.join("agent-abc123.jsonl");
        fs::write(
            &subagent_path,
            "{\"timestamp\":\"2026-07-10T10:02:00Z\",\"sessionId\":\"parent-1\",\"isSidechain\":true,\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}\n",
        )
        .expect("write subagent transcript");
        let metadata = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &subagent_path,
            "2026-07-10T10:04:00Z",
            "fp".to_string(),
            &metadata,
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.source_session_id, "parent-1_agent-abc123");
        assert_eq!(item.session_display_name, None);

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_title_metadata_fingerprint_tracks_title_content_only() {
        let (home, _transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-fingerprint",
            "s-3",
            "{\"cliSessionId\":\"s-3\",\"title\":\"First title\",\"titleSource\":\"auto\"}",
            "",
        );
        let store_file = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-ctx")
            .join("workspace")
            .join("local_desktop-1.json");
        let first = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));

        // Rewriting the file with the SAME title (mtime/size churn from
        // ordinary session activity) must keep the fingerprint stable...
        fs::write(
            &store_file,
            "{\"cliSessionId\":\"s-3\",\"title\":\"First title\",\"titleSource\":\"auto\",\"lastFocusedAt\":\"2026-07-10T11:00:00Z\"}",
        )
        .expect("rewrite store");
        let same = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_eq!(first.sidecar_fingerprint, same.sidecar_fingerprint);

        // ...while an actual title change must change it so unchanged
        // transcripts re-parse and pick the new title up.
        fs::write(
            &store_file,
            "{\"cliSessionId\":\"s-3\",\"title\":\"Second title\",\"titleSource\":\"user\"}",
        )
        .expect("rewrite store with new title");
        let changed = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_ne!(first.sidecar_fingerprint, changed.sidecar_fingerprint);

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_first_prompt_falls_back_when_no_title_exists() {
        let path = temp_file("claude-first-prompt");
        fs::write(
            &path,
            concat!(
                // Harness wrappers and tool_result user records never title.
                "{\"type\":\"user\",\"sessionId\":\"s-4\",\"message\":{\"role\":\"user\",\"content\":\"<command-name>/model</command-name>\"}}\n",
                "{\"type\":\"user\",\"sessionId\":\"s-4\",\"isMeta\":true,\"message\":{\"role\":\"user\",\"content\":\"Caveat: the messages below were generated by the user while running local commands\"}}\n",
                "{\"type\":\"user\",\"sessionId\":\"s-4\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"t1\",\"content\":[{\"type\":\"text\",\"text\":\"file contents here\"}]}]}}\n",
                "{\"type\":\"user\",\"sessionId\":\"s-4\",\"timestamp\":\"2026-07-10T10:00:00Z\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"fix the flaky sessions table sort\"}]}}\n",
                "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"s-4\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-10T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("fix the flaky sessions table sort")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_transcript_title_beats_first_prompt_fallback() {
        let path = temp_file("claude-first-prompt-vs-summary");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"user\",\"sessionId\":\"s-5\",\"message\":{\"role\":\"user\",\"content\":\"rename all the things\"}}\n",
                "{\"timestamp\":\"2026-07-10T10:00:00Z\",\"sessionId\":\"s-5\",\"summary\":\"Rename cleanup pass\"}\n",
                "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"s-5\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-10T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Rename cleanup pass")
        );
        assert_eq!(item.session_display_name_source.as_deref(), Some("summary"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_zero_token_usage_events_drop_from_buckets() {
        let path = temp_file("claude-zero-token-activity");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-session-zero\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-05-06T10:02:00Z\",\"sessionId\":\"claude-session-zero\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        // v6 couples usage and activity into the same bucket-row aggregation;
        // a token-less event with no usage has nothing to attribute to the
        // hour, so the second event drops out entirely. v5 would have
        // counted it in activity_buckets but never in model_usage.
        assert_eq!(item.request_count, 1);
        assert_eq!(item.usage_buckets.len(), 1);
        assert_eq!(item.usage_buckets[0].bucket_start, "2026-05-06T10:00:00Z");
        assert_eq!(
            item.usage_buckets[0].first_activity_at.as_deref(),
            Some("2026-05-06T10:01:00Z")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_builds_distinct_hourly_usage_buckets() {
        let path = temp_file("claude-activity-buckets");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:59:59Z\",\"sessionId\":\"claude-session-buckets\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-05-06T11:00:01Z\",\"sessionId\":\"claude-session-buckets\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T11:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.usage_buckets.len(), 2);
        assert_eq!(item.usage_buckets[0].bucket_start, "2026-05-06T10:00:00Z");
        assert_eq!(
            item.usage_buckets[0].first_activity_at.as_deref(),
            Some("2026-05-06T10:59:59Z")
        );
        assert_eq!(item.usage_buckets[0].model_usage[0].request_count, 1);
        assert_eq!(item.usage_buckets[1].bucket_start, "2026-05-06T11:00:00Z");
        assert_eq!(
            item.usage_buckets[1].first_activity_at.as_deref(),
            Some("2026-05-06T11:00:01Z")
        );
        assert_eq!(item.usage_buckets[1].model_usage[0].request_count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_preserves_speed_region_and_batch_selectors() {
        let path = temp_file("claude-selectors");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"sessionId\":\"claude-selector\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":100,\"output_tokens\":30,\"speed\":\"fast\",\"inference_geo\":\"us\"}}}\n",
                "{\"timestamp\":\"2026-05-19T10:05:00Z\",\"sessionId\":\"claude-selector\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":200,\"output_tokens\":60,\"speed\":\"standard\",\"batch_mode\":true,\"context_bucket\":\"long\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-19T10:10:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        let fast = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("speed_mode").map(String::as_str) == Some("fast"))
            .expect("fast row");
        let batch = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("batch_mode").map(String::as_str) == Some("true"))
            .expect("batch row");
        assert_eq!(
            fast.selector_context.get("region_mode").map(String::as_str),
            Some("us")
        );
        assert_eq!(
            fast.selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("fast")
        );
        assert_eq!(
            batch
                .selector_context
                .get("context_bucket")
                .map(String::as_str),
            Some("long")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_extracts_ephemeral_cache_creation_split() {
        let path = temp_file("claude-ephemeral");
        fs::write(
            &path,
            concat!(
                // 1h-heavy block (mirrors the real Claude Code transcript on disk).
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":6,\"output_tokens\":370,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":33383,\"cache_creation\":{\"ephemeral_5m_input_tokens\":0,\"ephemeral_1h_input_tokens\":33383}}}}\n",
                // 5m-heavy block.
                "{\"timestamp\":\"2026-05-19T10:05:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":4,\"output_tokens\":120,\"cache_read_input_tokens\":12,\"cache_creation_input_tokens\":2500,\"cache_creation\":{\"ephemeral_5m_input_tokens\":2500,\"ephemeral_1h_input_tokens\":0}}}}\n",
                // Mixed.
                "{\"timestamp\":\"2026-05-19T10:10:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":2,\"output_tokens\":60,\"cache_read_input_tokens\":40,\"cache_creation_input_tokens\":3000,\"cache_creation\":{\"ephemeral_5m_input_tokens\":1000,\"ephemeral_1h_input_tokens\":2000}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-19T10:15:00Z",
            "ephemeral-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.cache_creation_5m_tokens, 3500);
        assert_eq!(item.cache_creation_1h_tokens, 35383);
        assert_eq!(item.cache_read_tokens, 52);
        // The flat `cache_creation_input_tokens` field must not be double-counted: when
        // nested values are non-zero we trust the split, never both.
        assert_eq!(
            item.cache_creation_5m_tokens + item.cache_creation_1h_tokens,
            38883
        );
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.model_usage[0].cache_creation_5m_tokens, 3500);
        assert_eq!(item.model_usage[0].cache_creation_1h_tokens, 35383);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_usage_accepts_future_cache_write_alias() {
        let value = serde_json::json!({
            "total_token_usage": {
                "input_tokens": 100,
                "cached_input_tokens": 30,
                "cache_write_tokens": 20,
                "output_tokens": 5,
                "request_count": 1
            }
        });
        let usage = codex_total_usage(&value).expect("usage");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_creation_5m_tokens, 20);
    }

    #[test]
    fn codex_usage_accepts_official_openai_input_details_shape() {
        let value = serde_json::json!({
            "total_token_usage": {
                "input_tokens": 100,
                "input_tokens_details": {
                    "cached_tokens": 30,
                    "cache_write_tokens": 20
                },
                "output_tokens": 5,
                "request_count": 1
            }
        });
        let usage = codex_total_usage(&value).expect("usage");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_creation_5m_tokens, 20);
    }

    #[test]
    fn pi_parser_applies_selector_custom_entries_to_following_messages() {
        let path = temp_file("pi-selector");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-dddd-7000-9000-333333333333\",\"cwd\":\"/Users/example/work\",\"timestamp\":\"2026-05-19T11:00:00Z\"}\n",
                "{\"type\":\"custom\",\"customType\":\"ottto-selector\",\"data\":{\"selector_context\":{\"service_tier\":\"flex\",\"batch_mode\":true,\"context_bucket\":\"long\"}},\"timestamp\":1779234001000}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234002000,\"usage\":{\"input\":80,\"output\":20,\"cacheRead\":0,\"cacheWrite\":0}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234003000,\"usage\":{\"input\":40,\"output\":10,\"cacheRead\":0,\"cacheWrite\":0},\"speed\":\"fast\"}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-19T11:05:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        let flex_batch = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("flex")
            })
            .expect("flex row");
        let fast = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("speed_mode").map(String::as_str) == Some("fast"))
            .expect("fast row");
        assert_eq!(flex_batch.input_tokens, 80);
        assert_eq!(
            flex_batch
                .selector_context
                .get("batch_mode")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(fast.input_tokens, 40);
        assert_eq!(
            fast.selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("fast")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_splits_cache_write_1h_from_flat_total() {
        let path = temp_file("pi-cache-write-1h");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"pi-cache-write-1h\",\"cwd\":\"/work\",\"timestamp\":\"2026-05-19T11:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"anthropic\",\"model\":\"claude-opus-4-7\",\"timestamp\":1779234002000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":20,\"cacheWrite\":15,\"cacheWrite1h\":9,\"cost\":{\"total\":0.0042,\"input\":0.001,\"output\":0.002,\"cacheRead\":0.0002,\"cacheWrite\":0.001}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-19T11:05:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.cache_creation_5m_tokens, 6);
        assert_eq!(item.cache_creation_1h_tokens, 9);
        assert_eq!(item.model_usage[0].cache_creation_5m_tokens, 6);
        assert_eq!(item.model_usage[0].cache_creation_1h_tokens, 9);
        assert_eq!(item.model_usage[0].cost_usd.as_deref(), Some("0.0042"));
        assert_eq!(
            item.model_usage[0].cache_creation_cost_usd.as_deref(),
            Some("0.001")
        );
        let cost = item.cost.as_ref().expect("snapshot cost");
        assert_eq!(cost.total_cost_usd.as_deref(), Some("0.0042"));
        assert_eq!(cost.cache_creation_cost_usd.as_deref(), Some("0.001"));
        assert_eq!(
            item.usage_buckets[0].model_usage[0].cost_usd,
            item.model_usage[0].cost_usd
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_cost_parser_preserves_partial_and_invalid_field_coverage() {
        let partial = serde_json::json!({
            "cost": {
                "total": null,
                "input": "0.001",
                "output": "invalid",
                "cacheRead": -1
            }
        });
        let costs = pi_usage_costs(&partial);
        assert!(costs.observed);
        assert!(costs.reported);
        assert_eq!(costs.total, None);
        assert_eq!(costs.input, Some(1_000_000_000));
        assert_eq!(costs.output, None);
        assert_eq!(costs.cache_read, None);
        let snapshot_cost = costs.snapshot_cost().expect("partial cost evidence");
        assert_eq!(snapshot_cost.total_cost_usd, None);
        assert_eq!(snapshot_cost.input_cost_usd.as_deref(), Some("0.001"));

        let invalid = pi_usage_costs(&serde_json::json!({
            "cost": {"total": null, "input": "invalid"}
        }));
        assert!(invalid.observed);
        assert!(!invalid.reported);
        assert_eq!(invalid.snapshot_cost(), None);

        let mut aggregate = costs.clone();
        aggregate.add(&invalid);
        assert!(!aggregate.reported);
        assert_eq!(aggregate.snapshot_cost(), None);
    }

    #[test]
    fn pi_parser_sums_message_end_usage_and_extracts_session_meta() {
        let path = temp_file("pi-basic");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-aaaa-7000-9000-111111111111\",\"cwd\":\"/Users/example/work\",\"version\":\"0.42\",\"timestamp\":\"2026-05-14T22:00:00Z\"}\n",
                "{\"type\":\"message\",\"role\":\"user\",\"content\":\"Summarize the changes in the diff\",\"timestamp\":1779234001000}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779234002000,\"usage\":{\"input\":100,\"output\":40,\"cacheRead\":20,\"cacheWrite\":5,\"cost\":{\"total\":0.0011,\"input\":0.0005,\"output\":0.0004,\"cacheRead\":0.0001,\"cacheWrite\":0.0001}}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779234004000,\"usage\":{\"input\":50,\"output\":15,\"cacheRead\":10,\"cacheWrite\":0,\"cost\":{\"total\":0.0006,\"input\":0.0002,\"output\":0.0003,\"cacheRead\":0.0001,\"cacheWrite\":0.0}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-14T22:05:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "019e2700-aaaa-7000-9000-111111111111"
        );
        assert_eq!(item.input_tokens, 150);
        assert_eq!(item.output_tokens, 55);
        assert_eq!(item.cache_read_tokens, 30);
        // Gemini-backed Pi has no 5m/1h split; flat cacheWrite routes to the 5m bucket.
        assert_eq!(item.cache_creation_5m_tokens, 5);
        assert_eq!(item.cache_creation_1h_tokens, 0);
        assert_eq!(item.request_count, 2);
        assert_eq!(item.usage_buckets.len(), 1);
        let bucket_request_count: u64 = item.usage_buckets[0]
            .model_usage
            .iter()
            .map(|r| r.request_count)
            .sum();
        assert_eq!(bucket_request_count, 2);
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.model_usage[0].model, "gemini-2.5-pro");
        assert_eq!(item.model_usage[0].input_tokens, 150);
        assert_eq!(item.model_usage[0].cost_usd.as_deref(), Some("0.0017"));
        assert_eq!(
            item.model_usage[0].input_cost_usd.as_deref(),
            Some("0.0007")
        );
        assert_eq!(
            item.model_usage[0].output_cost_usd.as_deref(),
            Some("0.0007")
        );
        assert_eq!(
            item.model_usage[0].cache_read_cost_usd.as_deref(),
            Some("0.0002")
        );
        assert_eq!(
            item.model_usage[0].cache_creation_cost_usd.as_deref(),
            Some("0.0001")
        );
        assert_eq!(
            item.cost
                .as_ref()
                .and_then(|cost| cost.total_cost_usd.as_deref()),
            Some("0.0017")
        );
        assert_eq!(item.provenance.collector, "pi_jsonl");
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("uncached")
        );
        assert!(item.workspace_hash.is_some());
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Summarize the changes in the diff")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_handles_multi_model_sessions() {
        let path = temp_file("pi-multimodel");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-bbbb-7000-9000-222222222222\",\"cwd\":\"/Users/example/repo\",\"timestamp\":\"2026-05-14T22:10:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-flash\",\"api\":\"vertex\",\"timestamp\":1779235001000,\"usage\":{\"input\":80,\"output\":20,\"cacheRead\":0,\"cacheWrite\":0,\"cost\":{\"total\":0.0002,\"input\":0.0001,\"output\":0.0001,\"cacheRead\":0.0,\"cacheWrite\":0.0}}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779235002000,\"usage\":{\"input\":120,\"output\":35,\"cacheRead\":0,\"cacheWrite\":0,\"cost\":{\"total\":0.0008,\"input\":0.0005,\"output\":0.0003,\"cacheRead\":0.0,\"cacheWrite\":0.0}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-14T22:11:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.input_tokens, 200);
        assert_eq!(item.output_tokens, 55);
        assert_eq!(item.model_usage.len(), 2);
        let model_names: Vec<&str> = item
            .model_usage
            .iter()
            .map(|usage| usage.model.as_str())
            .collect();
        assert!(model_names.contains(&"gemini-2.5-flash"));
        assert!(model_names.contains(&"gemini-2.5-pro"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_returns_none_for_empty_session() {
        let path = temp_file("pi-empty");
        fs::write(
            &path,
            "{\"type\":\"session\",\"session_id\":\"019e2700-cccc-7000-9000-333333333333\",\"cwd\":\"/tmp\",\"timestamp\":\"2026-05-14T22:20:00Z\"}\n",
        )
        .expect("write fixture");

        let item =
            parse_pi_jsonl_file(&path, "2026-05-14T22:21:00Z", "fp".to_string()).expect("parse");

        assert!(item.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_ms_timestamp_formats_rfc3339_with_millis() {
        // Anchor on epoch 0 and a verifiable mid-2024 date.
        assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        // 2024-01-01T00:00:00.000Z = 1_704_067_200 s = 1_704_067_200_000 ms
        assert_eq!(
            format_rfc3339_millis(1_704_067_200_000),
            "2024-01-01T00:00:00.000Z"
        );
        // Sub-second granularity is preserved.
        assert_eq!(
            format_rfc3339_millis(1_704_067_200_123),
            "2024-01-01T00:00:00.123Z"
        );
    }

    #[test]
    fn snapshot_parser_streaming_guard() {
        let source = include_str!("snapshots.rs");
        let forbidden_std_call = ["fs::", "read", "_to", "_string"].concat();
        let forbidden_reader_call = [".", "read", "_to", "_string("].concat();
        assert!(!source.contains(&forbidden_std_call));
        assert!(!source.contains(&forbidden_reader_call));
    }

    #[test]
    fn claude_code_parser_marks_vertex_routing_from_message_id_prefix() {
        let path = temp_file("claude-vertex-routing");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-27T11:00:00Z\",\"sessionId\":\"2cc9312d-6254-421d-a3f4-af09f0ea6843\",\"summary\":\"Vertex routed session\"}\n",
                "{\"timestamp\":\"2026-05-27T11:01:00Z\",\"sessionId\":\"2cc9312d-6254-421d-a3f4-af09f0ea6843\",\"requestId\":\"req_vrtx_011CbTQja3ndEG6i5VSxvTMy\",\"message\":{\"id\":\"msg_vrtx_01E8CZoVChX5VsRneeXge7Xn\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":12,\"output_tokens\":8}}}\n",
                "{\"timestamp\":\"2026-05-27T11:02:00Z\",\"sessionId\":\"2cc9312d-6254-421d-a3f4-af09f0ea6843\",\"requestId\":\"req_vrtx_011CbTQjb5ndEG6i5VSxvTMz\",\"message\":{\"id\":\"msg_vrtx_01E8CZoVChX5VsRneeXge7Xo\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_claude_code_jsonl_file(
            &path,
            "2026-05-27T11:05:00Z",
            "vertex-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1, "single row for pure vertex session");
        let item = items.into_iter().next().expect("snapshot");
        // gateway_provider / model_provider now live on the model_usage row.
        assert_eq!(
            item.model_usage[0].gateway_provider.as_deref(),
            Some("vertex")
        );
        assert_eq!(
            item.model_usage[0].model_provider.as_deref(),
            Some("anthropic")
        );
        assert!(item.model_usage[0].subscription_product.is_none());
        assert_eq!(item.input_tokens, 16);
        assert_eq!(item.output_tokens, 11);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_marks_bedrock_routing_from_message_id_prefix() {
        let path = temp_file("claude-bedrock-routing");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-27T12:00:00Z\",\"sessionId\":\"bedrock-session-1\",\"summary\":\"Bedrock routed session\"}\n",
                "{\"timestamp\":\"2026-05-27T12:01:00Z\",\"sessionId\":\"bedrock-session-1\",\"requestId\":\"req_bdrk_011CbV4TXyzr5mSprKh46T21\",\"message\":{\"id\":\"msg_bdrk_01NL9dabWXgaJeBdwZRrWEYc\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":20,\"output_tokens\":11}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_claude_code_jsonl_file(
            &path,
            "2026-05-27T12:05:00Z",
            "bedrock-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1);
        let item = items.into_iter().next().expect("snapshot");
        assert_eq!(
            item.model_usage[0].gateway_provider.as_deref(),
            Some("bedrock")
        );
        assert_eq!(
            item.model_usage[0].model_provider.as_deref(),
            Some("anthropic")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_marks_anthropic_routing_when_id_has_no_provider_infix() {
        let path = temp_file("claude-anthropic-routing");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-27T13:00:00Z\",\"sessionId\":\"1b2a248b-a5b7-41c5-bcd2-7b162a257149\",\"summary\":\"First-party routed session\"}\n",
                "{\"timestamp\":\"2026-05-27T13:01:00Z\",\"sessionId\":\"1b2a248b-a5b7-41c5-bcd2-7b162a257149\",\"requestId\":\"req_011CbU3R6JKp2myJL8gtuRpZ\",\"message\":{\"id\":\"msg_01VYXWshPjnW6L97x52sQbCT\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":9,\"output_tokens\":6}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_claude_code_jsonl_file(
            &path,
            "2026-05-27T13:05:00Z",
            "first-party-fingerprint".to_string(),
        )
        .expect("parse");
        let item = items.into_iter().next().expect("snapshot");
        assert_eq!(
            item.model_usage[0].gateway_provider.as_deref(),
            Some("anthropic")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_splits_mixed_provider_session_into_distinct_rows() {
        // A single Claude Code JSONL that interleaves Vertex (`msg_vrtx_*`) and
        // first-party Anthropic (`msg_01*`) turns. v6 emits ONE Item per
        // session with one model_usage row per gateway_provider so each maps
        // to its own billing identity downstream.
        let path = temp_file("claude-mixed-provider");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-27T14:00:00Z\",\"sessionId\":\"mixed-session\",\"summary\":\"cvon/cvoff demo\"}\n",
                "{\"timestamp\":\"2026-05-27T14:01:00Z\",\"sessionId\":\"mixed-session\",\"requestId\":\"req_vrtx_011CbTQja3ndEG6i5VSxvTMy\",\"message\":{\"id\":\"msg_vrtx_01E8CZoVChX5VsRneeXge7Xn\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-05-27T14:05:00Z\",\"sessionId\":\"mixed-session\",\"requestId\":\"req_011CbU3R6JKp2myJL8gtuRpZ\",\"message\":{\"id\":\"msg_01VYXWshPjnW6L97x52sQbCT\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_claude_code_jsonl_file(
            &path,
            "2026-05-27T14:10:00Z",
            "mixed-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1, "v6 emits one item per session");
        let item = &items[0];
        assert_eq!(item.model_usage.len(), 2);
        let mut gateways: Vec<Option<String>> = item
            .model_usage
            .iter()
            .map(|row| row.gateway_provider.clone())
            .collect();
        gateways.sort();
        assert_eq!(
            gateways,
            vec![Some("anthropic".to_string()), Some("vertex".to_string())]
        );
        let vertex = item
            .model_usage
            .iter()
            .find(|row| row.gateway_provider.as_deref() == Some("vertex"))
            .expect("vertex row");
        let anthropic = item
            .model_usage
            .iter()
            .find(|row| row.gateway_provider.as_deref() == Some("anthropic"))
            .expect("anthropic row");
        assert_eq!(vertex.input_tokens, 10);
        assert_eq!(vertex.output_tokens, 5);
        assert_eq!(anthropic.input_tokens, 4);
        assert_eq!(anthropic.output_tokens, 3);
        // Item totals reconcile with the row sum.
        assert_eq!(item.input_tokens, 14);
        assert_eq!(item.output_tokens, 8);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_splits_long_and_short_context_into_distinct_rows() {
        // One first-party Anthropic session (same model, same gateway, same
        // hour) whose turns differ ONLY in prompt size. The daemon derives a
        // per-turn `context_bucket` from effective input volume (input +
        // cache_read + cache_creation): the >200K turn could only have run on
        // the "(1M context)" window so it tags `long`; the boundary turn tags
        // `short`. Because context_bucket rides in selector_context (and thus
        // the RowKey/selector_hash), the otherwise-identical turns split into
        // separate model_usage rows the backend attributes independently.
        let path = temp_file("claude-context-bucket");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-29T09:00:00Z\",\"sessionId\":\"ctx-bucket-session\",\"summary\":\"1M context demo\"}\n",
                // short/boundary: effective == 200_000 exactly. The threshold is
                // strict `>`, so 200K is NOT long.
                "{\"timestamp\":\"2026-05-29T09:01:00Z\",\"sessionId\":\"ctx-bucket-session\",\"requestId\":\"req_011CbU3R6JKp2myJL8gtuRpZ\",\"message\":{\"id\":\"msg_01VYXWshPjnW6L97x52sQbCT\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":200000,\"output_tokens\":10}}}\n",
                // long: uncached input is only 20K, but cache_read (250K) +
                // cache_creation (5K) push effective input to 275K > 200K. Proves
                // cached tokens count toward the effective context window.
                "{\"timestamp\":\"2026-05-29T09:05:00Z\",\"sessionId\":\"ctx-bucket-session\",\"requestId\":\"req_011CbU3R6JKp2myJL8gtuRpA\",\"message\":{\"id\":\"msg_01VYXWshPjnW6L97x52sQbCU\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":20000,\"cache_read_input_tokens\":250000,\"cache_creation_input_tokens\":5000,\"output_tokens\":20}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_claude_code_jsonl_file(
            &path,
            "2026-05-29T09:10:00Z",
            "context-bucket-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1, "one item per session");
        let item = &items[0];
        assert_eq!(
            item.model_usage.len(),
            2,
            "long and short turns split into distinct rows"
        );

        let short = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context
                    .get("context_bucket")
                    .map(String::as_str)
                    == Some("short")
            })
            .expect("short-context row");
        let long = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context
                    .get("context_bucket")
                    .map(String::as_str)
                    == Some("long")
            })
            .expect("long-context row");

        // Boundary: effective == 200_000 stays short (strict `>`).
        assert_eq!(short.input_tokens, 200_000);
        assert_eq!(short.output_tokens, 10);
        assert_eq!(short.cache_read_tokens, 0);
        assert_eq!(short.cache_creation_5m_tokens, 0);
        // Long: cached tokens are what cross the threshold (input alone is 20K).
        assert_eq!(long.input_tokens, 20_000);
        assert_eq!(long.cache_read_tokens, 250_000);
        assert_eq!(long.cache_creation_5m_tokens, 5_000);
        assert_eq!(long.output_tokens, 20);

        // Both rows record the derivation source and share model + gateway, so
        // the ONLY dimension that split them is the context_bucket.
        for row in [short, long] {
            assert_eq!(
                row.selector_sources
                    .get("context_bucket")
                    .map(String::as_str),
                Some("derived_from_effective_input_volume")
            );
            assert_eq!(row.model, "claude-opus-4-8");
            assert_eq!(row.gateway_provider.as_deref(), Some("anthropic"));
            assert_eq!(row.model_provider.as_deref(), Some("anthropic"));
        }

        // Item totals reconcile with the row sum across both buckets.
        assert_eq!(item.input_tokens, 220_000);
        assert_eq!(item.output_tokens, 30);
        assert_eq!(item.cache_read_tokens, 250_000);
        assert_eq!(item.cache_creation_5m_tokens, 5_000);

        // The single 09:00 hour bucket carries the same split, so the backend
        // sees long/short separated per hour, not merged into one row.
        assert_eq!(item.usage_buckets.len(), 1);
        assert_eq!(item.usage_buckets[0].model_usage.len(), 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_extracts_pro_subscription_product_from_rate_limits() {
        let path = temp_file("codex-pro-plan");
        // Pro plan fixture mirrors rons's empirical 2026-05-21 personal session.
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-21T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-codex-pro-personal\",\"model_provider\":\"openai\"}}\n",
                "{\"timestamp\":\"2026-05-21T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":30,\"output_tokens\":12,\"cached_input_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"pro\",\"primary\":{\"used_percent\":35.5,\"window_minutes\":300,\"resets_at\":1779691736},\"secondary\":{\"used_percent\":12.3,\"window_minutes\":10080,\"resets_at\":1780206326},\"credits\":{\"has_credits\":true,\"unlimited\":false,\"balance\":null}}}}\n"
            ),
        )
        .expect("write fixture");

        let items =
            parse_codex_jsonl_file(&path, "2026-05-21T10:05:00Z", "pro-fingerprint".to_string())
                .expect("parse");
        let item = items.into_iter().next().expect("snapshot");
        // v6: subscription_product / model_provider are hoisted onto the row.
        // plan_window_bucket and agent_quota_* are stripped (not in backend's
        // SELECTOR_FIELDS allowlist, so backend would drop them on receipt).
        assert_eq!(item.model_usage.len(), 1);
        let row = &item.model_usage[0];
        assert_eq!(row.subscription_product.as_deref(), Some("pro"));
        assert_eq!(row.model_provider.as_deref(), Some("openai"));
        assert!(!row.selector_context.contains_key("subscription_product"));
        assert!(!row.selector_context.contains_key("plan_window_bucket"));
        assert!(!row
            .selector_context
            .contains_key("agent_quota_primary_used_percent"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_extracts_team_subscription_product_distinct_from_pro() {
        let path = temp_file("codex-team-plan");
        // Team plan fixture mirrors rons's empirical 2026-05-27 Singular session.
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-27T14:34:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-codex-team-singular\",\"model_provider\":\"openai\"}}\n",
                "{\"timestamp\":\"2026-05-27T14:35:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":18,\"request_count\":1},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"team\",\"primary\":{\"used_percent\":2.0,\"window_minutes\":300,\"resets_at\":1779898136},\"secondary\":{\"used_percent\":16.0,\"window_minutes\":10080,\"resets_at\":1780484936}}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_codex_jsonl_file(
            &path,
            "2026-05-27T14:40:00Z",
            "team-fingerprint".to_string(),
        )
        .expect("parse");
        let item = items.into_iter().next().expect("snapshot");
        assert_eq!(
            item.model_usage[0].subscription_product.as_deref(),
            Some("team")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_pro_and_team_subscription_products_produce_distinct_fingerprints() {
        // Sanity check: pro and team plans produce distinct row-level
        // subscription_product values and distinct snapshot fingerprints
        // across two separate sessions.
        let pro_path = temp_file("codex-pro-vs-team-1");
        let team_path = temp_file("codex-pro-vs-team-2");
        fs::write(
            &pro_path,
            "{\"timestamp\":\"2026-05-21T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-codex-pro-vs-team-1\"}}\n{\"timestamp\":\"2026-05-21T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":1,\"output_tokens\":1,\"request_count\":1},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"pro\",\"secondary\":{\"resets_at\":1780206326}}}}\n",
        )
        .expect("write pro");
        fs::write(
            &team_path,
            "{\"timestamp\":\"2026-05-27T14:34:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-codex-pro-vs-team-2\"}}\n{\"timestamp\":\"2026-05-27T14:35:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":1,\"output_tokens\":1,\"request_count\":1},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"team\",\"secondary\":{\"resets_at\":1780484936}}}}\n",
        )
        .expect("write team");

        let pro_item = parse_codex_jsonl_file(&pro_path, "2026-05-21T10:05:00Z", "p".to_string())
            .expect("parse pro")
            .into_iter()
            .next()
            .expect("pro snapshot");
        let team_item = parse_codex_jsonl_file(&team_path, "2026-05-27T14:40:00Z", "t".to_string())
            .expect("parse team")
            .into_iter()
            .next()
            .expect("team snapshot");
        assert_eq!(
            pro_item.model_usage[0].subscription_product.as_deref(),
            Some("pro")
        );
        assert_eq!(
            team_item.model_usage[0].subscription_product.as_deref(),
            Some("team")
        );
        assert_ne!(
            pro_item.snapshot_fingerprint,
            team_item.snapshot_fingerprint
        );

        let _ = fs::remove_file(pro_path);
        let _ = fs::remove_file(team_path);
    }

    #[test]
    fn pi_parser_emits_one_row_per_gateway_in_multi_provider_session() {
        // Pi can route per-turn to different providers within a single
        // session. v6 emits ONE Item with one model_usage row per gateway.
        let path = temp_file("pi-multi-provider");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"timestamp\":\"2026-05-20T09:00:00Z\",\"sessionId\":\"pi-multi\",\"cwd\":\"/work\"}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747731600000,\"gatewayProvider\":\"anthropic\",\"modelProvider\":\"anthropic\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747731660000,\"gatewayProvider\":\"openai\",\"modelProvider\":\"openai\",\"message\":{\"model\":\"gpt-5.5\",\"usage\":{\"input\":8,\"output\":6}}}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747731720000,\"gatewayProvider\":\"google\",\"modelProvider\":\"google\",\"message\":{\"model\":\"gemini-2.5\",\"usage\":{\"input\":3,\"output\":7}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_pi_jsonl_file(
            &path,
            "2026-05-20T09:05:00Z",
            "pi-multi-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1, "v6 collapses to one item per session");
        let item = &items[0];
        assert_eq!(item.source_session_id, "pi-multi");
        assert_eq!(item.model_usage.len(), 3);
        let mut gateways: Vec<Option<String>> = item
            .model_usage
            .iter()
            .map(|row| row.gateway_provider.clone())
            .collect();
        gateways.sort();
        assert_eq!(
            gateways,
            vec![
                Some("anthropic".to_string()),
                Some("google".to_string()),
                Some("openai".to_string()),
            ]
        );
        for row in &item.model_usage {
            assert!(row.subscription_product.is_none());
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn detect_claude_gateway_provider_recognizes_known_prefixes() {
        assert_eq!(
            detect_claude_gateway_provider(&serde_json::json!({
                "message": { "id": "msg_vrtx_01E8CZoVChX5VsRneeXge7Xn" }
            })),
            Some("vertex".to_string())
        );
        assert_eq!(
            detect_claude_gateway_provider(&serde_json::json!({
                "requestId": "req_bdrk_011CbV4T"
            })),
            Some("bedrock".to_string())
        );
        assert_eq!(
            detect_claude_gateway_provider(&serde_json::json!({
                "message": { "id": "msg_01VYXWshPjnW6L97x52sQbCT" }
            })),
            Some("anthropic".to_string())
        );
        assert_eq!(
            detect_claude_gateway_provider(&serde_json::json!({
                "message": { "id": "" }
            })),
            None
        );
        assert_eq!(detect_claude_gateway_provider(&serde_json::json!({})), None);
    }

    #[test]
    fn codex_cumulative_split_across_plan_window_rollover_buckets_correctly() {
        // Regression: a single Codex session that crosses a `secondary.resets_at`
        // day-boundary must not double-count the cumulative. Cumulative
        // 100/40 → 130/55 is monotonic, so no session restart; the delta is
        // 30/15. In v6 the two deltas land in two hour buckets (23:00 and
        // 00:00) under the same RowKey (plan_window_bucket is stripped, so
        // the row identity collapses). Top-level totals: 130/55.
        let path = temp_file("codex-rollover");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-31T23:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-rollover-session\"}}\n",
                "{\"timestamp\":\"2026-05-31T23:30:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":40,\"request_count\":1},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"pro\",\"secondary\":{\"resets_at\":1780123199}}}}\n",
                "{\"timestamp\":\"2026-06-01T00:30:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":130,\"output_tokens\":55,\"request_count\":2},\"model\":\"gpt-5.5\"},\"rate_limits\":{\"plan_type\":\"pro\",\"secondary\":{\"resets_at\":1780209599}}}}\n"
            ),
        )
        .expect("write fixture");

        let items = parse_codex_jsonl_file(
            &path,
            "2026-06-01T00:35:00Z",
            "rollover-fingerprint".to_string(),
        )
        .expect("parse");
        assert_eq!(items.len(), 1);
        let item = &items[0];
        // Top-level totals match the latest cumulative.
        assert_eq!(item.input_tokens, 130);
        assert_eq!(item.output_tokens, 55);
        // Two hour buckets, each with the right per-hour delta.
        assert_eq!(item.usage_buckets.len(), 2);
        let pre = item
            .usage_buckets
            .iter()
            .find(|b| b.bucket_start == "2026-05-31T23:00:00Z")
            .expect("pre-rollover bucket");
        let post = item
            .usage_buckets
            .iter()
            .find(|b| b.bucket_start == "2026-06-01T00:00:00Z")
            .expect("post-rollover bucket");
        assert_eq!(pre.model_usage[0].input_tokens, 100);
        assert_eq!(pre.model_usage[0].output_tokens, 40);
        assert_eq!(
            post.model_usage[0].input_tokens, 30,
            "post-rollover gets only the delta"
        );
        assert_eq!(post.model_usage[0].output_tokens, 15);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_unlabeled_turn_lands_in_distinct_row_from_labeled_turn() {
        // Regression: a Pi turn that omits gatewayProvider must NOT inherit
        // the gateway_provider key from a prior labeled turn into its row
        // identity. The unlabeled turn becomes a row with gateway_provider=None
        // rather than mis-attributing to anthropic. Pi message_end events
        // don't update current_selector, so each line's gateway is line-local.
        let path = temp_file("pi-partition-isolation");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"timestamp\":\"2026-05-20T09:00:00Z\",\"sessionId\":\"pi-iso\",\"cwd\":\"/work\"}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747731600000,\"gatewayProvider\":\"anthropic\",\"modelProvider\":\"anthropic\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input\":10,\"output\":5}}}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747731660000,\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input\":7,\"output\":3}}}\n"
            ),
        )
        .expect("write fixture");

        let items =
            parse_pi_jsonl_file(&path, "2026-05-20T09:05:00Z", "iso-fingerprint".to_string())
                .expect("parse");
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.model_usage.len(), 2);
        let labeled = item
            .model_usage
            .iter()
            .find(|row| row.gateway_provider.as_deref() == Some("anthropic"))
            .expect("anthropic row");
        let unlabeled = item
            .model_usage
            .iter()
            .find(|row| row.gateway_provider.is_none())
            .expect("unlabeled row");
        assert_eq!(labeled.input_tokens, 10);
        assert_eq!(labeled.output_tokens, 5);
        assert_eq!(unlabeled.input_tokens, 7);
        assert_eq!(unlabeled.output_tokens, 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn v6_snapshot_batch_matches_backend_contract() {
        // Golden daemon<->backend contract guard. Companion to the backend's
        // backend/tests/unit/test_daemon_snapshot_contract.py (master 6fa4deeff),
        // which validates the canonical daemon payload (generated from THIS
        // serializer) against AgentSessionSnapshotBatchRequest, declared
        // `extra="forbid"`. The v5->v6 break shipped silent because no
        // cross-language test existed: the daemon emitted item-level
        // gateway_provider / plan_fingerprint / backfill_source while the backend
        // forbade them, so every batch 422'd. Keep the two tests in lockstep:
        // when the snapshot schema changes, update the field sets below AND the
        // backend fixture/model together.

        // Allowed AgentSessionSnapshotItem fields (extra="forbid"), copied from
        // app/schemas/agent_session_snapshots.py. Pi emits `cost`; the other
        // collectors omit it.
        const ALLOWED_ITEM_FIELDS: &[&str] = &[
            "source_session_id",
            "snapshot_fingerprint",
            "status",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "peak_context_fill_tokens",
            "first_turn_context_tokens",
            "compaction_count",
            "model_usage",
            "usage_buckets",
            "cost",
            "session_display_name",
            "session_display_name_source",
            "source_started_at",
            "source_ended_at",
            "source_last_activity_at",
            "collected_at",
            "workspace_hash",
            "workspace_display_label",
            "workspace_label_source",
            "repository_hash",
            "repository_label",
            "repository_label_source",
            "repository_identity_source",
            "workspace_kind",
            "source_file_fingerprint",
            "session_artifacts",
            "provenance",
            "origin",
        ];
        // Allowed AgentSessionSnapshotModelUsage fields (extra="forbid").
        const ALLOWED_ROW_FIELDS: &[&str] = &[
            "model",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "reasoning_effort",
            "unattributed_total_tokens",
            "request_count",
            "selector_context",
            "selector_sources",
            "billing_provider",
            "model_provider",
            "billing_channel",
            "auth_mode",
            "gateway_provider",
            "subscription_product",
            "account_identifier_hash",
            "cost_usd",
            "input_cost_usd",
            "output_cost_usd",
            "cache_read_cost_usd",
            "cache_creation_cost_usd",
        ];
        // The exact v5 item-level attribution keys the backend now forbids — the
        // shape that produced the 422. A daemon regression that re-adds any of
        // these to the item is caught here, not in prod.
        const FORBIDDEN_ITEM_FIELDS: &[&str] =
            &["gateway_provider", "plan_fingerprint", "backfill_source"];

        // One Vertex Claude row (mirrors the backend's snapshot_batch_v6.json),
        // carried both as the item-level aggregate and inside the hour bucket.
        let vertex_row = SnapshotModelUsage {
            model: "claude-opus-4-7".to_string(),
            input_tokens: 100,
            output_tokens: 40,
            cache_read_tokens: 10,
            cache_creation_5m_tokens: 5,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            reasoning_effort: None,
            unattributed_total_tokens: 0,
            request_count: 1,
            selector_context: BTreeMap::from([
                ("service_tier".to_string(), "standard".to_string()),
                // v8: the 1M-context attribution bucket rides INSIDE
                // selector_context (a free-form JsonObject on the row), so it
                // adds no new top-level row key and stays within the backend's
                // extra="forbid" AgentSessionSnapshotModelUsage field set. The
                // backend's normalize_selector_context recognizes it
                // (SELECTOR_FIELDS / source key `context_bucket`).
                ("context_bucket".to_string(), "long".to_string()),
                (
                    "attribution_subagent".to_string(),
                    "general-purpose".to_string(),
                ),
                ("attribution_skill".to_string(), "design-sync".to_string()),
                (
                    "attribution_plugin".to_string(),
                    "anthropic-skills".to_string(),
                ),
                (
                    "attribution_mcp_server".to_string(),
                    "claude-in-chrome".to_string(),
                ),
            ]),
            selector_sources: BTreeMap::from([
                (
                    "service_tier".to_string(),
                    "message.usage.service_tier".to_string(),
                ),
                (
                    "context_bucket".to_string(),
                    "derived_from_effective_input_volume".to_string(),
                ),
                (
                    "attribution_subagent".to_string(),
                    "claude_code_attribution_field".to_string(),
                ),
                (
                    "attribution_skill".to_string(),
                    "claude_code_attribution_field".to_string(),
                ),
                (
                    "attribution_plugin".to_string(),
                    "claude_code_attribution_field".to_string(),
                ),
                (
                    "attribution_mcp_server".to_string(),
                    "claude_code_attribution_field".to_string(),
                ),
            ]),
            auth_mode: Some("service_account_oauth".to_string()),
            billing_channel: Some("cloud".to_string()),
            billing_provider: Some("google_cloud".to_string()),
            gateway_provider: Some("vertex".to_string()),
            model_provider: Some("anthropic".to_string()),
            subscription_product: None,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        let item = SnapshotItem {
            source_session_id: "claude-vertex-session-1".to_string(),
            snapshot_fingerprint: "a".repeat(32),
            status: "final".to_string(),
            input_tokens: 100,
            output_tokens: 40,
            cache_read_tokens: 10,
            cache_creation_5m_tokens: 5,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: Some(115),
            first_turn_context_tokens: Some(105),
            compaction_count: Some(0),
            model_usage: vec![vertex_row.clone()],
            usage_buckets: vec![SnapshotUsageBucket {
                bucket_start: "2026-05-28T17:00:00Z".to_string(),
                model_usage: vec![vertex_row],
                first_activity_at: Some("2026-05-28T17:05:00Z".to_string()),
                last_activity_at: Some("2026-05-28T17:45:00Z".to_string()),
            }],
            cost: None,
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: Some("2026-05-28T17:00:00Z".to_string()),
            source_ended_at: Some("2026-05-28T17:45:00Z".to_string()),
            source_last_activity_at: Some("2026-05-28T17:45:00Z".to_string()),
            collected_at: "2026-05-28T17:46:00Z".to_string(),
            workspace_hash: Some("b".repeat(32)),
            workspace_display_label: None,
            workspace_label_source: None,
            repository_hash: Some("d".repeat(64)),
            repository_label: Some("checkout-service".to_string()),
            repository_label_source: Some("git_root".to_string()),
            repository_identity_source: Some("git_common_dir".to_string()),
            workspace_kind: Some("repository_subdir".to_string()),
            source_file_fingerprint: Some("c".repeat(32)),
            session_artifacts: Vec::new(),
            provenance: SnapshotProvenance {
                collector: "claude_code_jsonl".to_string(),
                source_file_count: 1,
                input_token_scope: Some("uncached".to_string()),
                state_total_tokens: None,
                state_archived: None,
            },
            origin: None,
            attribution_facts: Vec::new(),
        };
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::ClaudeCode.api_slug().to_string(),
            machine_id: "machine-contract-0001".to_string(),
            collector_version: Some("local-enriched/1".to_string()),
            snapshots: vec![item],
        };
        validate_snapshot_batch_request(&request).expect("canonical v6 batch passes preflight");
        let value = serde_json::to_value(&request).expect("serialize v6 batch");

        // (1) schema version is 6 — both the constant and the wire value.
        assert_eq!(SNAPSHOT_SCHEMA_VERSION, 6);
        assert_eq!(value["schema_version"], json!(6));

        let allowed_item: BTreeSet<&str> = ALLOWED_ITEM_FIELDS.iter().copied().collect();
        let allowed_row: BTreeSet<&str> = ALLOWED_ROW_FIELDS.iter().copied().collect();

        let item_value = &value["snapshots"][0];
        let snapshot = item_value
            .as_object()
            .expect("snapshot item serializes to an object");

        // (2) every snapshot-item key is within the backend's allowed item set.
        for key in snapshot.keys() {
            assert!(
                allowed_item.contains(key.as_str()),
                "snapshot item key `{key}` is not in the backend AgentSessionSnapshotItem field set"
            );
        }

        // (3) no v5 item-level attribution keys (the precise 422 cause).
        for forbidden in FORBIDDEN_ITEM_FIELDS {
            assert!(
                !snapshot.contains_key(*forbidden),
                "snapshot item must NOT carry v5 item-level `{forbidden}` (the v6 422 cause)"
            );
        }

        // (4) every model_usage row key — item-level AND per-bucket — is within
        // the backend's allowed row set, and attribution rides on the row.
        let mut rows: Vec<&Value> = item_value["model_usage"]
            .as_array()
            .expect("item model_usage is an array")
            .iter()
            .collect();
        for bucket in item_value["usage_buckets"]
            .as_array()
            .expect("usage_buckets is an array")
        {
            rows.extend(
                bucket["model_usage"]
                    .as_array()
                    .expect("bucket model_usage is an array"),
            );
        }
        assert!(!rows.is_empty(), "expected at least one model_usage row");
        for row in rows {
            let row = row.as_object().expect("model_usage row is an object");
            for key in row.keys() {
                assert!(
                    allowed_row.contains(key.as_str()),
                    "model_usage row key `{key}` is not in the backend \
                     AgentSessionSnapshotModelUsage field set"
                );
            }
            // v6 moved attribution onto the row; assert it is actually there.
            assert_eq!(row.get("gateway_provider"), Some(&json!("vertex")));
        }

        // (5) v8: context_bucket rides inside selector_context (a free-form
        // dict), not as a top-level row key. Assert it survives serialization
        // there and does NOT leak out as a new row field the backend forbids.
        let first_row = item_value["model_usage"][0]
            .as_object()
            .expect("first model_usage row is an object");
        assert!(
            !first_row.contains_key("context_bucket"),
            "context_bucket must live inside selector_context, not as a top-level row key"
        );
        assert_eq!(
            item_value["model_usage"][0]["selector_context"]["context_bucket"],
            json!("long"),
            "context_bucket must be carried inside the row's selector_context"
        );
        for (key, expected) in [
            ("attribution_subagent", "general-purpose"),
            ("attribution_skill", "design-sync"),
            ("attribution_plugin", "anthropic-skills"),
            ("attribution_mcp_server", "claude-in-chrome"),
        ] {
            assert!(
                !first_row.contains_key(key),
                "{key} must live inside selector_context, not as a top-level row key"
            );
            assert_eq!(
                item_value["model_usage"][0]["selector_context"][key],
                json!(expected),
                "{key} must be carried inside the row's selector_context"
            );
        }
        assert!(
            item_value["model_usage"][0]["selector_context"]["attribution_mcp_tool"].is_null(),
            "attribution_mcp_tool must stay out of the first selector_context contract"
        );
    }

    #[test]
    fn v6_snapshot_preflight_rejects_missing_usage_buckets() {
        let mut request = valid_v6_batch_request();
        request.snapshots[0].usage_buckets.clear();

        let error = validate_snapshot_batch_request(&request).expect_err("preflight rejects");

        assert!(error.contains("no usage_buckets"), "{error}");
    }

    #[test]
    fn v6_snapshot_preflight_rejects_bucket_total_mismatch() {
        let mut request = valid_v6_batch_request();
        request.snapshots[0].usage_buckets[0].model_usage[0].input_tokens = 99;

        let error = validate_snapshot_batch_request(&request).expect_err("preflight rejects");

        assert!(error.contains("totals do not match"), "{error}");
    }

    #[test]
    fn v6_snapshot_preflight_rejects_top_level_row_mismatch() {
        let mut request = valid_v6_batch_request();
        request.snapshots[0].model_usage[0].gateway_provider = Some("anthropic".to_string());

        let error = validate_snapshot_batch_request(&request).expect_err("preflight rejects");

        assert!(error.contains("model rows do not match"), "{error}");
    }

    fn valid_v6_batch_request() -> SnapshotBatchRequest {
        let row = SnapshotModelUsage {
            model: "claude-opus-4-7".to_string(),
            input_tokens: 100,
            output_tokens: 40,
            cache_read_tokens: 10,
            cache_creation_5m_tokens: 5,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            reasoning_effort: None,
            unattributed_total_tokens: 0,
            request_count: 1,
            selector_context: BTreeMap::from([(
                "service_tier".to_string(),
                "standard".to_string(),
            )]),
            selector_sources: BTreeMap::from([(
                "service_tier".to_string(),
                "message.usage.service_tier".to_string(),
            )]),
            auth_mode: Some("service_account_oauth".to_string()),
            billing_channel: Some("cloud".to_string()),
            billing_provider: Some("google_cloud".to_string()),
            gateway_provider: Some("vertex".to_string()),
            model_provider: Some("anthropic".to_string()),
            subscription_product: None,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::ClaudeCode.api_slug().to_string(),
            machine_id: "machine-contract-0001".to_string(),
            collector_version: Some("local-enriched/1".to_string()),
            snapshots: vec![SnapshotItem {
                source_session_id: "claude-vertex-session-1".to_string(),
                snapshot_fingerprint: "a".repeat(32),
                status: "final".to_string(),
                input_tokens: 100,
                output_tokens: 40,
                cache_read_tokens: 10,
                cache_creation_5m_tokens: 5,
                cache_creation_1h_tokens: 0,
                reasoning_output_tokens: 0,
                unattributed_total_tokens: 0,
                request_count: 1,
                avg_duration_ms: None,
                avg_time_to_first_token_ms: None,
                max_duration_ms: None,
                max_time_to_first_token_ms: None,
                peak_context_fill_tokens: None,
                first_turn_context_tokens: None,
                compaction_count: None,
                model_usage: vec![row.clone()],
                usage_buckets: vec![SnapshotUsageBucket {
                    bucket_start: "2026-05-28T17:00:00Z".to_string(),
                    model_usage: vec![row],
                    first_activity_at: Some("2026-05-28T17:05:00Z".to_string()),
                    last_activity_at: Some("2026-05-28T17:45:00Z".to_string()),
                }],
                cost: None,
                session_display_name: None,
                session_display_name_source: None,
                source_started_at: Some("2026-05-28T17:00:00Z".to_string()),
                source_ended_at: Some("2026-05-28T17:45:00Z".to_string()),
                source_last_activity_at: Some("2026-05-28T17:45:00Z".to_string()),
                collected_at: "2026-05-28T17:46:00Z".to_string(),
                workspace_hash: Some("b".repeat(32)),
                workspace_display_label: None,
                workspace_label_source: None,
                repository_hash: None,
                repository_label: None,
                repository_label_source: None,
                repository_identity_source: None,
                workspace_kind: None,
                source_file_fingerprint: Some("c".repeat(32)),
                session_artifacts: Vec::new(),
                provenance: SnapshotProvenance {
                    collector: "claude_code_jsonl".to_string(),
                    source_file_count: 1,
                    input_token_scope: Some("uncached".to_string()),
                    state_total_tokens: None,
                    state_archived: None,
                },
                origin: None,
                attribution_facts: Vec::new(),
            }],
        }
    }
}
