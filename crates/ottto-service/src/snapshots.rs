use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
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
pub const SNAPSHOT_ENTITY_ACK_CONTRACT: &str = "snapshot_entity_ack:v1";
// SnapshotStatusRequest endpoint stayed at v5; only the batch endpoint
// cut over to v6 in this change. Backend's AgentSessionSnapshotStatusRequest
// is still Literal[5] (backend/app/schemas/agent_session_snapshots.py).
pub const SNAPSHOT_STATUS_SCHEMA_VERSION: u16 = 5;
// Parser versions describe parser provenance only. They MUST NOT be reused as
// incremental-scan identity or historical replay policy: a parser build bump
// is not proof that every historical session changed semantically.
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
// v21/v18: retain timestamped compaction events for the machine-local active
// session status and the additive backend snapshot contract.
// v22/v19/v10: activate the backend-gated session-attribution wire contract.
// Facts join the fingerprint only when present, and all three versions advance
// atomically so already-indexed history is revisited once.
// claude_code v20: complete the v13 subagent re-key. v13 only recognized a
// subagent transcript whose IMMEDIATE parent directory is `subagents`, which is
// true for a Task-tool agent (`<sessionId>/subagents/agent-<id>.jsonl`) but NOT
// for a Workflow-tool agent, whose transcript sits one or two levels deeper at
// `<sessionId>/subagents/workflows/<wfId>/agent-<id>.jsonl`. Those files carry
// the PARENT's `sessionId` on every line just like the Task-tool ones, so they
// kept collapsing onto the human parent session: an arbitrary workflow agent's
// slice (its model, its totals, `isSidechain=true` -> ai_agent, its context
// watermark) overwrote the real orchestrator session under last-writer-wins
// promotion. The subagent test is now "ANY ancestor directory is `subagents`",
// the parent session id is read from the PATH (the directory whose child is
// `subagents`) rather than from the in-file `sessionId`, and the workflow
// journal (`.../subagents/workflows/<wfId>/journal.jsonl`) is excluded from
// snapshot emission outright: it carries no `message.usage` and no `sessionId`,
// and its `journal` file stem is not unique across the workflow directories of
// one parent session. The bump re-walks every Claude transcript once so already
// scanned workflow-agent files re-emit under their own
// `<parentSessionId>_agent-<agentId>` id instead of over their parent.
// claude_code v21: subagent sessions get real display names. A re-keyed
// `<parentSessionId>_agent-<agentId>` session now emits
// `session_display_name_source=agent_label` built from the best available
// durable label material — Workflow run-manifest `label`
// (`workflows/wf_*.json` -> `workflowProgress[].label`, e.g.
// `probe:data-model`) > Task sidecar `description` (`agent-<id>.meta.json`,
// e.g. "Fix flaky backend tests") > sidecar `agentType`. Parent provenance is
// emitted separately, so it is not duplicated inside the child title. The
// first-prompt TITLE fallback is suppressed for subagent transcripts (their
// "first prompt" is the injected Task prompt body; the operator decision is
// short titles yes, prompt content no), while first-prompt MATERIAL still
// feeds attribution grouping. Naming sidecars (meta.json, workflow manifest,
// parent desktop title) join the subagent scan fingerprint so late-arriving
// labels re-select unchanged transcripts, and the scan-identity bump below
// re-walks already-indexed subagent files once so EXISTING agent sessions
// re-emit with names instead of staying on their generic fallbacks.
// claude_code v22: consume Claude Code's transcript-native `custom-title`
// records, including the PR-fixer slug emitted by automated repair sessions;
// reject continuation boilerplate as a first-prompt title; and keep subagent
// task labels independent from their parent relationship. The bump revisits
// existing transcripts so corrected titles replace already-uploaded fallbacks.
// v23/v23/v11: injected AGENTS/environment envelopes are not human prompts.
// Skip them before selecting first-prompt title and attribution material, then
// continue to the first real task message. All scan identities move so already
// indexed sessions are revisited and stale shared-envelope template groups are
// removed or replaced by task-specific opaque groups.
// codex v24: constrained "You are the <role> agent/worker/orchestrator" startup
// prompts expose the role as a safe title instead of falling back to the model
// or repository. The full prompt remains private and is never used as a title.
// codex v25: Codex response-item user messages carry injected prompt scaffolds
// as separate content elements. Strip each full element before title/template
// normalization; the shared 255-character normalizer used to truncate the
// recommended-plugins element before its closing tag, making it look human.
// claude_code v25: current Claude transcripts write one compaction twice: a
// `compact_boundary` system record and a legacy `isCompactSummary` user record
// a few milliseconds apart. Pair those provider records into one event while
// retaining support for transcripts that carry only one of the two shapes.
pub const CODEX_SNAPSHOT_PARSER_VERSION: &str = "codex_jsonl:v25";
pub const CLAUDE_CODE_SNAPSHOT_PARSER_VERSION: &str = "claude_code_jsonl:v25";
// v13 makes the provider response timestamp authoritative for both Pi usage
// record shapes and reconciles every exact cross-shape occurrence for a reused
// response id. This prevents envelope write time from moving current records
// into a different hour or turning a valid transitional pair into loss.
pub const PI_SNAPSHOT_PARSER_VERSION: &str = "pi_jsonl:v13";

// Frozen scan-identity versions. They intentionally begin at the versions used
// by the 0.1.91 baseline so upgrading to semantic sync does not itself select
// every indexed transcript. Advance only for a reviewed scan-index derivation
// change, never for ordinary parser implementation work.
//
// claude_code v20 IS such a change and is the reason this constant moves with
// the parser version here: the scan index skips a transcript whose bytes and
// mtime are unchanged, so a parser-version bump alone (which no longer feeds
// `scan_file_fingerprint_with_context`) would leave every already-indexed
// workflow-agent file permanently skipped and the fix inert on existing
// installs. The derivation that changed is which SESSION a file maps to, which
// is scan identity, not parser provenance. Cost of the one-time revisit stays
// bounded: an unchanged session re-parses to the same semantic fingerprint and
// is suppressed as a semantic no-op instead of being re-uploaded.
// claude_code v21 also moves scan identity, for the same reason v20 did: the
// scan index skips a transcript whose bytes and mtime are unchanged, and the
// new naming-sidecar fingerprint components only guard FUTURE label/title
// changes — they are computed against entries indexed under the old identity,
// which recorded no sidecar contribution at all, so without the bump every
// already-indexed subagent transcript would keep its generic fallback name
// forever. The one-time revisit stays bounded: an unchanged session re-parses
// to a new title but is otherwise a semantic no-op-sized re-upload of
// already-known usage.
pub const CODEX_SCAN_IDENTITY_VERSION: &str = "codex_jsonl:v25";
pub const CLAUDE_CODE_SCAN_IDENTITY_VERSION: &str = "claude_code_jsonl:v23";
pub const PI_SCAN_IDENTITY_VERSION: &str = "pi_jsonl:v13";
const LOCAL_SCAN_INDEX_IDENTITY_VERSION: &str = "semantic_sync:v2";
const OPENED_OBJECT_IDENTITY_VERSION: &str = "opened_object:v2";
const SCAN_INDEX_SCHEMA_VERSION: u16 = 2;
const FILE_CONTENT_SAMPLE_BYTES: usize = 4 * 1024;
pub(crate) const SNAPSHOT_SEMANTIC_CONTRACT_VERSION: &str = "snapshot_semantic:v1";
pub(crate) const SNAPSHOT_REVISION_CONTRACT_VERSION: &str = "snapshot_revision:v1";
pub(crate) const SNAPSHOT_REVISION_V2_CONTRACT_VERSION: &str = "snapshot_revision:v2";
pub(crate) const MAX_SEMANTIC_ENVELOPE_BYTES: usize = 2 * 1024;
pub(crate) const MAX_SNAPSHOT_ITEM_WIRE_BYTES: usize = 128 * 1024;
pub(crate) const MAX_SNAPSHOT_BATCH_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// Hash epoch of the policy-neutral `content_hash`.
///
/// It is deliberately independent of `SNAPSHOT_SCHEMA_VERSION` and of the
/// parser versions: a new wire field, a parser fix, or a new semantic component
/// is invisible to `content_hash` until this epoch moves. Moving it re-mints
/// every session's content identity fleet-wide, so it moves only as a
/// deliberate, announced change — never as a side effect of shipping a field.
pub const SNAPSHOT_CONTENT_HASH_EPOCH: u16 = 1;

/// The semantic components that survive every upload policy and every org
/// display toggle. `content_hash` is computed over exactly these, which is what
/// makes a privacy flip (titles, workspace labels, artifacts, attribution) a
/// change in *content* rather than a change in *identity*.
pub(crate) const POLICY_NEUTRAL_COMPONENTS: [&str; 4] = [
    "usage_accounting",
    "lifecycle_activity",
    "latency",
    "context_posture",
];

/// Contract label folded into the scan-index manifest hash. It names both the
/// fold and the entity grain, so a change to either changes the hash instead of
/// silently changing its meaning.
pub const SNAPSHOT_MANIFEST_CONTRACT_VERSION: &str = "snapshot_manifest:v2";
pub const SNAPSHOT_QUARANTINE_CONTRACT_VERSION: &str = "snapshot_quarantine:v1";
pub const SNAPSHOT_QUARANTINE_RETRY_SECONDS: u64 = 6 * 60 * 60;

/// What the manifest counts, declared on the wire rather than assumed.
///
/// The live scan index only ever holds transcripts inside the authorized scan
/// window. The one-time historical bootstrap uploads older sessions from a
/// throwaway index that is never persisted, so those entities are on the server
/// and permanently absent from this manifest. A consumer that compared this
/// count against its whole stored set would therefore report a mismatch on a
/// perfectly healthy machine — so the scope and the window travel with the
/// count, and the comparison is the consumer's to scope.
pub const SNAPSHOT_MANIFEST_SCOPE: &str = "semantic_activity_window";

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
// Directory discovery has its own hard per-tick budget. Candidate parsing was
// already capped, but recursively walking an arbitrarily large tree before
// applying that cap made one tick O(all paths). The durable traversal below
// consumes at most this many directory entries and then resumes next tick.
pub const MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK: usize = 10_000;
pub const MAX_WATCHER_HINTED_FILES_PER_TICK: usize = 256;
const UNHEALTHY_SCAN_RETRY_BASE_SECONDS: u64 = 60;
const UNHEALTHY_SCAN_RETRY_MAX_SECONDS: u64 = 60 * 60;
pub(crate) const MAX_COMPACTION_TIMESTAMPS: usize = 64;
const REPOSITORY_IDENTITY_CACHE_MAX_ENTRIES: usize = 512;
const REPOSITORY_IDENTITY_CACHE_TTL_SECONDS: u64 = 6 * 60 * 60;
pub const BACKFILL_WINDOW_DAYS: u64 = 730;

pub(crate) fn bounded_compaction_timestamps(mut timestamps: Vec<String>) -> Vec<String> {
    timestamps.sort();
    timestamps.dedup();
    if timestamps.len() > MAX_COMPACTION_TIMESTAMPS {
        timestamps.split_off(timestamps.len() - MAX_COMPACTION_TIMESTAMPS)
    } else {
        timestamps
    }
}

const CLAUDE_COMPACTION_PAIR_TOLERANCE_MILLISECONDS: i128 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeCompactionKind {
    LegacySummary,
    CurrentBoundary,
}

#[derive(Debug, Clone)]
struct ClaudeCompactionObservation {
    kind: ClaudeCompactionKind,
    timestamp: Option<String>,
}

fn claude_compaction_summary(observations: &[ClaudeCompactionObservation]) -> (u64, Vec<String>) {
    let mut matched_legacy = BTreeSet::new();
    let mut pair_count = 0_u64;

    for current in observations
        .iter()
        .filter(|observation| observation.kind == ClaudeCompactionKind::CurrentBoundary)
    {
        let Some(current_timestamp) = current
            .timestamp
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        else {
            continue;
        };
        let current_millis = current_timestamp.unix_timestamp_nanos() / 1_000_000;
        let candidate = observations
            .iter()
            .enumerate()
            .filter(|(index, observation)| {
                observation.kind == ClaudeCompactionKind::LegacySummary
                    && !matched_legacy.contains(index)
            })
            .filter_map(|(index, observation)| {
                let legacy_timestamp = observation
                    .timestamp
                    .as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
                let delta =
                    (legacy_timestamp.unix_timestamp_nanos() / 1_000_000 - current_millis).abs();
                (delta <= CLAUDE_COMPACTION_PAIR_TOLERANCE_MILLISECONDS).then_some((delta, index))
            })
            .min();
        if let Some((_, legacy_index)) = candidate {
            matched_legacy.insert(legacy_index);
            pair_count += 1;
        }
    }

    let timestamps = observations
        .iter()
        .enumerate()
        .filter(|(index, observation)| {
            observation.kind == ClaudeCompactionKind::CurrentBoundary
                || !matched_legacy.contains(index)
        })
        .filter_map(|(_, observation)| observation.timestamp.clone())
        .collect();
    (
        observations.len() as u64 - pair_count,
        bounded_compaction_timestamps(timestamps),
    )
}

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

    pub fn scan_identity_version(self) -> &'static str {
        match self {
            SnapshotSource::Codex => CODEX_SCAN_IDENTITY_VERSION,
            SnapshotSource::ClaudeCode => CLAUDE_CODE_SCAN_IDENTITY_VERSION,
            SnapshotSource::Pi => PI_SCAN_IDENTITY_VERSION,
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

#[derive(Debug, Clone)]
pub struct SnapshotBatchRequest {
    pub schema_version: u16,
    pub source: String,
    pub machine_id: String,
    pub collector_version: Option<String>,
    pub snapshots: Vec<SnapshotItem>,
    pub upload_policy: SnapshotUploadPolicy,
    /// Daemon-side loss accounting since the last acknowledged batch. Always
    /// present, including its zeros: an absent counter cannot distinguish "no
    /// losses" from "not reporting".
    pub client_report: crate::client_report::ClientReport,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotSemanticEnvelope {
    pub component_contract_version: &'static str,
    pub revision_contract_version: &'static str,
    pub upload_policy: SnapshotUploadPolicy,
    pub component_hashes: BTreeMap<&'static str, String>,
    pub revision_hash: String,
    /// Additive, server-reproducible revision witness. The v1 fields remain
    /// byte-identical for old-backend tolerance; only this RFC 8785 witness is
    /// eligible for a future conflict challenge because every input either
    /// travels here or already travels in the post-policy snapshot body.
    pub revision_v2_contract_version: &'static str,
    pub revision_v2_canonicalization: &'static str,
    pub revision_v2_parser_version: &'static str,
    pub revision_v2_scan_identity_version: &'static str,
    pub revision_v2_hash: String,
    /// Policy-neutral content identity: SHA-256 over the RFC 8785 canonical
    /// bytes of `snapshot_content_identity_body`. Write-only for now — the
    /// server stores it and does not key on it until its own cutover — which is
    /// exactly why it ships in this release rather than waiting for the server
    /// side to be ready: the daemon release train is the long pole.
    pub content_hash: String,
    /// The epoch `content_hash` was computed at. Present on every item so the
    /// server never has to guess which projection produced a hash.
    pub hash_epoch: u16,
}

#[derive(Serialize)]
struct SnapshotItemWire<'a> {
    #[serde(flatten)]
    snapshot: &'a SnapshotItem,
    semantic_envelope: SnapshotSemanticEnvelope,
}

impl Serialize for SnapshotBatchRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let source = snapshot_source_from_api_slug(&self.source)
            .ok_or_else(|| serde::ser::Error::custom("unsupported snapshot source"))?;
        let snapshots = self
            .snapshots
            .iter()
            .map(|snapshot| {
                let semantic_envelope =
                    snapshot_semantic_envelope(source, snapshot, self.upload_policy);
                let encoded =
                    serde_json::to_vec(&semantic_envelope).map_err(serde::ser::Error::custom)?;
                if encoded.len() > MAX_SEMANTIC_ENVELOPE_BYTES {
                    return Err(serde::ser::Error::custom(format!(
                        "semantic_envelope exceeds {MAX_SEMANTIC_ENVELOPE_BYTES} bytes"
                    )));
                }
                Ok(SnapshotItemWire {
                    snapshot,
                    semantic_envelope,
                })
            })
            .collect::<Result<Vec<_>, S::Error>>()?;
        let mut state = serializer.serialize_struct("SnapshotBatchRequest", 7)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("machine_id", &self.machine_id)?;
        state.serialize_field("collector_version", &self.collector_version)?;
        // Daemon-first capability declaration. Older backends use a
        // forward-tolerant ingest model and ignore it; capable backends echo it
        // and may return a complete per-entity outcome partition.
        state.serialize_field("entity_ack_contract", SNAPSHOT_ENTITY_ACK_CONTRACT)?;
        state.serialize_field("snapshots", &snapshots)?;
        state.serialize_field("client_report", &self.client_report)?;
        state.end()
    }
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compaction_timestamps: Vec<String>,
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
    /// Codex-only raw session-surface label read from `session_meta.originator`
    /// (e.g. `codex_work_desktop` for the unified ChatGPT desktop app's local
    /// "Work" sessions, `codex_cli_rs`/`codex_vscode` for the CLI/editor
    /// surfaces). Forward-looking top-level mirror of `origin.originator`: the
    /// backend prefers this field and derives a display sub-surface at serve
    /// time (never classified here). None for non-Codex sources (Claude Code /
    /// Pi have no originator concept) and when the Codex `session_meta` omits it.
    /// Additive/optional so older backends ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub originator: Option<String>,
    /// Compact evidence-first facts derived locally without transcript content.
    /// Empty fact sets stay off the wire; populated sets use the backend's v1
    /// field-evidence contract. Opaque template/skill facts may carry optional
    /// bounded labels only under the existing title-upload consent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    pub account_identifier_hash: Option<String>,
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

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ScanTraversalPath {
    scan_root: PathBuf,
    path: PathBuf,
    #[serde(default = "default_true")]
    census_member: bool,
    #[serde(default)]
    watcher_hint: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct ScanTraversalCounts {
    discovered_file_count: usize,
    directory_entry_cap_exceeded_count: usize,
    symlink_rejected_count: usize,
    unreadable_path_count: usize,
    oversized_file_count: usize,
    disappeared_file_count: usize,
    malformed_json_line_count: usize,
    invalid_utf8_line_count: usize,
    over_line_cap_count: usize,
    recognized_usage_drop_count: usize,
    zero_snapshot_usage_evidence_count: usize,
    dropped_usage_record_count: u64,
}

impl ScanTraversalCounts {
    fn has_errors(&self) -> bool {
        self.symlink_rejected_count > 0
            || self.directory_entry_cap_exceeded_count > 0
            || self.unreadable_path_count > 0
            || self.oversized_file_count > 0
            || self.disappeared_file_count > 0
            || self.malformed_json_line_count > 0
            || self.invalid_utf8_line_count > 0
            || self.over_line_cap_count > 0
            || self.recognized_usage_drop_count > 0
            || self.zero_snapshot_usage_evidence_count > 0
            || self.dropped_usage_record_count > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanTraversalCheckpoint {
    context_fingerprint: String,
    census_window_end: String,
    scan_roots: Vec<PathBuf>,
    pending_directories: VecDeque<ScanTraversalPath>,
    pending_candidates: VecDeque<ScanTraversalPath>,
    observed_index_keys: BTreeSet<String>,
    reconciliation_upper_bound: Option<String>,
    reconciliation_after: Option<String>,
    reconciliation_started: bool,
    #[serde(default)]
    watcher_hint_seen: bool,
    #[serde(default)]
    unhealthy_retry_attempt: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unhealthy_retry_not_before_unix_seconds: Option<u64>,
    counts: ScanTraversalCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndex {
    #[serde(default = "scan_index_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub generation: u64,
    /// The exact privacy/attribution context under which every settled entity
    /// fingerprint in this index was produced. A policy transition keeps the
    /// policy-neutral entity identity but must force one complete correction
    /// pass before this witness advances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_context_fingerprint: Option<String>,
    pub files: BTreeMap<String, ScanIndexEntry>,
    /// Configured roots that have successfully resolved at least once for this
    /// destination/source index. A root that never existed is optional, but a
    /// root that disappears after contributing an authoritative census must
    /// fail the generation red instead of reconciling every entity beneath it
    /// away as if the directory had been observed empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    known_configured_scan_roots: BTreeSet<String>,
    /// Pre-root-witness index paths not currently covered by any resolved root.
    /// This is the upgrade-safe witness for a configured symlink whose old
    /// canonical target cannot be reconstructed while the link is missing.
    /// Inference requires a prior traversal with the same root-context proof;
    /// paths clear when a resolved root covers them or the root context changes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    legacy_unresolved_root_file_witnesses: BTreeSet<String>,
    /// Last accepted semantic fingerprint for Codex sessions that exist only
    /// in the local state database and have no usage-bearing rollout file.
    ///
    /// These snapshots are rebuilt every scan from `state_*.sqlite`. Keeping
    /// their fingerprints beside the file index lets a successful upload
    /// acknowledge them exactly like file-backed snapshots, without turning
    /// every later state-database observation into another upload.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub codex_state_only_snapshot_fingerprints: BTreeMap<String, String>,
    /// Durable, local-only index of Claude Desktop naming sidecars. Paging the
    /// store without retaining these safe extracted fields would make titles
    /// disappear whenever their file was outside the current bounded page.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    claude_desktop_title_files: BTreeMap<String, ClaudeDesktopTitleIndexEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude_desktop_store_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude_desktop_store_upper_bound: Option<String>,
    #[serde(default)]
    claude_desktop_store_sweep_had_errors: bool,
    #[serde(default)]
    claude_desktop_store_retry_attempt: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude_desktop_store_retry_not_before_unix_seconds: Option<u64>,
    /// Lexicographic path cursor for a bounded sweep when a source has more
    /// eligible transcripts than one cycle may parse. Kept in the v2-only
    /// index so an older daemon can neither clobber nor misread it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after_path: Option<String>,
    /// Frozen lexicographic ceiling for the current bounded sweep. Files that
    /// arrive after the sweep starts wait for the next generation instead of
    /// keeping a hot tail full forever and starving older prefix keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_upper_bound_path: Option<String>,
    /// Observation boundary paired with `resume_upper_bound_path`. A sweep
    /// that spans cycles may publish only through the time at which its frozen
    /// path generation was captured, never through the later finishing tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_census_window_end: Option<String>,
    /// At least one earlier page in this frozen sweep was only partially
    /// settled. The final page may finish discovery, but one clean follow-up
    /// generation is still required before the policy epoch can advance.
    #[serde(default)]
    bounded_sweep_had_unsettled_upload: bool,
    /// Durable bounded filesystem census. It is intentionally destination-
    /// scoped with the rest of the scan index: missed watcher events, daemon
    /// restarts, deletions, and roots created after startup all converge via
    /// this finite queue without an O(all paths) tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    traversal: Option<ScanTraversalCheckpoint>,
    /// Destination-scoped historical bootstrap/replay generation currently
    /// being paged. Matching generations resume; a new reviewed revision
    /// clears only derived transcript settlement state once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    historical_replay_generation: Option<String>,
    /// Files that were fully read and valid but intentionally produced no
    /// snapshot. Separate from `last_snapshot_fingerprint=None`, which legacy
    /// indexes can only treat as unknown/incomplete.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub confirmed_empty_files: BTreeSet<String>,
    /// Final post-policy entity fingerprints produced by each transcript.
    /// Most files contain one session; the set preserves exact entity grain
    /// for split/provider files instead of hiding all but an arbitrary last.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_snapshot_fingerprints: BTreeMap<String, BTreeSet<String>>,
    /// Server-reconstructible semantic activity clock for each final entity.
    /// This mirrors the accepted-log `occurred_at` rule and never uses local
    /// file mtime or the collector observation clock.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub snapshot_activity_at: BTreeMap<String, Option<String>>,
    /// Rejected entities are quarantined under the exact daemon/parser/wire
    /// contract that produced the rejection. They are excluded from the
    /// server-agreement manifest while that witness is current, but are
    /// automatically re-derived after a repair changes any witness component.
    /// This isolates poison without turning quarantine into a permanent fence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quarantined_snapshot_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
    /// Runtime-only witness used to decide whether a persisted quarantine is
    /// stale. It is reconstructed from the current source before every scan.
    #[serde(skip)]
    active_quarantine_witness: Option<SnapshotQuarantineWitness>,
    /// Runtime-only desired upload context. It becomes durable only after a
    /// complete census, so a bounded/failed sweep cannot skip untouched files.
    #[serde(skip)]
    active_upload_context_fingerprint: Option<String>,
}

impl Default for ScanIndex {
    fn default() -> Self {
        Self {
            schema_version: SCAN_INDEX_SCHEMA_VERSION,
            generation: 0,
            upload_context_fingerprint: None,
            files: BTreeMap::new(),
            known_configured_scan_roots: BTreeSet::new(),
            legacy_unresolved_root_file_witnesses: BTreeSet::new(),
            codex_state_only_snapshot_fingerprints: BTreeMap::new(),
            claude_desktop_title_files: BTreeMap::new(),
            claude_desktop_store_cursor: None,
            claude_desktop_store_upper_bound: None,
            claude_desktop_store_sweep_had_errors: false,
            claude_desktop_store_retry_attempt: 0,
            claude_desktop_store_retry_not_before_unix_seconds: None,
            resume_after_path: None,
            resume_upper_bound_path: None,
            resume_census_window_end: None,
            bounded_sweep_had_unsettled_upload: false,
            traversal: None,
            historical_replay_generation: None,
            confirmed_empty_files: BTreeSet::new(),
            file_snapshot_fingerprints: BTreeMap::new(),
            snapshot_activity_at: BTreeMap::new(),
            quarantined_snapshot_fingerprints: BTreeMap::new(),
            active_quarantine_witness: None,
            active_upload_context_fingerprint: None,
        }
    }
}

/// Content-free proof of the code and wire contract that rejected an entity.
/// A semantic fingerprint alone is insufficient: a parser or validator fix
/// can make the same entity acceptable without changing that fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQuarantineWitness {
    pub contract: String,
    pub collector_version: String,
    pub parser_version: String,
    pub scan_identity_version: String,
    pub snapshot_schema_version: u16,
    pub entity_ack_contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQuarantineRecord {
    pub witness: SnapshotQuarantineWitness,
    pub retry_after_unix_seconds: u64,
}

pub fn snapshot_quarantine_witness(source: SnapshotSource) -> SnapshotQuarantineWitness {
    SnapshotQuarantineWitness {
        contract: SNAPSHOT_QUARANTINE_CONTRACT_VERSION.to_string(),
        collector_version: collector_version(),
        parser_version: source.parser_version().to_string(),
        scan_identity_version: source.scan_identity_version().to_string(),
        snapshot_schema_version: SNAPSHOT_SCHEMA_VERSION,
        entity_ack_contract: SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
    }
}

pub fn snapshot_quarantine_record(source: SnapshotSource) -> SnapshotQuarantineRecord {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    SnapshotQuarantineRecord {
        witness: snapshot_quarantine_witness(source),
        retry_after_unix_seconds: now.saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS),
    }
}

pub(crate) fn snapshot_quarantine_deadline_is_bounded(record: &SnapshotQuarantineRecord) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    snapshot_quarantine_deadline_is_bounded_at(record, now)
}

fn snapshot_quarantine_deadline_is_bounded_at(record: &SnapshotQuarantineRecord, now: u64) -> bool {
    // Fresh quarantine is deterministically staggered across [6h, 12h).
    // Anything further out is corrupt state or evidence the wall clock moved
    // backwards. In either case local state must never become a permanent
    // authority that fences a repaired backend forever.
    record.retry_after_unix_seconds
        <= now.saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(2))
}

fn scan_index_schema_version() -> u16 {
    SCAN_INDEX_SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_unix_nanos: Option<u64>,
    pub source_file_fingerprint: String,
    pub last_snapshot_fingerprint: Option<String>,
    /// Marks entries written by the semantic-sync scan derivation. `None`
    /// identifies a pre-cutover entry that can be adopted without reparsing
    /// when transcript size and mtime are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_identity_version: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanParseOutcome {
    /// Old indexes cannot distinguish an empty parse from an interrupted one.
    #[default]
    Unknown,
    Snapshot,
    ConfirmedEmpty,
    PolicySuppressed,
}

/// Exact `snapshot_manifest:v2` wire contract carried on collector check-ins.
/// Census diagnostics stay in the top-level status counters rather than
/// masquerading as server proof inside this producer-side manifest.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotSourceManifest {
    pub contract_version: &'static str,
    pub scope: &'static str,
    pub source: String,
    pub window_start: String,
    pub window_end: String,
    pub entity_count: u64,
    pub rolling_hash: String,
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
    pub semantic_noop_count: usize,
    pub census_complete: bool,
    pub census_window_end: String,
    /// State-only Codex census is separate from transcript discovery. If an
    /// existing SQLite source was unreadable, its previous durable map must be
    /// retained even while healthy transcript siblings progress.
    pub state_census_complete: bool,
    /// Display/naming sidecars are optional enrichment, but a partial read
    /// cannot publish a source-wide manifest or advance the upload context.
    pub sidecar_census_complete: bool,
    pub symlink_rejected_count: usize,
    pub directory_entry_cap_exceeded_count: usize,
    pub unreadable_path_count: usize,
    pub oversized_file_count: usize,
    pub disappeared_file_count: usize,
    pub malformed_json_line_count: usize,
    pub invalid_utf8_line_count: usize,
    pub over_line_cap_count: usize,
    pub recognized_usage_drop_count: usize,
    pub zero_snapshot_confirmed_count: usize,
    pub zero_snapshot_usage_evidence_count: usize,
    pub dropped_usage_record_count: u64,
    pub snapshots: Vec<SnapshotItem>,
    pending_finalization: Vec<PendingIndexFinalization>,
}

#[derive(Debug, Clone)]
struct PendingIndexFinalization {
    index_key: String,
    source_file_fingerprint: String,
    previous_snapshot_fingerprint: Option<String>,
    parse_complete: bool,
    parsed_snapshot_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct SnapshotUploadPolicy {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
    pub session_artifacts_enabled: bool,
    pub session_attribution_enabled: bool,
    /// Backend capability derived from the existing session-title privacy
    /// choice. It is not a separate user setting and defaults off for older
    /// backends that do not advertise the additive private-label contract.
    pub session_attribution_labels_enabled: bool,
}

pub(crate) fn snapshot_source_from_api_slug(value: &str) -> Option<SnapshotSource> {
    match value {
        "codex" => Some(SnapshotSource::Codex),
        "claude_code" => Some(SnapshotSource::ClaudeCode),
        "pi" => Some(SnapshotSource::Pi),
        _ => None,
    }
}

impl Default for SnapshotUploadPolicy {
    fn default() -> Self {
        Self {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
            // Opt-in: artifacts are stripped before upload unless the backend
            // activity hint explicitly enables them for the org.
            session_artifacts_enabled: false,
            // Opt-in: compact facts stay local unless the backend explicitly
            // enables the additive attribution contract.
            session_attribution_enabled: false,
            session_attribution_labels_enabled: false,
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
        if !policy.session_attribution_enabled && !item.attribution_facts.is_empty() {
            item.attribution_facts.clear();
            fingerprint_needs_refresh = true;
        } else if (!policy.session_titles_enabled || !policy.session_attribution_labels_enabled)
            && crate::session_attribution::strip_display_labels(&mut item.attribution_facts)
        {
            fingerprint_needs_refresh = true;
        }
        if fingerprint_needs_refresh {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
}

/// Bind incremental state to the exact bytes/semantics that will go on the
/// wire. This MUST run after every enrichment, privacy policy, and account
/// cutoff. Parser-time fingerprints are provisional only: committing them
/// earlier can suppress a later policy/enrichment correction forever.
pub fn finalize_scan_after_policy(
    source: SnapshotSource,
    result: &mut SourceScanResult,
    index: &mut ScanIndex,
) {
    for snapshot in &mut result.snapshots {
        snapshot.snapshot_fingerprint = snapshot_fingerprint(source, snapshot);
        index.snapshot_activity_at.insert(
            snapshot.snapshot_fingerprint.clone(),
            snapshot_semantic_activity_at(snapshot),
        );
    }

    let mut by_source_file: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for snapshot in &result.snapshots {
        if let Some(source_file_fingerprint) = snapshot.source_file_fingerprint.as_ref() {
            by_source_file
                .entry(source_file_fingerprint.clone())
                .or_default()
                .insert(snapshot.snapshot_fingerprint.clone());
        }
    }

    let mut noop_source_files = BTreeSet::new();
    for pending in &result.pending_finalization {
        if !pending.parse_complete {
            continue;
        }
        let final_fingerprints = by_source_file
            .get(&pending.source_file_fingerprint)
            .cloned()
            .unwrap_or_default();
        let final_group_fingerprint = (!final_fingerprints.is_empty()).then(|| {
            let mut digest = Sha256::new();
            update_length_prefixed(&mut digest, b"snapshot_file_entity_set:v1");
            for fingerprint in &final_fingerprints {
                update_length_prefixed(&mut digest, fingerprint.as_bytes());
            }
            format!("{:x}", digest.finalize())
        });
        if let Some(entry) = index.files.get_mut(&pending.index_key) {
            entry.last_snapshot_fingerprint = final_group_fingerprint.clone();
        }
        if final_fingerprints.is_empty() {
            index.file_snapshot_fingerprints.remove(&pending.index_key);
            index
                .confirmed_empty_files
                .insert(pending.index_key.clone());
        } else {
            index
                .file_snapshot_fingerprints
                .insert(pending.index_key.clone(), final_fingerprints);
            index.confirmed_empty_files.remove(&pending.index_key);
        }
        if final_group_fingerprint.is_some()
            && final_group_fingerprint == pending.previous_snapshot_fingerprint
        {
            noop_source_files.insert(pending.source_file_fingerprint.clone());
            result.semantic_noop_count = result
                .semantic_noop_count
                .saturating_add(pending.parsed_snapshot_count);
        }
    }
    result.snapshots.retain(|snapshot| {
        snapshot
            .source_file_fingerprint
            .as_ref()
            .map(|source_file| !noop_source_files.contains(source_file))
            .unwrap_or(true)
    });

    // State-only Codex entities do not have a source-file fingerprint, so they
    // cannot use the file finalization table above. Rebind their durable map to
    // the final post-enrichment/post-policy/post-cutoff fingerprint here. This
    // is also where no-op suppression belongs: parser-time equality is not
    // authoritative when a privacy policy or account cutoff changed.
    if source == SnapshotSource::Codex && result.state_census_complete {
        let previous = index.codex_state_only_snapshot_fingerprints.clone();
        let mut current = BTreeMap::new();
        let mut noop_state_only = BTreeSet::new();
        for snapshot in &result.snapshots {
            if snapshot.source_file_fingerprint.is_none()
                && snapshot.provenance.collector == "codex_state_sqlite"
            {
                let fingerprint = snapshot.snapshot_fingerprint.clone();
                if previous.get(&snapshot.source_session_id) == Some(&fingerprint)
                    && index.snapshot_activity_at.contains_key(&fingerprint)
                    && !index.quarantine_requires_retry(&fingerprint)
                {
                    noop_state_only.insert(snapshot.source_session_id.clone());
                    result.semantic_noop_count = result.semantic_noop_count.saturating_add(1);
                }
                current.insert(snapshot.source_session_id.clone(), fingerprint);
            }
        }
        index.codex_state_only_snapshot_fingerprints = current;
        result.snapshots.retain(|snapshot| {
            snapshot.source_file_fingerprint.is_some()
                || snapshot.provenance.collector != "codex_state_sqlite"
                || !noop_state_only.contains(&snapshot.source_session_id)
        });
    }
    if result.census_complete {
        if !index.bounded_sweep_had_unsettled_upload {
            index.upload_context_fingerprint = index.active_upload_context_fingerprint.clone();
        }
        index.bounded_sweep_had_unsettled_upload = false;
    }
    let current_fingerprints = index
        .file_snapshot_fingerprints
        .values()
        .flat_map(BTreeSet::iter)
        .chain(index.codex_state_only_snapshot_fingerprints.values())
        .collect::<BTreeSet<_>>();
    index
        .snapshot_activity_at
        .retain(|fingerprint, _| current_fingerprints.contains(fingerprint));
}

/// The producer-side event clock mirrored by the accepted-log append path.
/// The maximum activity clock is stable across retries and reconstructible on
/// both sides. `collected_at` is deliberately excluded because it is an
/// observation clock; metadata-only entities without semantic activity do not
/// participate in a v2 manifest.
fn snapshot_semantic_activity_at(item: &SnapshotItem) -> Option<String> {
    item.usage_buckets
        .iter()
        .flat_map(|bucket| {
            [
                Some(bucket.bucket_start.as_str()),
                bucket.first_activity_at.as_deref(),
                bucket.last_activity_at.as_deref(),
            ]
        })
        .chain([
            item.source_started_at.as_deref(),
            item.source_ended_at.as_deref(),
            item.source_last_activity_at.as_deref(),
        ])
        .flatten()
        .filter_map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .ok()
                .map(|parsed| (parsed, value))
        })
        .max_by_key(|(parsed, _)| *parsed)
        .map(|(_, value)| value.to_string())
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
        let mut changed = apply_claude_account_evidence(item, evidence);
        let mut grouped: BTreeMap<(String, String, String), UsageTotals> = BTreeMap::new();
        for observed in evidence {
            if observed.effort.is_empty() {
                continue;
            }
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

fn apply_claude_account_evidence(
    item: &mut SnapshotItem,
    evidence: &[crate::claude_effort::ClaudeEffortEvidence],
) -> bool {
    let checked_evidence = evidence
        .iter()
        .filter(|row| row.account_identity_checked)
        .collect::<Vec<_>>();
    if checked_evidence.is_empty() {
        return false;
    }
    let evidence_hashes = checked_evidence
        .iter()
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let has_unidentified_request = checked_evidence
        .iter()
        .any(|row| row.account_identifier_hash.is_none());
    let has_legacy_unchecked_request = evidence.iter().any(|row| !row.account_identity_checked);
    let existing_hashes = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let existing_identity_matches =
        !existing_hashes.is_empty() && existing_hashes == evidence_hashes;
    let evidence_covers_snapshot = claude_account_evidence_covers_snapshot(item, &checked_evidence);
    let target = (!has_unidentified_request
        && evidence_hashes.len() == 1
        && (existing_identity_matches
            || (existing_hashes.is_empty()
                && !has_legacy_unchecked_request
                && evidence_covers_snapshot)))
        .then(|| evidence_hashes.first().map(|value| (*value).to_string()))
        .flatten();
    let mut changed = false;
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        if row.account_identifier_hash != target {
            row.account_identifier_hash = target.clone();
            changed = true;
        }
    }
    changed
}

fn claude_account_evidence_covers_snapshot(
    item: &SnapshotItem,
    evidence: &[&crate::claude_effort::ClaudeEffortEvidence],
) -> bool {
    let sum = |value: fn(&crate::claude_effort::ClaudeEffortEvidence) -> u64| {
        evidence
            .iter()
            .map(|row| u128::from(value(row)))
            .sum::<u128>()
    };
    let cache_creation = evidence
        .iter()
        .map(|row| {
            u128::from(row.cache_creation_tokens)
                + u128::from(row.cache_creation_5m_tokens)
                + u128::from(row.cache_creation_1h_tokens)
        })
        .sum::<u128>();
    item.unattributed_total_tokens == 0
        && sum(|row| row.input_tokens) == u128::from(item.input_tokens)
        && sum(|row| row.output_tokens) == u128::from(item.output_tokens)
        && sum(|row| row.cache_read_tokens) == u128::from(item.cache_read_tokens)
        && cache_creation
            == u128::from(item.cache_creation_5m_tokens) + u128::from(item.cache_creation_1h_tokens)
        && sum(|row| row.reasoning_output_tokens) == u128::from(item.reasoning_output_tokens)
        && sum(|row| row.request_count) == u128::from(item.request_count)
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
    let account_hashes = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let has_missing_account_hash = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .any(|row| row.account_identifier_hash.is_none());
    let account_identifier_hash = (!has_missing_account_hash && account_hashes.len() == 1)
        .then(|| account_hashes.first().map(|value| (*value).to_string()))
        .flatten();
    drop(account_hashes);
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
    for row in &mut item.model_usage {
        row.account_identifier_hash = account_identifier_hash.clone();
    }
}

fn semantic_attribution_facts(item: &SnapshotItem) -> Vec<Value> {
    let mut facts = item
        .attribution_facts
        .iter()
        .map(|fact| {
            json!({
                "field": &fact.field,
                "value": &fact.value,
                "display_label": &fact.display_label,
                "display_label_source": &fact.display_label_source,
                "evidence_kind": &fact.evidence.kind,
                "evidence_strength": &fact.evidence.strength,
            })
        })
        .collect::<Vec<_>>();
    facts.sort_by_key(Value::to_string);
    facts
}

fn semantic_attribution(item: &SnapshotItem) -> Value {
    let account_identifier_hashes = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let mut value = json!({
        "origin": &item.origin,
        "facts": semantic_attribution_facts(item),
    });
    if !account_identifier_hashes.is_empty() {
        value
            .as_object_mut()
            .expect("semantic attribution is an object")
            .insert(
                "account_identifier_hashes".to_string(),
                json!(account_identifier_hashes),
            );
    }
    value
}

fn semantic_model_usage(row: &SnapshotModelUsage) -> Value {
    // `account_identifier_hash` remains outside hash epoch 1. The account-keyed
    // Claude sidecar fingerprint changes `source_file_fingerprint`, and thus
    // `revision_hash`, when exact evidence appears; changing epoch-1 content
    // semantics would reject older clients that already use this wire field.
    json!({
        "model": &row.model,
        "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens,
        "cache_read_tokens": row.cache_read_tokens,
        "cache_creation_5m_tokens": row.cache_creation_5m_tokens,
        "cache_creation_1h_tokens": row.cache_creation_1h_tokens,
        "reasoning_output_tokens": row.reasoning_output_tokens,
        "reasoning_effort": &row.reasoning_effort,
        "unattributed_total_tokens": row.unattributed_total_tokens,
        "request_count": row.request_count,
        "selector_context": &row.selector_context,
        "selector_sources": &row.selector_sources,
        "auth_mode": &row.auth_mode,
        "billing_channel": &row.billing_channel,
        "billing_provider": &row.billing_provider,
        "gateway_provider": &row.gateway_provider,
        "model_provider": &row.model_provider,
        "subscription_product": &row.subscription_product,
        "cost_usd": &row.cost_usd,
        "input_cost_usd": &row.input_cost_usd,
        "output_cost_usd": &row.output_cost_usd,
        "cache_read_cost_usd": &row.cache_read_cost_usd,
        "cache_creation_cost_usd": &row.cache_creation_cost_usd,
    })
}

fn semantic_usage_buckets(item: &SnapshotItem) -> Vec<Value> {
    item.usage_buckets
        .iter()
        .map(|bucket| {
            json!({
                "bucket_start": &bucket.bucket_start,
                "model_usage": bucket.model_usage.iter().map(semantic_model_usage).collect::<Vec<_>>(),
                "first_activity_at": &bucket.first_activity_at,
                "last_activity_at": &bucket.last_activity_at,
            })
        })
        .collect()
}

pub(crate) fn snapshot_semantic_component_hashes(
    source: SnapshotSource,
    item: &SnapshotItem,
) -> BTreeMap<&'static str, String> {
    let mut components = BTreeMap::new();
    let mut insert = |name: &'static str, payload: Value| {
        components.insert(name, sha256_hex(&[&payload.to_string()]));
    };

    insert(
        "usage_accounting",
        json!({
            "input_tokens": item.input_tokens,
            "output_tokens": item.output_tokens,
            "cache_read_tokens": item.cache_read_tokens,
            "cache_creation_5m_tokens": item.cache_creation_5m_tokens,
            "cache_creation_1h_tokens": item.cache_creation_1h_tokens,
            "reasoning_output_tokens": item.reasoning_output_tokens,
            "unattributed_total_tokens": item.unattributed_total_tokens,
            "request_count": item.request_count,
            "model_usage": item.model_usage.iter().map(semantic_model_usage).collect::<Vec<_>>(),
            "usage_buckets": semantic_usage_buckets(item),
            "cost": item.cost.as_ref().map(|cost| json!({
                "total_cost_usd": &cost.total_cost_usd,
                "input_cost_usd": &cost.input_cost_usd,
                "output_cost_usd": &cost.output_cost_usd,
                "cache_read_cost_usd": &cost.cache_read_cost_usd,
                "cache_creation_cost_usd": &cost.cache_creation_cost_usd,
            })),
        }),
    );
    insert(
        "lifecycle_activity",
        json!({
            "status": &item.status,
            "source_started_at": &item.source_started_at,
            "source_ended_at": &item.source_ended_at,
            "source_last_activity_at": &item.source_last_activity_at,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        }),
    );
    insert(
        "latency",
        json!({
            "avg_duration_ms": item.avg_duration_ms,
            "avg_time_to_first_token_ms": item.avg_time_to_first_token_ms,
            "max_duration_ms": item.max_duration_ms,
            "max_time_to_first_token_ms": item.max_time_to_first_token_ms,
        }),
    );
    if source.derives_context_posture() {
        insert(
            "context_posture",
            json!({
                "peak_context_fill_tokens": item.peak_context_fill_tokens,
                "first_turn_context_tokens": item.first_turn_context_tokens,
                "compaction_count": item.compaction_count,
                "compaction_timestamps": &item.compaction_timestamps,
            }),
        );
    }
    insert(
        "display_identity",
        json!({
            "title": &item.session_display_name,
            "title_source": &item.session_display_name_source,
            "workspace_hash": &item.workspace_hash,
            "workspace_display_label": &item.workspace_display_label,
            "workspace_label_source": &item.workspace_label_source,
            "repository_hash": &item.repository_hash,
            "repository_label": &item.repository_label,
            "repository_label_source": &item.repository_label_source,
            "repository_identity_source": &item.repository_identity_source,
            "workspace_kind": &item.workspace_kind,
        }),
    );
    insert("attribution", semantic_attribution(item));
    insert("artifacts", json!(&item.session_artifacts));
    components
}

pub(crate) fn snapshot_fingerprint_from_component_hashes(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let component_payload = serde_json::to_string(&component_hashes)
        .expect("snapshot semantic component hashes serialize");
    sha256_hex(&[
        SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        source.api_slug(),
        source_session_id,
        &component_payload,
    ])
}

fn snapshot_fingerprint(source: SnapshotSource, item: &SnapshotItem) -> String {
    snapshot_fingerprint_from_component_hashes(
        source,
        &item.source_session_id,
        &snapshot_semantic_component_hashes(source, item),
    )
}

/// The policy-neutral component hashes, in canonical order.
pub(crate) fn policy_neutral_component_hashes(
    component_hashes: &BTreeMap<&'static str, String>,
) -> BTreeMap<String, String> {
    POLICY_NEUTRAL_COMPONENTS
        .iter()
        .filter_map(|name| {
            component_hashes
                .get(name)
                .map(|value| ((*name).to_string(), value.clone()))
        })
        .collect()
}

/// The body `content_hash` is computed over.
///
/// It carries the content identity scope (source + session id) and the
/// policy-neutral semantic components, and nothing else. Every field of
/// `snapshot_revision_material` that is NOT here is excluded because it is
/// implementation state, mutable inventory, or wall-clock, and identity may not
/// depend on any of those:
///
/// * `source_file_fingerprint` — scan/inventory state; the same content read
///   from a rotated or recopied transcript is the same content.
/// * parser version and scan-identity version — a parser fix must not re-mint
///   every session's identity (they stay in `revision_hash`, which is the
///   *re-upload* trigger, not the identity).
/// * `provenance.collector` / `provenance.source_file_count` — implementation
///   state and mutable inventory.
/// * the lifecycle scalars (`status`, the three `source_*_at` timestamps,
///   `state_total_tokens`, `state_archived`) — already inside the
///   `lifecycle_activity` component hash, so restating them would double-count
///   without adding coverage.
///
/// Excluded by construction rather than by filter: the policy-scoped components
/// (`display_identity`, `attribution`, `artifacts`), which is what keeps an org
/// display toggle from re-minting identity for every session.
pub(crate) fn snapshot_content_identity_body(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    json!({
        "canonicalization": crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        "components": policy_neutral_component_hashes(component_hashes),
        "hash_epoch": SNAPSHOT_CONTENT_HASH_EPOCH,
        "source": source.api_slug(),
        "source_session_id": source_session_id,
    })
}

/// SHA-256 over the RFC 8785 canonical bytes of the policy-neutral body.
///
/// SHA-256, not a faster hash: every component hash in this daemon is already
/// SHA-256, the backend has it everywhere, and a second cross-language hash
/// implementation would be a second thing to keep byte-identical for no
/// measurable gain at this item volume.
pub(crate) fn snapshot_content_hash(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let body = snapshot_content_identity_body(source, source_session_id, component_hashes);
    // Infallible by construction: the body is strings, one integer, and one
    // string-to-string map. `content_identity_body_stays_canonicalizable`
    // enforces that mechanically, so this is a proof obligation with a test
    // behind it rather than an assumption.
    let canonical = crate::canonical_json::canonicalize(&body)
        .expect("policy-neutral content identity body is canonicalizable");
    let mut digest = Sha256::new();
    digest.update(&canonical);
    format!("{:x}", digest.finalize())
}

fn snapshot_revision_material(
    item: &SnapshotItem,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    let policy_neutral_component_hashes = policy_neutral_component_hashes(component_hashes);
    json!({
        "source_file_fingerprint": &item.source_file_fingerprint,
        "source_started_at": &item.source_started_at,
        "source_ended_at": &item.source_ended_at,
        "source_last_activity_at": &item.source_last_activity_at,
        "status": &item.status,
        "provenance": {
            "collector": &item.provenance.collector,
            "source_file_count": item.provenance.source_file_count,
            "input_token_scope": &item.provenance.input_token_scope,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        },
        "policy_neutral_component_hashes": policy_neutral_component_hashes,
    })
}

pub(crate) fn snapshot_revision_hash(
    source: SnapshotSource,
    item: &SnapshotItem,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let material = snapshot_revision_material(item, component_hashes).to_string();
    sha256_hex(&[
        SNAPSHOT_REVISION_CONTRACT_VERSION,
        source.api_slug(),
        source.parser_version(),
        source.scan_identity_version(),
        &material,
    ])
}

pub(crate) fn snapshot_revision_v2_body(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    json!({
        "canonicalization": crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        "contract": SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        "component_hashes": component_hashes,
        "parser_version": source.parser_version(),
        "scan_identity_version": source.scan_identity_version(),
        "source": source.api_slug(),
        "source_session_id": &item.source_session_id,
        "source_file_fingerprint": &item.source_file_fingerprint,
        "lifecycle": {
            "status": &item.status,
            "source_started_at": &item.source_started_at,
            "source_ended_at": &item.source_ended_at,
            "source_last_activity_at": &item.source_last_activity_at,
        },
        "provenance": {
            "collector": &item.provenance.collector,
            "input_token_scope": &item.provenance.input_token_scope,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        },
        "upload_policy": upload_policy,
    })
}

pub(crate) fn snapshot_revision_v2_hash(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let body = snapshot_revision_v2_body(source, item, upload_policy, component_hashes);
    let canonical = crate::canonical_json::canonicalize(&body)
        .expect("snapshot revision v2 body is canonicalizable");
    let mut digest = Sha256::new();
    digest.update(&canonical);
    format!("{:x}", digest.finalize())
}

pub(crate) fn snapshot_semantic_envelope(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
) -> SnapshotSemanticEnvelope {
    let component_hashes = snapshot_semantic_component_hashes(source, item);
    SnapshotSemanticEnvelope {
        component_contract_version: SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        revision_contract_version: SNAPSHOT_REVISION_CONTRACT_VERSION,
        upload_policy,
        revision_hash: snapshot_revision_hash(source, item, &component_hashes),
        revision_v2_contract_version: SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        revision_v2_canonicalization: crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        revision_v2_parser_version: source.parser_version(),
        revision_v2_scan_identity_version: source.scan_identity_version(),
        revision_v2_hash: snapshot_revision_v2_hash(source, item, upload_policy, &component_hashes),
        content_hash: snapshot_content_hash(source, &item.source_session_id, &component_hashes),
        hash_epoch: SNAPSHOT_CONTENT_HASH_EPOCH,
        component_hashes,
    }
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
    let source = snapshot_source_from_api_slug(&request.source)
        .ok_or_else(|| "unsupported snapshot source".to_string())?;
    for (index, item) in request.snapshots.iter().enumerate() {
        validate_snapshot_item(index, item)?;
        let component_hashes = snapshot_semantic_component_hashes(source, item);
        let expected_fingerprint = snapshot_fingerprint_from_component_hashes(
            source,
            &item.source_session_id,
            &component_hashes,
        );
        if item.snapshot_fingerprint != expected_fingerprint {
            return Err(format!(
                "snapshot[{index}] fingerprint does not match semantic components"
            ));
        }
        let envelope = snapshot_semantic_envelope(source, item, request.upload_policy);
        let envelope_size = serde_json::to_vec(&envelope)
            .map_err(|error| format!("snapshot[{index}] semantic_envelope: {error}"))?
            .len();
        if envelope_size > MAX_SEMANTIC_ENVELOPE_BYTES {
            return Err(format!(
                "snapshot[{index}] semantic_envelope is {envelope_size} bytes; maximum is {MAX_SEMANTIC_ENVELOPE_BYTES}"
            ));
        }
        let item_size = serde_json::to_vec(&SnapshotItemWire {
            snapshot: item,
            semantic_envelope: envelope,
        })
        .map_err(|error| format!("snapshot[{index}] wire encoding: {error}"))?
        .len();
        if item_size > MAX_SNAPSHOT_ITEM_WIRE_BYTES {
            return Err(format!(
                "snapshot[{index}] wire body is {item_size} bytes; maximum is {MAX_SNAPSHOT_ITEM_WIRE_BYTES}"
            ));
        }
    }
    let batch_size = serde_json::to_vec(request)
        .map_err(|error| format!("snapshot batch wire encoding: {error}"))?
        .len();
    if batch_size > MAX_SNAPSHOT_BATCH_WIRE_BYTES {
        return Err(format!(
            "snapshot batch wire body is {batch_size} bytes; maximum is {MAX_SNAPSHOT_BATCH_WIRE_BYTES}"
        ));
    }
    Ok(())
}

fn validate_snapshot_item(index: usize, item: &SnapshotItem) -> Result<(), String> {
    if item.compaction_timestamps.len() > MAX_COMPACTION_TIMESTAMPS {
        return Err(format!(
            "snapshot[{index}] has more than {MAX_COMPACTION_TIMESTAMPS} compaction_timestamps"
        ));
    }
    crate::session_attribution::validate_fact_limits(&item.attribution_facts)
        .map_err(|error| format!("snapshot[{index}] {error}"))?;
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
    /// True only when an existing state DB could not be read completely. A
    /// missing DB means there is no state-only source and is complete-empty.
    state_census_incomplete: bool,
    sidecar_census_incomplete: bool,
    legacy_sidecar_fingerprint: String,
    /// The old index retained only config file stats, not content or affected
    /// session ids. Presence therefore requires one conservative corrective
    /// reconciliation; absence plus a matching legacy identity is provable.
    legacy_config_file_present: bool,
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
/// Candidate identity is derived per session from extracted title content (not
/// file stats): rewriting one store file can select only its matching session.
#[derive(Debug, Clone, Default)]
struct ClaudeTitleMetadata {
    titles: BTreeMap<String, ClaudeTitleCandidate>,
    account_identifier_hashes: BTreeMap<String, BTreeSet<String>>,
    legacy_sidecar_fingerprint: String,
    sidecar_census_incomplete: bool,
}

#[derive(Debug, Clone)]
struct ClaudeTitleCandidate {
    title: String,
    /// True when the desktop `titleSource` is `user` (an explicit rename). A
    /// user-set title overrides transcript-derived titles; an auto title only
    /// fills absences.
    user_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ClaudeDesktopTitleIndexEntry {
    cli_session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    user_set: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_identifier_hash: Option<String>,
}

// The desktop store holds one ~80KB JSON per session; both caps are far above
// anything observed and exist only to bound a pathological store.
const MAX_CLAUDE_DESKTOP_SESSION_FILES: usize = 5_000;
const MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CLAUDE_DESKTOP_STORE_DEPTH: usize = 3;
const MAX_CLAUDE_DESKTOP_STORE_ENTRIES_PER_SCAN: usize = 10_000;

impl ClaudeTitleMetadata {
    fn account_identifier_hash(&self, source_session_id: &str) -> Option<&str> {
        let hashes = self.account_identifier_hashes.get(source_session_id)?;
        (hashes.len() == 1)
            .then(|| hashes.first().map(String::as_str))
            .flatten()
    }

    fn session_sidecar_fingerprint(&self, source_session_id: &str) -> String {
        let candidate = self.titles.get(source_session_id);
        let account_identity = match self.account_identifier_hashes.get(source_session_id) {
            Some(hashes) if hashes.len() == 1 => hashes.first().map(String::as_str).unwrap_or(""),
            Some(_) => "ambiguous",
            None => "",
        };
        sha256_hex(&[
            "claude_session_sidecar:v2",
            source_session_id,
            candidate.map(|value| value.title.as_str()).unwrap_or(""),
            candidate
                .map(|value| if value.user_set { "user" } else { "auto" })
                .unwrap_or(""),
            account_identity,
        ])
    }

    #[cfg(test)]
    fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut index = ScanIndex::default();
        Self::load_from_roots_with_index(roots, &mut index, "2026-07-31T00:00:00Z")
    }

    fn load_from_roots_with_index(
        roots: &[PathBuf],
        index: &mut ScanIndex,
        collected_at: &str,
    ) -> Self {
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
        Self::load_from_store_dirs_with_index(&store_dirs, index, collected_at)
    }

    fn load_from_store_dirs_with_index(
        store_dirs: &BTreeSet<PathBuf>,
        index: &mut ScanIndex,
        collected_at: &str,
    ) -> Self {
        let now = rfc3339_unix_seconds(collected_at);
        let retry_due = match (
            now,
            index.claude_desktop_store_retry_not_before_unix_seconds,
        ) {
            (_, None) => true,
            (Some(now), Some(deadline)) => {
                now >= deadline || deadline > now.saturating_add(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
            }
            (None, Some(_)) => true,
        };
        if !retry_due {
            return Self::from_durable_index(index, true);
        }

        let mut metadata = Self::default();
        let mut selection = BoundedPathSelection::new(
            index.claude_desktop_store_cursor.clone(),
            index.claude_desktop_store_upper_bound.clone(),
            MAX_CLAUDE_DESKTOP_SESSION_FILES,
        );
        let mut census = ClaudeDesktopStoreCensus::default();
        let mut remaining_entries = MAX_CLAUDE_DESKTOP_STORE_ENTRIES_PER_SCAN;
        for (position, dir) in store_dirs.iter().enumerate() {
            collect_claude_desktop_session_files(
                dir,
                0,
                &mut remaining_entries,
                &mut selection,
                &mut census,
            );
            if remaining_entries == 0 {
                if position + 1 < store_dirs.len() {
                    census.entry_budget_exceeded_count += 1;
                }
                break;
            }
        }
        let (session_files, sweep_complete, next_cursor, next_upper_bound) =
            selection.finish(census.discovered_file_count);
        for path in &session_files {
            let account_identifier_hash = store_dirs
                .iter()
                .find_map(|store_dir| claude_desktop_account_identifier_hash(store_dir, path));
            match load_claude_desktop_session_title(path, account_identifier_hash) {
                Ok(Some(entry)) => {
                    index
                        .claude_desktop_title_files
                        .insert(local_index_key(path), entry);
                }
                Ok(None) => {
                    index
                        .claude_desktop_title_files
                        .remove(&local_index_key(path));
                }
                Err(_) => census.invalid_file_count += 1,
            }
        }
        let sweep_had_errors = index.claude_desktop_store_sweep_had_errors || census.has_errors();
        if sweep_complete && !sweep_had_errors {
            index
                .claude_desktop_title_files
                .retain(|path, _| census.observed_paths.contains(path));
        }
        metadata.sidecar_census_incomplete = !sweep_complete || sweep_had_errors;
        index.claude_desktop_store_cursor = next_cursor;
        index.claude_desktop_store_upper_bound = next_upper_bound;
        index.claude_desktop_store_sweep_had_errors = if sweep_complete {
            false
        } else {
            sweep_had_errors
        };

        if metadata.sidecar_census_incomplete {
            index.claude_desktop_store_retry_attempt =
                index.claude_desktop_store_retry_attempt.saturating_add(1);
            let now = now.unwrap_or_default();
            index.claude_desktop_store_retry_not_before_unix_seconds = Some(now.saturating_add(
                unhealthy_scan_retry_delay_seconds(index.claude_desktop_store_retry_attempt),
            ));
        } else {
            index.claude_desktop_store_retry_attempt = 0;
            index.claude_desktop_store_retry_not_before_unix_seconds = None;
        }

        Self::from_durable_index_with_metadata(index, metadata)
    }

    fn from_durable_index(index: &ScanIndex, sidecar_census_incomplete: bool) -> Self {
        Self::from_durable_index_with_metadata(
            index,
            Self {
                sidecar_census_incomplete,
                ..Self::default()
            },
        )
    }

    fn from_durable_index_with_metadata(index: &ScanIndex, mut metadata: Self) -> Self {
        for entry in index.claude_desktop_title_files.values() {
            if let Some(account_identifier_hash) = &entry.account_identifier_hash {
                metadata
                    .account_identifier_hashes
                    .entry(entry.cli_session_id.clone())
                    .or_default()
                    .insert(account_identifier_hash.clone());
            }
            let Some(title) = &entry.title else {
                continue;
            };
            let candidate = ClaudeTitleCandidate {
                title: title.clone(),
                user_set: entry.user_set,
            };
            match metadata.titles.get(entry.cli_session_id.as_str()) {
                Some(existing) if existing.user_set && !candidate.user_set => {}
                _ => {
                    metadata
                        .titles
                        .insert(entry.cli_session_id.clone(), candidate);
                }
            }
        }
        let sidecar_parts = metadata
            .titles
            .iter()
            .map(|(id, candidate)| format!("{id}:{}:{}", candidate.user_set, candidate.title))
            .collect::<Vec<_>>();
        metadata.legacy_sidecar_fingerprint = sha256_hex_owned(&sidecar_parts);
        metadata
    }
}

#[derive(Debug, Default)]
struct ClaudeDesktopStoreCensus {
    discovered_file_count: usize,
    unreadable_path_count: usize,
    symlink_rejected_count: usize,
    depth_exceeded_count: usize,
    invalid_file_count: usize,
    entry_budget_exceeded_count: usize,
    observed_paths: BTreeSet<String>,
}

impl ClaudeDesktopStoreCensus {
    fn has_errors(&self) -> bool {
        self.unreadable_path_count > 0
            || self.symlink_rejected_count > 0
            || self.depth_exceeded_count > 0
            || self.invalid_file_count > 0
            || self.entry_budget_exceeded_count > 0
    }
}

#[derive(Debug)]
struct BoundedPathSelection {
    cursor: Option<String>,
    upper_bound: Option<String>,
    limit: usize,
    selected: BTreeMap<String, PathBuf>,
    observed_max: Option<String>,
}

impl BoundedPathSelection {
    fn new(cursor: Option<String>, upper_bound: Option<String>, limit: usize) -> Self {
        let cursor = cursor.filter(|_| upper_bound.is_some());
        Self {
            cursor,
            upper_bound,
            limit,
            selected: BTreeMap::new(),
            observed_max: None,
        }
    }

    fn insert(&mut self, path: PathBuf) {
        let key = local_index_key(&path);
        if self
            .observed_max
            .as_ref()
            .map_or(true, |maximum| key > *maximum)
        {
            self.observed_max = Some(key.clone());
        }
        if self.limit == 0
            || self
                .upper_bound
                .as_ref()
                .is_some_and(|upper_bound| key > *upper_bound)
            || self.cursor.as_ref().is_some_and(|cursor| key <= *cursor)
        {
            return;
        }
        self.selected.insert(key, path);
        if self.selected.len() > self.limit {
            self.selected.pop_last();
        }
    }

    fn finish(self, discovered: usize) -> (Vec<PathBuf>, bool, Option<String>, Option<String>) {
        let upper_bound = self.upper_bound.or(self.observed_max);
        let selected = self.selected.into_values().collect::<Vec<_>>();
        let next_cursor = selected.last().map(|path| local_index_key(path));
        let reached_upper_bound = next_cursor
            .as_ref()
            .zip(upper_bound.as_ref())
            .is_some_and(|(cursor, upper_bound)| cursor >= upper_bound);
        let complete = if self.limit == 0 {
            discovered == 0
        } else {
            selected.len() < self.limit || reached_upper_bound
        };
        (
            selected,
            complete,
            (!complete).then_some(next_cursor).flatten(),
            (!complete).then_some(upper_bound).flatten(),
        )
    }
}

fn collect_claude_desktop_session_files(
    dir: &Path,
    depth: usize,
    remaining_entries: &mut usize,
    selection: &mut BoundedPathSelection,
    census: &mut ClaudeDesktopStoreCensus,
) {
    if depth > MAX_CLAUDE_DESKTOP_STORE_DEPTH {
        census.depth_exceeded_count += 1;
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            census.unreadable_path_count += 1;
            return;
        }
    };
    for entry in entries {
        if *remaining_entries == 0 {
            census.entry_budget_exceeded_count += 1;
            return;
        }
        *remaining_entries -= 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        if file_type.is_symlink() {
            census.symlink_rejected_count += 1;
            continue;
        }
        if file_type.is_dir() {
            collect_claude_desktop_session_files(
                &path,
                depth + 1,
                remaining_entries,
                selection,
                census,
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        census.discovered_file_count += 1;
        census.observed_paths.insert(local_index_key(&path));
        selection.insert(path);
    }
}

fn claude_desktop_account_identifier_hash(store_dir: &Path, path: &Path) -> Option<String> {
    let account_uuid = path
        .strip_prefix(store_dir)
        .ok()
        .and_then(|relative| relative.components().next())
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        });
    account_uuid.and_then(|uuid| ottto_core::billing_identity_hash("anthropic", "account", uuid))
}

fn load_claude_desktop_session_title(
    path: &Path,
    account_identifier_hash: Option<String>,
) -> Result<Option<ClaudeDesktopTitleIndexEntry>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .context("open Claude desktop title sidecar")?;
    let metadata = file
        .metadata()
        .context("stat Claude desktop title sidecar")?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES {
        return Err(anyhow::anyhow!("Claude desktop title sidecar was invalid"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read Claude desktop title sidecar")?;
    if bytes.len() as u64 > MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES {
        return Err(anyhow::anyhow!("Claude desktop title sidecar exceeded cap"));
    }
    let value =
        serde_json::from_slice::<Value>(&bytes).context("parse Claude desktop title sidecar")?;
    // Non-session JSONs in the store (e.g. scheduled-tasks.json) lack these
    // fields and fall out here.
    let cli_session_id = match string_at(&value, &["cliSessionId"]) {
        Some(cli_session_id) => cli_session_id,
        None if value.get("cliSessionId").is_none() => return Ok(None),
        None => {
            return Err(anyhow::anyhow!(
                "Claude desktop title sidecar session id was invalid"
            ));
        }
    };
    let title = match string_at(&value, &["title"]) {
        Some(title) => Some(title),
        None if value.get("title").is_none() => None,
        None => {
            return Err(anyhow::anyhow!(
                "Claude desktop title sidecar title was invalid"
            ));
        }
    };
    let user_set =
        title.is_some() && string_at(&value, &["titleSource"]).as_deref() == Some("user");
    Ok(Some(ClaudeDesktopTitleIndexEntry {
        cli_session_id,
        title,
        user_set,
        account_identifier_hash,
    }))
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
    account_identifier_hash: Option<String>,
    title: Option<String>,
    title_source: Option<String>,
    first_prompt_title: Option<String>,
    // In-memory only: bounded first-user text used to derive opaque template,
    // schedule, and explicit slash-skill facts. The source text is never copied
    // into SnapshotItem; at most a separately sanitized 96-byte prefix is.
    first_prompt_material: Option<String>,
    // In-memory only: provider-native skill names. HMACed before facts are
    // produced; an allowlisted short name may also become a private display
    // label, which upload policy strips unless title consent is active.
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
    // Current Pi transcripts carry usage on `type=message` assistant records;
    // older exporters used `type=message_end`. When both representations are
    // present, their response id is the exact occurrence key that prevents a
    // compatibility parser from charging the same response twice.
    // Each response id retains the unmatched digest multiset for both record
    // shapes. A later opposite-shape exact match consumes one occurrence;
    // repeated same-shape occurrences remain distinct. Keeping the multiset is
    // required because transitional writers may reuse one response id for more
    // than one paired occurrence.
    seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
    // Positive usage observations deliberately refused because their activity
    // timestamp could not produce a truthful hourly bucket.
    dropped_usage_record_count: u64,
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
    compaction_timestamps: Vec<String>,
    claude_compaction_observations: Vec<ClaudeCompactionObservation>,
}

impl SnapshotAccumulator {
    fn new(source: SnapshotSource) -> Self {
        Self {
            source,
            source_session_id: None,
            account_identifier_hash: None,
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
            seen_pi_usage_keys: BTreeMap::new(),
            dropped_usage_record_count: 0,
            claude_last_user_ts: None,
            peak_context_fill_tokens: 0,
            first_turn_context_tokens: None,
            compaction_count: 0,
            compaction_timestamps: Vec::new(),
            claude_compaction_observations: Vec::new(),
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

    fn note_pi_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| pi_timestamp_is_before(&timestamp, current))
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| pi_timestamp_is_after(&timestamp, current))
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
        let value = crate::session_attribution::prompt_without_injected_scaffolding(&value);
        if value.is_empty() {
            return;
        }
        if self.first_prompt_material.is_none() {
            self.first_prompt_material = Some(value.to_string());
        }
        if self.first_prompt_title.is_none() {
            self.first_prompt_title = first_prompt_display_title(self.source, value.to_string());
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
        // A subagent transcript (Task tool or Workflow tool, at any nesting
        // depth under `subagents/`) carries its PARENT's sessionId on every line
        // and is re-keyed later in into_items; never hand a subagent session its
        // parent's desktop title. Instead, name it from the agent's own durable
        // label material (workflow label > Task description > agentType),
        // without duplicating the parent relationship in the child title.
        if let Some(identity) = claude_subagent_identity(path) {
            let label = claude_workflow_agent_label(path, &identity).or_else(|| {
                let meta = read_claude_agent_meta(path);
                meta.description.or(meta.agent_kind)
            });
            if let Some(label) = label {
                // Unconditional set: the deterministic agent label is the
                // operator-approved name for these sessions and must also
                // replace any prompt-derived candidate captured line-by-line.
                self.set_title(Some(label), "agent_label");
            }
            return;
        }
        self.account_identifier_hash = metadata
            .account_identifier_hash(session_id.as_str())
            .map(str::to_string);
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

    fn note_dropped_usage(&mut self) {
        self.dropped_usage_record_count = self.dropped_usage_record_count.saturating_add(1);
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
            self.note_dropped_usage();
            return;
        };
        let Some((bucket_start, normalized_timestamp)) =
            activity_bucket_from_timestamp(&bucket_input)
        else {
            self.note_dropped_usage();
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
        // Defence in depth: the scan already refuses to collect the Workflow
        // journal, but the parse entry points are public, so nothing downstream
        // may mint a `<parentSessionId>_journal` session either.
        if self.source == SnapshotSource::ClaudeCode
            && claude_transcript_excluded_from_snapshots(path)
        {
            return Vec::new();
        }
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
        // A Claude Code subagent transcript (Task tool or Workflow tool) shares
        // its parent's `sessionId`; re-key it from its PATH to a distinct id so
        // it ingests as its own `isSidechain=true` (ai_agent) session instead of
        // collapsing into -- and overwriting -- the human parent. Top-level
        // transcripts are unchanged.
        let claude_subagent = (self.source == SnapshotSource::ClaudeCode)
            .then(|| claude_subagent_identity(path))
            .flatten();
        let source_session_id = match claude_subagent.as_ref() {
            Some(identity) => identity.source_session_id(),
            None => source_session_id,
        };
        // Subagent tree position, read from the provider's own sidecar. Absent
        // or malformed metadata simply leaves the derived facts absent.
        let claude_agent_meta = claude_subagent
            .as_ref()
            .map(|_| read_claude_agent_meta(path))
            .unwrap_or_default();
        if let Some(identity) = claude_subagent.as_ref() {
            // DIRECT parent: the top-level session for a depth-1 agent, or the
            // spawning agent's own re-keyed session id when the provider records
            // a `parentAgentId`, so the tree edge is exact rather than flattened
            // onto the root.
            self.origin.parent_session_ref =
                Some(match claude_agent_meta.parent_agent_id.as_deref() {
                    Some(parent_agent_id) => {
                        format!("{}_agent-{parent_agent_id}", identity.root_session_id)
                    }
                    None => identity.root_session_id.clone(),
                });
        }
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
        // Subagent identity rides immediately behind the direct provider facts
        // and ahead of the grouping facts: `enforce_fact_limits` trims from the
        // tail, so the tree edges and the agent identity outrank the derived
        // grouping ids inside the bounded payload budget.
        if let Some(identity) = claude_subagent.as_ref() {
            attribution_facts.extend(crate::session_attribution::claude_subagent_facts(
                &crate::session_attribution::ClaudeSubagentAttribution {
                    root_session_ref: &identity.root_session_id,
                    agent_kind: claude_agent_meta.agent_kind.as_deref(),
                    agent_ref: identity.agent_ref(),
                    spawn_depth: claude_agent_meta.spawn_depth.as_deref(),
                    workflow_ref: identity.workflow_ref.as_deref(),
                },
                &source_session_id,
                collected_at,
                self.source.parser_version(),
            ));
        }
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
        }
        // Unconditional: `direct_provider_facts` bounds only its own output, so
        // anything appended after it (subagent identity, grouping ids) has to be
        // re-bounded here or an item could exceed the payload budget the backend
        // schema rejects.
        crate::session_attribution::enforce_fact_limits(&mut attribution_facts);
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
        let mut model_usage: Vec<SnapshotModelUsage> = session_rows
            .iter()
            .map(|(row_key, row)| model_usage_from_row(row_key, row))
            .collect();
        for row in &mut model_usage {
            row.account_identifier_hash = self.account_identifier_hash.clone();
        }
        for bucket in &mut usage_buckets {
            for row in &mut bucket.model_usage {
                row.account_identifier_hash = self.account_identifier_hash.clone();
            }
        }
        let mut totals = UsageTotals::default();
        for row in session_rows.values() {
            totals.add(&row.usage);
        }
        let (compaction_count, compaction_timestamps) = if self.source == SnapshotSource::ClaudeCode
        {
            claude_compaction_summary(&self.claude_compaction_observations)
        } else {
            (
                self.compaction_count,
                bounded_compaction_timestamps(self.compaction_timestamps),
            )
        };
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
                .then_some(compaction_count),
            compaction_timestamps: if self.source.derives_context_posture() {
                compaction_timestamps
            } else {
                Vec::new()
            },
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
            // Forward-looking top-level mirror of the Codex `session_meta`
            // originator (e.g. `codex_work_desktop`). `origin.originator` is only
            // ever populated by the Codex line parser, but guard on `source` too
            // so a non-Codex path can never fabricate one.
            originator: match self.source {
                SnapshotSource::Codex => self.origin.originator.clone(),
                SnapshotSource::ClaudeCode | SnapshotSource::Pi => None,
            },
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
        account_identifier_hash: None,
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
    let mut result = scan_source_roots_with_artifacts(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        true,
    )?;
    // This convenience entry has no later privacy/enrichment stage. Finalize
    // immediately so its incremental state has the same final semantic entity
    // sets as the production path, which explicitly finalizes after policy.
    finalize_scan_after_policy(source, &mut result, index);
    Ok(result)
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
        None,
        &[],
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scan_source_roots_with_attribution_and_hints(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
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
        None,
        hinted_paths,
        watcher_overflowed,
    )
}

/// Production scan entry that tracks both the local Claude OTLP sidecar and
/// bounded watcher hints. Keeping the support directory explicit preserves
/// the pure scan API for audits and backfills.
#[allow(clippy::too_many_arguments)]
pub fn scan_source_roots_with_attribution_and_claude_effort_and_hints(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    claude_effort_support_dir: Option<&Path>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
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
        claude_effort_support_dir,
        hinted_paths,
        watcher_overflowed,
    )
}

/// Compatibility entry retained for focused account-attribution and effort
/// sidecar tests that do not exercise watcher hints.
#[allow(clippy::too_many_arguments)]
pub fn scan_source_roots_with_attribution_and_claude_effort(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    claude_effort_support_dir: Option<&Path>,
) -> Result<SourceScanResult> {
    scan_source_roots_with_attribution_and_claude_effort_and_hints(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        artifacts_enabled,
        attribution_context,
        claude_effort_support_dir,
        &[],
        false,
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
        None,
        &[],
        false,
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
    claude_effort_support_dir: Option<&Path>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) -> Result<SourceScanResult> {
    index.activate_quarantine_witness(source);
    let backfill_window_days = effective_backfill_window_days(requested_backfill_window_days);
    let codex_title_metadata = if source == SnapshotSource::Codex {
        CodexTitleMetadata::load_from_roots(roots)
    } else {
        CodexTitleMetadata::default()
    };
    let claude_sidecar_was_incomplete = source == SnapshotSource::ClaudeCode
        && (index
            .claude_desktop_store_retry_not_before_unix_seconds
            .is_some()
            || index.claude_desktop_store_cursor.is_some()
            || index.claude_desktop_store_sweep_had_errors);
    let claude_title_metadata = if source == SnapshotSource::ClaudeCode {
        ClaudeTitleMetadata::load_from_roots_with_index(roots, index, collected_at)
    } else {
        ClaudeTitleMetadata::default()
    };
    let state_census_complete =
        source != SnapshotSource::Codex || !codex_title_metadata.state_census_incomplete;
    let sidecar_census_complete = match source {
        SnapshotSource::Codex => !codex_title_metadata.sidecar_census_incomplete,
        SnapshotSource::ClaudeCode => !claude_title_metadata.sidecar_census_incomplete,
        SnapshotSource::Pi => true,
    };
    if claude_sidecar_was_incomplete && sidecar_census_complete {
        // The prior transcript generation was intentionally held red while
        // title discovery was partial. Start a fresh bounded transcript walk
        // now so sidecar additions/removals are folded into each affected
        // file fingerprint before a terminal manifest can publish.
        index.traversal = None;
    }
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
    ensure_bounded_traversal(source, roots, index, collected_at, backfill_window_days);
    let traversal = index.traversal.as_mut().expect("traversal initialized");
    enqueue_watcher_hints(source, traversal, hinted_paths, watcher_overflowed);
    advance_bounded_directory_traversal(source, traversal, backfill_window_days);
    let census_window_end = traversal.census_window_end.clone();
    let discovered_file_count = traversal.counts.discovered_file_count;
    let mut pending_paths = Vec::new();
    // Watcher freshness must not starve the durable census when callers use a
    // small page size. Production reserves almost the whole 10k page already,
    // but the explicit slot also makes liveness independent of that ratio.
    let ordinary_census_pending = traversal
        .pending_candidates
        .iter()
        .any(|candidate| candidate.census_member && !candidate.watcher_hint);
    let hinted_budget = file_limit
        .min(MAX_WATCHER_HINTED_FILES_PER_TICK)
        .saturating_sub(usize::from(ordinary_census_pending && file_limit > 0));
    for _ in 0..hinted_budget {
        let Some(position) = traversal
            .pending_candidates
            .iter()
            .position(|candidate| candidate.watcher_hint)
        else {
            break;
        };
        if let Some(candidate) = traversal.pending_candidates.remove(position) {
            pending_paths.push(candidate);
        }
    }
    while pending_paths.len() < file_limit {
        let Some(position) = traversal
            .pending_candidates
            .iter()
            .position(|candidate| candidate.census_member && !candidate.watcher_hint)
        else {
            break;
        };
        if let Some(candidate) = traversal.pending_candidates.remove(position) {
            pending_paths.push(candidate);
        }
    }
    while pending_paths.len() < file_limit {
        let Some(candidate) = traversal.pending_candidates.pop_front() else {
            break;
        };
        pending_paths.push(candidate);
    }
    index.resume_census_window_end = Some(census_window_end.clone());
    let census_unix_seconds = rfc3339_unix_seconds(&census_window_end);
    let mut census = ScanCensus::default();
    let mut files = pending_paths
        .into_iter()
        .filter_map(|pending| {
            candidate_from_traversal_path(
                source,
                pending,
                &mut census,
                census_unix_seconds,
                backfill_window_days,
            )
        })
        .collect::<Vec<_>>();

    let legacy_sidecar_fingerprint = match source {
        SnapshotSource::Codex => codex_title_metadata.legacy_sidecar_fingerprint.as_str(),
        SnapshotSource::ClaudeCode => claude_title_metadata.legacy_sidecar_fingerprint.as_str(),
        SnapshotSource::Pi => "",
    };
    for candidate in &mut files {
        // Sidecar contribution is path-derived and can be computed before the
        // transcript opens. Transcript identity itself is filled from the
        // exact opened object below, never from discovery metadata.
        let legacy_sidecar_fingerprint = match source {
            SnapshotSource::Codex => codex_title_metadata.legacy_sidecar_fingerprint.as_str(),
            SnapshotSource::ClaudeCode => claude_title_metadata.legacy_sidecar_fingerprint.as_str(),
            SnapshotSource::Pi => "",
        };
        candidate.legacy_source_file_fingerprint = source_file_fingerprint_with_context(
            &candidate.path,
            candidate.size_bytes,
            candidate.modified_unix_seconds,
            source.parser_version(),
            legacy_sidecar_fingerprint,
        );
        candidate.legacy_config_reconciliation_required =
            source == SnapshotSource::Codex && codex_title_metadata.legacy_config_file_present;
        let sidecar_fingerprint = match source {
            SnapshotSource::Codex => codex_session_id_from_path(&candidate.path)
                .map(|session_id| {
                    codex_title_metadata.session_sidecar_fingerprint(session_id.as_str())
                })
                .unwrap_or_default(),
            SnapshotSource::ClaudeCode => {
                // A subagent transcript at any depth under `subagents/` has no
                // desktop-store entry of its own: its file stem is an agent id,
                // never a session id, so looking one up would either miss or
                // (worse) collide with an unrelated session. Its NAMING
                // material lives elsewhere — the `meta.json` sidecar and the
                // Workflow run manifest — so those feed the scan fingerprint
                // instead: a label arriving AFTER the transcript was indexed
                // must still re-select the unchanged transcript for a title re-emit
                // (same late-sidecar rationale as claude_code v14).
                if let Some(identity) = claude_subagent_identity(&candidate.path) {
                    claude_subagent_sidecar_fingerprint(&candidate.path, &identity)
                } else {
                    candidate
                        .path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .map(|session_id| {
                            let desktop_fingerprint =
                                claude_title_metadata.session_sidecar_fingerprint(session_id);
                            let effort_fingerprint = claude_effort_support_dir
                                .map(|support_dir| {
                                    crate::claude_effort::claude_effort_sidecar_fingerprint(
                                        support_dir,
                                        session_id,
                                    )
                                })
                                .unwrap_or_default();
                            if effort_fingerprint.is_empty() {
                                desktop_fingerprint
                            } else {
                                sha256_hex(&[
                                    "claude_session_sidecars:v1",
                                    desktop_fingerprint.as_str(),
                                    effort_fingerprint.as_str(),
                                ])
                            }
                        })
                        .unwrap_or_default()
                }
            }
            SnapshotSource::Pi => String::new(),
        };
        // Temporarily retain the sidecar digest in the source fingerprint slot;
        // the exact opened-object fingerprint replaces it immediately before
        // candidate comparison and parsing.
        candidate.source_file_fingerprint = sidecar_fingerprint;
    }
    let mut snapshots = Vec::new();
    let mut scanned_file_count = 0;
    let mut scanned_session_count = 0;
    let mut semantic_noop_count = 0;
    let mut pending_finalization = Vec::new();
    for mut candidate in files {
        let opened_file = match open_candidate_file(source, &mut candidate) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                census.disappeared_file_count += 1;
                continue;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::InvalidData
                    && candidate.size_bytes > max_jsonl_file_bytes(source) =>
            {
                census.oversized_file_count += 1;
                continue;
            }
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        if !opened_candidate_is_within_frozen_window(
            &candidate,
            census_unix_seconds,
            backfill_window_days,
        ) {
            // The path can be atomically replaced after directory/candidate
            // stat but before the no-follow open. Eligibility follows the
            // exact opened object, not stale discovery metadata; otherwise an
            // object outside the frozen lookback can enter this generation.
            census
                .removed_index_keys
                .insert(local_index_key(&candidate.path));
            continue;
        }
        let session_sidecar_fingerprint = std::mem::take(&mut candidate.source_file_fingerprint);
        candidate.legacy_source_file_fingerprint = source_file_fingerprint_with_context(
            &candidate.path,
            candidate.size_bytes,
            candidate.modified_unix_seconds,
            source.parser_version(),
            legacy_sidecar_fingerprint,
        );
        candidate.source_file_fingerprint = scan_file_fingerprint_with_opened_identity(
            &candidate.path,
            candidate.size_bytes,
            candidate.modified_unix_nanos,
            source.scan_identity_version(),
            &session_sidecar_fingerprint,
            &candidate.opened_object_identity,
        );
        let decision = index.candidate_decision(&candidate);
        match decision {
            CandidateDecision::Skip => continue,
            CandidateDecision::Migrate => {
                index.migrate(candidate);
                continue;
            }
            CandidateDecision::ReconcileLegacy | CandidateDecision::Parse => {}
        }
        scanned_file_count += 1;
        let previous_snapshot_fingerprint = index.last_snapshot_fingerprint(&candidate);
        let source_file_fingerprint = candidate.source_file_fingerprint.clone();
        let parsed_file = match source {
            SnapshotSource::Codex => parse_opened_jsonl_file(
                opened_file,
                &candidate.opened_object_identity,
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                source,
                apply_codex_line,
                Some(&codex_title_metadata),
                None,
                codex_turn_traces.clone(),
                true,
                attribution_context,
            ),
            SnapshotSource::ClaudeCode => parse_opened_jsonl_file(
                opened_file,
                &candidate.opened_object_identity,
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                source,
                apply_claude_code_line,
                None,
                Some(&claude_title_metadata),
                None,
                artifacts_enabled,
                attribution_context,
            ),
            SnapshotSource::Pi => parse_opened_jsonl_file(
                opened_file,
                &candidate.opened_object_identity,
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                source,
                apply_pi_line,
                None,
                None,
                None,
                true,
                attribution_context,
            ),
        };
        let parsed_file = match parsed_file {
            Ok(parsed) => parsed,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        let parse_complete = parsed_file.complete();
        let report = parsed_file.report;
        let recognized_usage_drop_count = parsed_file.recognized_usage_drop_count;
        let zero_snapshot_usage_evidence = parsed_file.zero_snapshot_usage_evidence;
        let dropped_usage_record_count = parsed_file.dropped_usage_record_count;
        let mut parsed = parsed_file.snapshots;
        if source == SnapshotSource::Codex {
            for snapshot in parsed.iter_mut() {
                apply_codex_state_evidence(snapshot, &codex_title_metadata);
            }
        }
        scanned_session_count += parsed.len();
        let last_snapshot_fingerprint = parsed
            .last()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone());
        let parsed_snapshot_count = parsed.len();
        let index_key = local_index_key(&candidate.path);
        pending_finalization.push(PendingIndexFinalization {
            index_key,
            source_file_fingerprint: source_file_fingerprint.clone(),
            previous_snapshot_fingerprint: (decision != CandidateDecision::ReconcileLegacy)
                .then_some(previous_snapshot_fingerprint)
                .flatten(),
            parse_complete,
            parsed_snapshot_count,
        });
        if parse_complete {
            let outcome = if last_snapshot_fingerprint.is_some() {
                ScanParseOutcome::Snapshot
            } else {
                ScanParseOutcome::ConfirmedEmpty
            };
            index.record(candidate, last_snapshot_fingerprint, outcome);
        }
        census.malformed_json_line_count += report.malformed_json_line_count;
        census.invalid_utf8_line_count += report.invalid_utf8_line_count;
        census.over_line_cap_count += report.over_line_cap_count;
        census.recognized_usage_drop_count += recognized_usage_drop_count;
        census.zero_snapshot_usage_evidence_count += usize::from(zero_snapshot_usage_evidence);
        census.dropped_usage_record_count = census
            .dropped_usage_record_count
            .saturating_add(dropped_usage_record_count);
        // A lossy file is one quarantined input, not a partially-authoritative
        // entity. Healthy siblings continue, but none of this file's derived
        // snapshots may reach upload/progress/manifest state until every line
        // is readable and recognized.
        if parse_complete {
            snapshots.extend(parsed);
        }
    }
    if let Some(traversal) = index.traversal.as_mut() {
        // Exact watcher remove/rename hints must amend the same durable
        // observation set used by directory census reconciliation. Apply
        // removals first so a valid observation later in this page wins.
        for index_key in &census.removed_index_keys {
            traversal.observed_index_keys.remove(index_key);
        }
        traversal
            .observed_index_keys
            .extend(census.observed_index_keys.iter().cloned());
        traversal.counts.directory_entry_cap_exceeded_count +=
            census.directory_entry_cap_exceeded_count;
        traversal.counts.symlink_rejected_count += census.symlink_rejected_count;
        traversal.counts.unreadable_path_count += census.unreadable_path_count;
        traversal.counts.oversized_file_count += census.oversized_file_count;
        traversal.counts.disappeared_file_count += census.disappeared_file_count;
        traversal.counts.malformed_json_line_count += census.malformed_json_line_count;
        traversal.counts.invalid_utf8_line_count += census.invalid_utf8_line_count;
        traversal.counts.over_line_cap_count += census.over_line_cap_count;
        traversal.counts.recognized_usage_drop_count += census.recognized_usage_drop_count;
        traversal.counts.zero_snapshot_usage_evidence_count +=
            census.zero_snapshot_usage_evidence_count;
        traversal.counts.dropped_usage_record_count = traversal
            .counts
            .dropped_usage_record_count
            .saturating_add(census.dropped_usage_record_count);
    }
    // A remove/rename hint can arrive after bounded reconciliation has already
    // passed this key. Removing it only from `observed_index_keys` is then too
    // late: the reconciliation cursor will never revisit the stale entry and a
    // terminal manifest can still publish it. The hint was revalidated as
    // absent beneath the configured root above, so retire the corresponding
    // derived index state directly. Any recreation after this absence witness
    // belongs to the next generation.
    for index_key in &census.removed_index_keys {
        index.remove_file_entry(index_key);
    }
    let traversal_snapshot = index
        .traversal
        .as_ref()
        .cloned()
        .expect("traversal remains active");
    let traversal_discovery_done = traversal_snapshot.pending_directories.is_empty()
        && traversal_snapshot.pending_candidates.is_empty();
    let traversal_healthy = !traversal_snapshot.counts.has_errors();
    let clean_frozen_generation = !traversal_snapshot.watcher_hint_seen;
    let reconciliation_complete = if traversal_discovery_done
        && traversal_healthy
        && clean_frozen_generation
        && state_census_complete
        && sidecar_census_complete
    {
        reconcile_missing_index_entries_bounded(index)
    } else {
        false
    };
    if source == SnapshotSource::Codex {
        // Reconcile authoritative transcript deletions before deciding which
        // state-database threads are file-backed. Otherwise a vanished rollout
        // remains "covered" for this whole generation, the state-only fallback
        // is delayed one cycle, and a complete terminal manifest can briefly
        // omit a thread the local state database still proves exists.
        let (state_only_scanned, state_only_noops) = append_codex_state_only_snapshots(
            &mut snapshots,
            &codex_title_metadata,
            collected_at,
            index,
        );
        scanned_session_count += state_only_scanned;
        semantic_noop_count += state_only_noops;
    }
    let census_complete = traversal_discovery_done
        && traversal_healthy
        && clean_frozen_generation
        && state_census_complete
        && sidecar_census_complete
        && reconciliation_complete;
    let reconciliation_pending = traversal_discovery_done
        && traversal_healthy
        && clean_frozen_generation
        && state_census_complete
        && sidecar_census_complete
        && !reconciliation_complete;
    let pending_work_count = index
        .traversal
        .as_ref()
        .map(|traversal| {
            traversal
                .pending_candidates
                .len()
                .saturating_add(traversal.pending_directories.len())
                .saturating_add(usize::from(reconciliation_pending))
        })
        .unwrap_or_default();
    let skipped_file_count_due_to_limit = index
        .traversal
        .as_ref()
        .map(|traversal| traversal.pending_candidates.len())
        .unwrap_or_default();
    let restart_after_hints =
        traversal_discovery_done && traversal_healthy && !clean_frozen_generation;
    let terminal_unhealthy = traversal_discovery_done && !traversal_healthy;
    if terminal_unhealthy {
        let now = rfc3339_unix_seconds(collected_at).unwrap_or_default();
        let traversal = index.traversal.as_mut().expect("traversal remains active");
        if traversal.unhealthy_retry_not_before_unix_seconds.is_none() {
            traversal.unhealthy_retry_attempt = traversal.unhealthy_retry_attempt.saturating_add(1);
            traversal.unhealthy_retry_not_before_unix_seconds = Some(now.saturating_add(
                unhealthy_scan_retry_delay_seconds(traversal.unhealthy_retry_attempt),
            ));
        }
    }
    let pending_work_count = pending_work_count
        .saturating_add(usize::from(restart_after_hints))
        .saturating_add(usize::from(terminal_unhealthy));
    if census_complete || restart_after_hints {
        index.traversal = None;
        index.resume_after_path = None;
        index.resume_upper_bound_path = None;
        index.resume_census_window_end = None;
    }
    let counts = traversal_snapshot.counts;
    let zero_snapshot_confirmed_count = index.confirmed_empty_files.len();
    let zero_snapshot_usage_evidence_count = counts.zero_snapshot_usage_evidence_count;
    let dropped_usage_record_count = counts.dropped_usage_record_count;
    Ok(SourceScanResult {
        source,
        backfill_window_days,
        backfill_file_limit: file_limit,
        discovered_file_count,
        skipped_file_count_due_to_limit,
        scan_cap_hit: pending_work_count > 0,
        scanned_file_count,
        scanned_session_count,
        semantic_noop_count,
        census_complete,
        census_window_end,
        state_census_complete,
        sidecar_census_complete,
        symlink_rejected_count: counts.symlink_rejected_count,
        directory_entry_cap_exceeded_count: counts.directory_entry_cap_exceeded_count,
        unreadable_path_count: counts.unreadable_path_count,
        oversized_file_count: counts.oversized_file_count,
        disappeared_file_count: counts.disappeared_file_count,
        malformed_json_line_count: counts.malformed_json_line_count,
        invalid_utf8_line_count: counts.invalid_utf8_line_count,
        over_line_cap_count: counts.over_line_cap_count,
        recognized_usage_drop_count: counts.recognized_usage_drop_count,
        zero_snapshot_confirmed_count,
        zero_snapshot_usage_evidence_count,
        dropped_usage_record_count,
        snapshots,
        pending_finalization,
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
    index: &mut ScanIndex,
) -> (usize, usize) {
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
    let mut scanned_session_count = 0;
    for (source_session_id, thread) in &metadata.state_threads {
        if thread.tokens_used == 0
            || covered_session_ids.contains(source_session_id)
            || covered_in_prior_runs.contains(source_session_id)
        {
            continue;
        }
        let snapshot = codex_state_only_snapshot(source_session_id, thread, collected_at);
        scanned_session_count += 1;
        // The final fingerprint can still change during enrichment, privacy
        // policy application, or account-cutoff filtering. Always carry the
        // provisional item to `finalize_scan_after_policy`, which owns both
        // durable state and semantic no-op suppression.
        snapshots.push(snapshot);
    }
    (scanned_session_count, 0)
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
        account_identifier_hash: None,
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
        compaction_timestamps: Vec::new(),
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
        originator: None,
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
    parse_codex_jsonl_file_with_diagnostics(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        codex_turn_traces,
        attribution_context,
    )
    .map(|parsed| parsed.snapshots)
}

fn parse_codex_jsonl_file_with_diagnostics(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
    codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
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
    parse_claude_code_jsonl_file_with_diagnostics(
        path,
        collected_at,
        source_file_fingerprint,
        title_metadata,
        artifacts_enabled,
        attribution_context,
    )
    .map(|parsed| parsed.snapshots)
}

fn parse_claude_code_jsonl_file_with_diagnostics(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &ClaudeTitleMetadata,
    artifacts_enabled: bool,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
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
    parse_pi_jsonl_file_with_diagnostics(
        path,
        collected_at,
        source_file_fingerprint,
        attribution_context,
    )
    .map(|parsed| parsed.snapshots)
}

fn parse_pi_jsonl_file_with_diagnostics(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<ParsedSnapshotFile> {
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

#[derive(Debug)]
struct ParsedSnapshotFile {
    snapshots: Vec<SnapshotItem>,
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
) -> Result<ParsedSnapshotFile> {
    let mut file = File::open(path).with_context(|| format!("open JSONL {}", path.display()))?;
    let opened_identity = opened_object_identity(source, &mut file)
        .with_context(|| format!("fingerprint opened JSONL {}", path.display()))?;
    let parsed = parse_opened_jsonl_file(
        file,
        &opened_identity,
        path,
        collected_at,
        source_file_fingerprint,
        source,
        apply_line,
        codex_title_metadata,
        claude_title_metadata,
        codex_turn_traces,
        artifacts_enabled,
        attribution_context,
    )?;
    Ok(ParsedSnapshotFile {
        snapshots: parsed.snapshots,
    })
}

#[derive(Debug)]
struct ParsedJsonlFile {
    snapshots: Vec<SnapshotItem>,
    report: JsonlReadReport,
    recognized_usage_drop_count: usize,
    zero_snapshot_usage_evidence: bool,
    dropped_usage_record_count: u64,
}

impl ParsedJsonlFile {
    fn complete(&self) -> bool {
        self.report.complete() && self.recognized_usage_drop_count == 0
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_opened_jsonl_file(
    file: File,
    expected_opened_object_identity: &str,
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
) -> Result<ParsedJsonlFile> {
    let mut reader = BufReader::new(file);
    // Snapshot semantics come from provider-native session evidence. Mutable
    // current config defaults are useful for live status display, but applying
    // today's defaults to cumulative historical usage would retroactively
    // rewrite old sessions and make a config edit a global replay trigger.
    let mut accumulator = SnapshotAccumulator::new(source);
    accumulator.artifacts_enabled = artifacts_enabled;
    accumulator.codex_turn_traces = codex_turn_traces;
    let mut recognized_usage_drop_count = 0;
    let mut positive_recognized_usage_count: usize = 0;
    let mut positive_usage_evidence = false;
    let report = read_bounded_jsonl_lines(&mut reader, MAX_JSONL_LINE_BYTES, |value| {
        if recognized_usage_shape_was_dropped(source, value) {
            recognized_usage_drop_count += 1;
        }
        if recognized_positive_usage_shape(source, value) {
            positive_recognized_usage_count += 1;
        }
        positive_usage_evidence |= json_has_positive_usage_evidence(value);
        apply_line(value, &mut accumulator);
    })
    .with_context(|| format!("read JSONL {}", path.display()))?;
    let observed_after_read = opened_object_identity(source, reader.get_mut())
        .with_context(|| format!("revalidate opened JSONL {}", path.display()))?;
    if observed_after_read != expected_opened_object_identity {
        return Err(anyhow::anyhow!(
            "opened snapshot candidate changed while it was parsed"
        ));
    }
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
        // A subagent transcript's "first user prompt" is the Task/Workflow
        // prompt BODY the parent injected, not a human-authored title. Agent
        // sessions are named from label material only (`agent_label` above);
        // prompt content must never become their display name. The captured
        // first-prompt MATERIAL still feeds attribution grouping unchanged.
        if claude_subagent_identity(path).is_none() {
            accumulator.apply_first_prompt_fallback();
        }
    }
    if source == SnapshotSource::Pi {
        accumulator.apply_first_prompt_fallback();
        recognized_usage_drop_count += accumulator
            .seen_pi_usage_keys
            .values()
            .filter(|state| state.has_cross_shape_conflict())
            .count();
    }
    let accumulator_dropped_usage_record_count = accumulator.dropped_usage_record_count as usize;
    recognized_usage_drop_count =
        recognized_usage_drop_count.saturating_add(accumulator_dropped_usage_record_count);
    let snapshots = accumulator.into_items(
        path,
        collected_at,
        source_file_fingerprint,
        attribution_context,
    );
    // A syntactically valid, positive provider usage record that yields no
    // entity is still loss. Typical causes are an absent/unparseable activity
    // timestamp or an identity shape the accumulator cannot settle. Treat the
    // whole file as retryable instead of persisting it as confirmed-empty.
    let zero_snapshot_usage_evidence = snapshots.is_empty() && positive_usage_evidence;
    if snapshots.is_empty() {
        recognized_usage_drop_count = recognized_usage_drop_count.saturating_add(
            positive_recognized_usage_count.saturating_sub(accumulator_dropped_usage_record_count),
        );
        if positive_usage_evidence && positive_recognized_usage_count == 0 {
            recognized_usage_drop_count = recognized_usage_drop_count.saturating_add(1);
        }
    }
    Ok(ParsedJsonlFile {
        snapshots,
        report,
        recognized_usage_drop_count,
        zero_snapshot_usage_evidence,
        dropped_usage_record_count: recognized_usage_drop_count as u64,
    })
}

fn recognized_positive_usage_shape(source: SnapshotSource, value: &Value) -> bool {
    match source {
        SnapshotSource::Codex => codex_total_usage(value)
            .map(|usage| !usage.is_zero())
            .unwrap_or(false),
        SnapshotSource::ClaudeCode => claude_code_delta_usage(value)
            .map(|usage| !usage.is_zero())
            .unwrap_or(false),
        SnapshotSource::Pi => {
            pi_usage_event(value)
                && pi_message_usage(value)
                    .map(|usage| !usage.is_zero())
                    .unwrap_or(false)
        }
    }
}

fn recognized_usage_shape_was_dropped(source: SnapshotSource, value: &Value) -> bool {
    match source {
        SnapshotSource::Codex => {
            let recognized = value
                .pointer("/token_count/info/total_token_usage")
                .is_some()
                || value.pointer("/payload/info/total_token_usage").is_some()
                || value.pointer("/payload/total_token_usage").is_some()
                || value.pointer("/total_token_usage").is_some();
            recognized && codex_total_usage(value).is_none()
        }
        SnapshotSource::ClaudeCode => {
            let recognized = value.pointer("/message/usage").is_some()
                || value.pointer("/usage").is_some()
                || value.pointer("/payload/usage").is_some();
            recognized && claude_code_delta_usage(value).is_none()
        }
        SnapshotSource::Pi => {
            pi_usage_event(value)
                && value.pointer("/message/usage").is_some()
                && pi_message_usage(value).is_none()
        }
    }
}

fn json_has_positive_usage_evidence(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            let object_kind = json_usage_object_kind(values);
            values.iter().any(|(name, value)| {
                let normalized = normalized_usage_key(name);
                if json_usage_child_is_opaque(&normalized, object_kind) {
                    return false;
                }
                (is_recognized_usage_container(&normalized)
                    && usage_container_has_positive_consumption(value, false))
                    || json_has_positive_usage_evidence(value)
            })
        }
        Value::Array(values) => values.iter().any(json_has_positive_usage_evidence),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonUsageObjectKind {
    ProviderEnvelope,
    AssistantMessage,
    OpaqueAuthored,
}

fn json_usage_object_kind(values: &serde_json::Map<String, Value>) -> JsonUsageObjectKind {
    let normalized = |key| {
        values
            .get(key)
            .and_then(Value::as_str)
            .map(normalized_usage_key)
    };
    if normalized("role").is_some_and(|role| matches!(role.as_str(), "assistant" | "model"))
        || normalized("type")
            .is_some_and(|kind| matches!(kind.as_str(), "assistantmessage" | "modelmessage"))
    {
        return JsonUsageObjectKind::AssistantMessage;
    }
    if normalized("role").is_some_and(|role| {
        matches!(
            role.as_str(),
            "user" | "human" | "system" | "developer" | "tool"
        )
    }) || normalized("type").is_some_and(|kind| {
        matches!(
            kind.as_str(),
            "user"
                | "human"
                | "system"
                | "developer"
                | "usermessage"
                | "tool"
                | "text"
                | "inputtext"
                | "outputtext"
                | "thinking"
                | "redactedthinking"
                | "tooluse"
                | "toolresult"
                | "toolcall"
                | "function"
                | "functioncall"
                | "functionresult"
                | "image"
                | "document"
        )
    }) {
        return JsonUsageObjectKind::OpaqueAuthored;
    }
    JsonUsageObjectKind::ProviderEnvelope
}

fn json_usage_child_is_opaque(name: &str, object_kind: JsonUsageObjectKind) -> bool {
    (object_kind == JsonUsageObjectKind::OpaqueAuthored && is_recognized_usage_container(name))
        || (object_kind != JsonUsageObjectKind::ProviderEnvelope
            && matches!(
                name,
                "content"
                    | "contents"
                    | "text"
                    | "prompt"
                    | "prompts"
                    | "argument"
                    | "arguments"
                    | "args"
                    | "toolinput"
                    | "tooloutput"
                    | "toolresult"
                    | "message"
                    | "payload"
                    | "data"
                    | "input"
                    | "output"
                    | "result"
            ))
}

fn normalized_usage_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_recognized_usage_container(name: &str) -> bool {
    matches!(
        name,
        "usage"
            | "tokenusage"
            | "totalusage"
            | "totaltokenusage"
            | "lasttokenusage"
            | "billingusage"
    )
}

fn is_consumption_metric(name: &str) -> bool {
    matches!(
        name,
        "input"
            | "output"
            | "inputtokens"
            | "outputtokens"
            | "prompttokens"
            | "completiontokens"
            | "cachedinputtokens"
            | "cacheread"
            | "cachereadtokens"
            | "cachereadinputtokens"
            | "cachewrite"
            | "cachewritetokens"
            | "cachecreationtokens"
            | "cachecreationinputtokens"
            | "reasoning"
            | "reasoningtokens"
            | "reasoningoutputtokens"
            | "unattributedtotaltokens"
            | "totaltokens"
            | "requestcount"
            | "requests"
    )
}

fn is_cost_container(name: &str) -> bool {
    matches!(
        name,
        "cost" | "costs" | "usagecost" | "usagecosts" | "billingcost" | "billingcosts"
    )
}

fn is_cost_metric(name: &str) -> bool {
    matches!(
        name,
        "total"
            | "amount"
            | "usd"
            | "totalcost"
            | "inputcost"
            | "outputcost"
            | "cachereadcost"
            | "cachewritecost"
            | "reasoningcost"
    )
}

fn is_nonconsumption_metadata(name: &str) -> bool {
    matches!(
        name,
        "version"
            | "schemaversion"
            | "usageversion"
            | "limit"
            | "limits"
            | "usagelimit"
            | "usagelimits"
            | "ratelimit"
            | "ratelimits"
            | "budget"
            | "budgets"
            | "quota"
            | "quotas"
            | "reset"
            | "resetsat"
            | "timestamp"
            | "createdat"
            | "updatedat"
            | "maxtokens"
    )
}

fn usage_container_has_positive_consumption(value: &Value, inside_cost: bool) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(name, value)| {
            let normalized = normalized_usage_key(name);
            if is_nonconsumption_metadata(&normalized) {
                return false;
            }
            if is_consumption_metric(&normalized) || (inside_cost && is_cost_metric(&normalized)) {
                return json_is_positive_number(value);
            }
            let child_inside_cost = inside_cost || is_cost_container(&normalized);
            usage_container_has_positive_consumption(value, child_inside_cost)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| usage_container_has_positive_consumption(value, inside_cost)),
        _ => false,
    }
}

fn json_is_positive_number(value: &Value) -> bool {
    let Value::Number(value) = value else {
        return false;
    };
    value.as_u64().is_some_and(|value| value > 0)
        || value.as_i64().is_some_and(|value| value > 0)
        || value.as_f64().is_some_and(|value| value > 0.0)
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct JsonlReadReport {
    physical_line_count: usize,
    parsed_json_line_count: usize,
    malformed_json_line_count: usize,
    invalid_utf8_line_count: usize,
    over_line_cap_count: usize,
}

impl JsonlReadReport {
    fn complete(self) -> bool {
        self.malformed_json_line_count == 0
            && self.invalid_utf8_line_count == 0
            && self.over_line_cap_count == 0
    }
}

fn read_bounded_jsonl_lines(
    mut reader: impl BufRead,
    max_line_bytes: usize,
    mut on_value: impl FnMut(&Value),
) -> std::io::Result<JsonlReadReport> {
    let mut buf = Vec::new();
    let mut report = JsonlReadReport::default();
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
        report.physical_line_count += 1;
        if overflowed {
            report.over_line_cap_count += 1;
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
        match std::str::from_utf8(bytes) {
            Ok(line) if line.trim().is_empty() => {}
            Ok(line) => match serde_json::from_str::<Value>(line) {
                Ok(value) => {
                    report.parsed_json_line_count += 1;
                    on_value(&value);
                }
                Err(_) => report.malformed_json_line_count += 1,
            },
            Err(_) => report.invalid_utf8_line_count += 1,
        }
        if reached_eof {
            break;
        }
    }
    Ok(report)
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

fn pi_selector_from_usage_message(value: &Value) -> SelectorCapture {
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
        if let Some(timestamp) = timestamp.clone() {
            accumulator.compaction_timestamps.push(timestamp);
        }
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
            .or_else(|| prompt_text_from_array(value.pointer("/payload/text_elements")));
    }
    if string_eq_at(value, &["type"], "user_message") {
        return string_at(value, &["message"])
            .or_else(|| string_at(value, &["text"]))
            .or_else(|| prompt_text_from_array(value.get("text_elements")));
    }
    if string_eq_at(value, &["payload", "type"], "message")
        && string_eq_at(value, &["payload", "role"], "user")
    {
        return prompt_text_from_array(value.pointer("/payload/content"));
    }
    None
}

fn prompt_text_from_array(value: Option<&Value>) -> Option<String> {
    let Value::Array(items) = value? else {
        return None;
    };
    let parts = items.iter().filter_map(|item| {
        let text = match item {
            Value::String(text) => Some(text.as_str()),
            Value::Object(_) => item
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| item.get("input_text").and_then(Value::as_str)),
            _ => None,
        }?;
        let text = crate::session_attribution::prompt_without_injected_scaffolding(text);
        (!text.is_empty()).then_some(text)
    });
    normalize_title(parts.collect::<Vec<_>>().join("\n"))
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
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["created_at"]))
        .or_else(|| string_at(value, &["message", "created_at"]));
    // Current Claude transcripts write both of these shapes for one compaction.
    // Keep the raw observations here; `claude_compaction_summary` pairs records
    // within the provider's millisecond-scale emission window while preserving
    // either shape when it appears alone in an older transcript.
    let is_legacy_compaction = string_eq_at(value, &["type"], "user")
        && value.get("isCompactSummary").and_then(Value::as_bool) == Some(true);
    let is_current_compaction = string_eq_at(value, &["type"], "system")
        && string_eq_at(value, &["subtype"], "compact_boundary");
    if is_legacy_compaction {
        accumulator
            .claude_compaction_observations
            .push(ClaudeCompactionObservation {
                kind: ClaudeCompactionKind::LegacySummary,
                timestamp: timestamp.clone(),
            });
    }
    if is_current_compaction {
        accumulator
            .claude_compaction_observations
            .push(ClaudeCompactionObservation {
                kind: ClaudeCompactionKind::CurrentBoundary,
                timestamp: timestamp.clone(),
            });
    }
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
    accumulator.set_title(
        string_at(value, &["customTitle"]).and_then(claude_custom_title_display_title),
        "transcript_title",
    );
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
    if !usage_object_has_numeric_field(
        root,
        &[
            "input_tokens",
            "inputTokens",
            "output_tokens",
            "outputTokens",
            "cache_read_tokens",
            "cached_input_tokens",
            "cachedInputTokens",
            "cache_write_tokens",
            "cacheWriteTokens",
            "cache_creation_tokens",
            "cacheCreationInputTokens",
            "reasoning_output_tokens",
            "request_count",
            "requests",
        ],
    ) {
        return None;
    }
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
            accumulator.note_pi_time(pi_timestamp_field(value));
        }
        Some("session") => {
            if accumulator.source_session_id.is_none() {
                accumulator.source_session_id = string_at(value, &["id"])
                    .or_else(|| string_at(value, &["session_id"]))
                    .or_else(|| string_at(value, &["sessionId"]));
            }
            accumulator.set_workspace_hash(string_at(value, &["cwd"]));
            accumulator.note_pi_time(pi_timestamp_field(value));
        }
        Some("message") => {
            // Pi user prompts use both legacy top-level `role` and current
            // nested `message.role`. This is the only chance to capture prompt
            // text for a title fallback.
            let role = pi_message_role(value);
            if role.as_deref() == Some("user") {
                accumulator.set_first_prompt_title(pi_message_text(value));
            }
            let timestamp = pi_message_timestamp(value);
            if role.as_deref() == Some("assistant")
                && (timestamp.is_some() || !pi_message_timestamp_is_present(value))
            {
                apply_pi_usage_line(
                    value,
                    accumulator,
                    timestamp.as_deref(),
                    PiUsageRecordShape::Message,
                );
            } else if role.as_deref() == Some("assistant")
                && pi_message_usage(value).is_some_and(|usage| !usage.is_zero())
            {
                accumulator.note_dropped_usage();
            }
            accumulator.note_pi_time(timestamp);
        }
        Some("message_end") => {
            let timestamp = pi_message_end_timestamp(value);
            if timestamp.is_some() || !pi_message_timestamp_is_present(value) {
                apply_pi_usage_line(
                    value,
                    accumulator,
                    timestamp.as_deref(),
                    PiUsageRecordShape::MessageEnd,
                );
            } else if pi_message_usage(value).is_some_and(|usage| !usage.is_zero()) {
                accumulator.note_dropped_usage();
            }
            accumulator.note_pi_time(timestamp);
        }
        Some("model_change") => {
            accumulator
                .set_model(string_at(value, &["modelId"]).or_else(|| string_at(value, &["model"])));
            accumulator.note_pi_time(pi_timestamp_field(value));
        }
        _ => {}
    }
}

fn pi_message_role(value: &Value) -> Option<String> {
    string_at(value, &["message", "role"]).or_else(|| string_at(value, &["role"]))
}

fn pi_usage_event(value: &Value) -> bool {
    string_eq_at(value, &["type"], "message_end")
        || (string_eq_at(value, &["type"], "message")
            && pi_message_role(value).as_deref() == Some("assistant"))
}

fn pi_usage_dedup_key(value: &Value) -> Option<String> {
    string_at(value, &["message", "responseId"])
        .or_else(|| string_at(value, &["message", "response_id"]))
        .or_else(|| string_at(value, &["responseId"]))
        .or_else(|| string_at(value, &["response_id"]))
}

fn apply_pi_usage_line(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
    timestamp: Option<&str>,
    shape: PiUsageRecordShape,
) {
    let model = string_at(value, &["message", "model"]);
    accumulator.set_model(model.clone());
    if let Some(usage) = pi_message_usage(value) {
        let mut selector = accumulator.current_selector.clone();
        selector.merge(pi_selector_from_usage_message(value));
        let occurrence_digest =
            pi_usage_occurrence_digest(model.as_deref(), &usage, &selector, timestamp);
        let is_new_occurrence = match pi_usage_dedup_key(value) {
            Some(key) => accumulator
                .seen_pi_usage_keys
                .entry(key)
                .or_default()
                .record(shape, occurrence_digest),
            None => true,
        };
        if is_new_occurrence {
            accumulator.add_usage_with_selector(
                model, usage, selector, timestamp,
                // Pi does not emit a per-turn reasoning effort tier.
                None,
            );
        }
    }
}

fn pi_usage_occurrence_digest(
    model: Option<&str>,
    usage: &UsageTotals,
    selector: &SelectorCapture,
    timestamp: Option<&str>,
) -> String {
    let selector_context = serde_json::to_string(&selector.context).unwrap_or_default();
    sha256_hex(&[
        model.unwrap_or(""),
        &timestamp
            .and_then(pi_usage_timestamp_identity)
            .unwrap_or_default(),
        &usage.input_tokens.to_string(),
        &usage.output_tokens.to_string(),
        &usage.cache_read_tokens.to_string(),
        &usage.cache_creation_5m_tokens.to_string(),
        &usage.cache_creation_1h_tokens.to_string(),
        &usage.reasoning_output_tokens.to_string(),
        &usage.unattributed_total_tokens.to_string(),
        &usage.request_count.to_string(),
        &usage.costs.observed.to_string(),
        &usage.costs.reported.to_string(),
        &format!("{:?}", usage.costs.total),
        &format!("{:?}", usage.costs.input),
        &format!("{:?}", usage.costs.output),
        &format!("{:?}", usage.costs.cache_read),
        &format!("{:?}", usage.costs.cache_creation),
        &selector_context,
    ])
}

fn pi_message_text(value: &Value) -> Option<String> {
    string_at(value, &["content"])
        .or_else(|| string_at(value, &["text"]))
        .or_else(|| string_at(value, &["message", "content"]))
        .or_else(|| text_from_array(value.get("content")))
        .or_else(|| text_from_array(value.pointer("/message/content")))
}

fn pi_timestamp_field(value: &Value) -> Option<String> {
    pi_timestamp_value(value.get("timestamp"))
        .or_else(|| pi_timestamp_value(value.pointer("/message/timestamp")))
}

fn pi_message_timestamp(value: &Value) -> Option<String> {
    // Current and transitional Pi records may carry a later envelope write
    // time at the top level. Provider response time is the usage occurrence
    // clock and is also what historical message_end records use.
    pi_usage_record_timestamp(value)
}

fn pi_message_end_timestamp(value: &Value) -> Option<String> {
    pi_usage_record_timestamp(value)
}

fn pi_usage_record_timestamp(value: &Value) -> Option<String> {
    let provider_timestamp = value.pointer("/message/timestamp");
    if provider_timestamp.is_some() {
        // Present-but-invalid provider evidence is loss. Falling back to the
        // envelope would silently turn a malformed occurrence clock into a
        // different, often later, billable hour.
        pi_timestamp_value(provider_timestamp)
    } else {
        pi_timestamp_value(value.get("timestamp"))
    }
}

fn pi_message_timestamp_is_present(value: &Value) -> bool {
    value.get("timestamp").is_some() || value.pointer("/message/timestamp").is_some()
}

fn pi_timestamp_value(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(text) = value.as_str() {
        if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
            if (1..=9999).contains(&parsed.year()) {
                return Some(text.to_string());
            }
        }
    }
    pi_ms_timestamp(Some(value))
}

fn pi_usage_timestamp_identity(value: &str) -> Option<String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|timestamp| timestamp.unix_timestamp_nanos().to_string())
}

fn pi_timestamp_is_before(candidate: &str, current: &str) -> bool {
    match (
        OffsetDateTime::parse(candidate, &Rfc3339),
        OffsetDateTime::parse(current, &Rfc3339),
    ) {
        (Ok(candidate), Ok(current)) => candidate < current,
        (Ok(_), Err(_)) => true,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => candidate < current,
    }
}

fn pi_timestamp_is_after(candidate: &str, current: &str) -> bool {
    match (
        OffsetDateTime::parse(candidate, &Rfc3339),
        OffsetDateTime::parse(current, &Rfc3339),
    ) {
        (Ok(candidate), Ok(current)) => candidate > current,
        (Ok(_), Err(_)) => true,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => candidate > current,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiUsageRecordShape {
    Message,
    MessageEnd,
}

#[derive(Debug, Clone, Default)]
struct PiUsageDedupState {
    message: BTreeMap<String, usize>,
    message_end: BTreeMap<String, usize>,
    paired_digests: BTreeSet<String>,
}

impl PiUsageDedupState {
    /// Returns true when this record is a new billable occurrence. An exact
    /// opposite-shape occurrence consumes one unmatched digest and is the
    /// compatibility duplicate of the occurrence already counted.
    fn record(&mut self, shape: PiUsageRecordShape, digest: String) -> bool {
        let (same_shape, opposite_shape) = match shape {
            PiUsageRecordShape::Message => (&mut self.message, &mut self.message_end),
            PiUsageRecordShape::MessageEnd => (&mut self.message_end, &mut self.message),
        };
        if let Some(count) = opposite_shape.get_mut(&digest) {
            self.paired_digests.insert(digest.clone());
            *count -= 1;
            if *count == 0 {
                opposite_shape.remove(&digest);
            }
            return false;
        }
        *same_shape.entry(digest).or_default() += 1;
        true
    }

    fn has_cross_shape_conflict(&self) -> bool {
        (!self.message.is_empty() && !self.message_end.is_empty())
            || (!self.paired_digests.is_empty()
                && self
                    .message
                    .keys()
                    .chain(self.message_end.keys())
                    .any(|digest| !self.paired_digests.contains(digest)))
    }
}

fn pi_ms_timestamp(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let ms = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    }?;
    bounded_rfc3339_millis(ms)
}

fn bounded_rfc3339_millis(ms: i64) -> Option<String> {
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()?;
    // Python/Pydantic datetimes, and therefore the backend snapshot contract,
    // admit only civil years 1..=9999. `time` deliberately supports a wider
    // internal range, so validate before formatting instead of minting a
    // superficially RFC3339-looking value that can poison an upload batch.
    if !(1..=9999).contains(&timestamp.year()) {
        return None;
    }
    let utc = timestamp.to_offset(time::UtcOffset::UTC);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond(),
    ))
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

fn pi_message_usage(value: &Value) -> Option<UsageTotals> {
    let usage = value.pointer("/message/usage")?;
    if !usage_object_has_numeric_field(
        usage,
        &[
            "input",
            "output",
            "cacheRead",
            "cache_read",
            "cacheWrite",
            "cache_write",
            "cacheWrite1h",
            "cache_write_1h",
            "reasoning",
        ],
    ) {
        return None;
    }
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
    if !usage_object_has_numeric_field(
        root,
        &[
            "input_tokens",
            "inputTokens",
            "output_tokens",
            "outputTokens",
            "cache_read_input_tokens",
            "cache_read_tokens",
            "cache_creation_input_tokens",
            "reasoning_output_tokens",
        ],
    ) {
        return None;
    }
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

fn usage_object_has_numeric_field(root: &Value, fields: &[&str]) -> bool {
    root.as_object().is_some_and(|object| {
        fields
            .iter()
            .any(|field| object.get(*field).and_then(Value::as_u64).is_some())
    })
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
    scan_root: PathBuf,
    path: PathBuf,
    size_bytes: u64,
    modified_unix_seconds: u64,
    modified_unix_nanos: u64,
    source_file_fingerprint: String,
    legacy_source_file_fingerprint: String,
    legacy_config_reconciliation_required: bool,
    opened_object_identity: String,
}

#[derive(Debug, Default)]
struct ScanCensus {
    #[cfg(test)]
    discovered_file_count: usize,
    directory_entry_cap_exceeded_count: usize,
    symlink_rejected_count: usize,
    unreadable_path_count: usize,
    oversized_file_count: usize,
    disappeared_file_count: usize,
    malformed_json_line_count: usize,
    invalid_utf8_line_count: usize,
    over_line_cap_count: usize,
    recognized_usage_drop_count: usize,
    zero_snapshot_usage_evidence_count: usize,
    dropped_usage_record_count: u64,
    observed_index_keys: BTreeSet<String>,
    removed_index_keys: BTreeSet<String>,
}

#[cfg(test)]
#[derive(Debug)]
struct BoundedCandidateSelection {
    cursor: Option<String>,
    upper_bound: Option<String>,
    limit: usize,
    selected: BTreeMap<String, CandidateFile>,
    observed_max: Option<String>,
}

#[cfg(test)]
impl BoundedCandidateSelection {
    fn new(cursor: Option<String>, upper_bound: Option<String>, limit: usize) -> Self {
        // Legacy indexes carried a cursor without a frozen ceiling. Restart a
        // fresh bounded generation once rather than inheriting its starvation
        // semantics.
        let cursor = cursor.filter(|_| upper_bound.is_some());
        Self {
            cursor,
            upper_bound,
            limit,
            selected: BTreeMap::new(),
            observed_max: None,
        }
    }

    fn insert(&mut self, candidate: CandidateFile) {
        let key = local_index_key(&candidate.path);
        if self
            .observed_max
            .as_ref()
            .map_or(true, |maximum| key > *maximum)
        {
            self.observed_max = Some(key.clone());
        }
        if self.limit == 0 {
            return;
        }
        if self
            .upper_bound
            .as_ref()
            .is_some_and(|upper_bound| key > *upper_bound)
            || self.cursor.as_ref().is_some_and(|cursor| key <= *cursor)
        {
            return;
        }
        self.selected.insert(key, candidate);
        if self.selected.len() > self.limit {
            self.selected.pop_last();
        }
    }

    fn finish(
        self,
        discovered: usize,
    ) -> (Vec<CandidateFile>, bool, Option<String>, Option<String>) {
        let upper_bound = self.upper_bound.or(self.observed_max);
        let selected = self.selected.into_values().collect::<Vec<_>>();
        let next_cursor = selected
            .last()
            .map(|candidate| local_index_key(&candidate.path));
        let reached_upper_bound = next_cursor
            .as_ref()
            .zip(upper_bound.as_ref())
            .is_some_and(|(cursor, upper_bound)| cursor >= upper_bound);
        let complete = if self.limit == 0 {
            discovered == 0
        } else {
            selected.len() < self.limit || reached_upper_bound
        };
        (
            selected,
            complete,
            (!complete).then_some(next_cursor).flatten(),
            (!complete).then_some(upper_bound).flatten(),
        )
    }
}

impl CodexTitleMetadata {
    fn session_sidecar_fingerprint(&self, source_session_id: &str) -> String {
        let title = self.titles.get(source_session_id);
        let thread = self.state_threads.get(source_session_id);
        sha256_hex(&[
            "codex_session_sidecar:v1",
            source_session_id,
            title.map(|value| value.title.as_str()).unwrap_or(""),
            title.map(|value| value.source.as_str()).unwrap_or(""),
            thread
                .and_then(|value| value.title.as_deref())
                .unwrap_or(""),
            &thread
                .map(|value| value.tokens_used)
                .unwrap_or_default()
                .to_string(),
            thread
                .map(|value| if value.archived { "archived" } else { "active" })
                .unwrap_or(""),
            thread
                .and_then(|value| value.created_at.as_deref())
                .unwrap_or(""),
            thread
                .and_then(|value| value.updated_at.as_deref())
                .unwrap_or(""),
            thread
                .and_then(|value| value.model.as_deref())
                .unwrap_or(""),
        ])
    }

    fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut metadata = Self::default();
        let mut legacy_sidecar_parts = Vec::new();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }

        for codex_dir in codex_dirs {
            let config_path = codex_dir.join("config.toml");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&config_path));
            metadata.legacy_config_file_present |= config_path.is_file();

            let state_path = codex_dir.join("state_5.sqlite");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&state_path));
            let title_census = load_codex_sqlite_titles(&state_path, &mut metadata.titles);
            let state_census =
                load_codex_sqlite_state_threads(&state_path, &mut metadata.state_threads);
            if title_census.is_err() || state_census.is_err() {
                metadata.state_census_incomplete = true;
                metadata.sidecar_census_incomplete = true;
            }

            let index_path = codex_dir.join("session_index.jsonl");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&index_path));
            if load_codex_session_index_titles(&index_path, &mut metadata.titles).is_err() {
                metadata.sidecar_census_incomplete = true;
            }
        }
        metadata.legacy_sidecar_fingerprint = sha256_hex_owned(&legacy_sidecar_parts);
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
) -> Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("open Codex session index"),
    };
    let mut parsed = BTreeMap::new();
    let mut invalid_shape = false;
    let report = read_bounded_jsonl_lines(BufReader::new(file), MAX_JSONL_LINE_BYTES, |value| {
        let Some(id) = string_at(value, &["id"]) else {
            invalid_shape = true;
            return;
        };
        insert_codex_sidecar_title(
            &mut parsed,
            id,
            string_at(value, &["thread_name"])
                .or_else(|| string_at(value, &["title"]))
                .or_else(|| string_at(value, &["name"])),
            "session_index",
            true,
        );
    })
    .context("read Codex session index")?;
    if !report.complete() || invalid_shape {
        return Err(anyhow::anyhow!("Codex session index census was incomplete"));
    }
    titles.extend(parsed);
    Ok(())
}

fn load_codex_sqlite_titles(
    path: &Path,
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .context("open Codex title database")?;
    let mut statement = connection
        .prepare("SELECT id, title FROM threads WHERE title IS NOT NULL AND title != ''")
        .context("prepare Codex title census")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut loaded = Vec::new();
    for row in rows {
        loaded.push(row.context("read Codex title census row")?);
    }
    for row in loaded {
        insert_codex_sidecar_title(titles, row.0, Some(row.1), "session_index", false);
    }
    Ok(())
}

fn load_codex_sqlite_state_threads(
    path: &Path,
    state_threads: &mut BTreeMap<String, CodexStateThread>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .context("open Codex state database")?;
    let columns = sqlite_table_columns(&connection, "threads")?;
    if !columns.contains("id") || !columns.contains("tokens_used") {
        return Err(anyhow::anyhow!(
            "Codex state database is missing required thread census columns"
        ));
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
    let mut statement = connection
        .prepare(sql.as_str())
        .context("prepare Codex state thread census")?;
    let rows = statement.query_map([], |row| {
        let id: String = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let tokens_used = non_negative_i64_to_u64(row.get::<_, i64>(2)?);
        let archived = row.get::<_, i64>(3)? != 0;
        let created_at = codex_state_timestamp(row.get(6)?, row.get(4)?);
        let updated_at = codex_state_timestamp(row.get(7)?, row.get(5)?);
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
    })?;
    let mut loaded = BTreeMap::new();
    for row in rows {
        let (id, thread) = row.context("read Codex state thread census row")?;
        loaded.insert(id, thread);
    }
    for (id, thread) in loaded {
        state_threads.insert(id, thread);
    }
    Ok(())
}

fn sqlite_table_columns(connection: &Connection, table_name: &str) -> Result<BTreeSet<String>> {
    let mut statement = connection
        .prepare(format!("PRAGMA table_info({table_name})").as_str())
        .context("prepare SQLite table census")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    rows.collect::<rusqlite::Result<BTreeSet<_>>>()
        .context("read SQLite table census")
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
    bounded_rfc3339_millis(timestamp_ms)
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

/// Defensive size ceiling for a Claude Code settings file. Real settings files
/// are a few KiB; anything larger is not a config file we should be parsing.
const MAX_CLAUDE_SETTINGS_FILE_BYTES: u64 = 1024 * 1024;

/// Display-safe Claude Code runtime defaults resolved across the settings chain.
///
/// The Codex sibling is `CodexConfigDefaults`; the same rules apply. These are
/// configured defaults, not evidence a session actually ran with them.
/// `selector_context` carries the resolved value per field and
/// `selector_sources` carries the `claude_code.<scope>.<json key path>`
/// provenance of the file that won, so the UI can name the file each value came
/// from instead of implying one global config.
///
/// `reasoning_effort` comes from Claude Code's durable `effortLevel` setting,
/// which `/effort` writes into the settings file. The value is reported exactly
/// as configured; nothing is normalized and no default is invented when the key
/// is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeConfigDefaults {
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
    pub approval_policy: Option<String>,
    pub fast_mode_enabled: Option<bool>,
    pub sandbox_mode: Option<String>,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
}

/// Result of reading the Claude Code settings chain.
///
/// `NothingConfigured` and `Unreadable` are kept apart on purpose: the UI must
/// be able to say "you have not configured a default" rather than implying
/// Ottto failed to look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaudeConfigDefaultsOutcome {
    /// At least one display-safe default is configured somewhere in the chain.
    Configured(ClaudeConfigDefaults),
    /// A settings file parsed cleanly, but none of the mapped keys are set.
    NothingConfigured,
    /// No settings file in the chain could be read and parsed.
    Unreadable,
}

/// One Claude Code settings file in precedence order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeSettingsScope<'a> {
    /// `selector_sources` prefix identifying the file, e.g. `claude_code.settings`.
    pub label: &'a str,
    pub path: &'a Path,
}

/// Raw per-key capture with the scope label that supplied it. Kept separate from
/// `ClaudeConfigDefaults` so a higher-precedence file that sets only one half of
/// a derived pair (for example `sandbox.autoAllowBashIfSandboxed` without
/// `sandbox.enabled`) still wins for the key it actually sets.
#[derive(Debug, Clone, Default)]
struct ClaudeSettingsRaw {
    model: Option<(String, String)>,
    effort_level: Option<(String, String)>,
    permission_mode: Option<(String, String)>,
    fast_mode: Option<(bool, String)>,
    fast_mode_per_session_opt_in: Option<(bool, String)>,
    sandbox_enabled: Option<(bool, String)>,
    sandbox_auto_allow_bash: Option<(bool, String)>,
}

/// Resolve display-safe Claude Code defaults from the settings chain.
///
/// `scopes` must be ordered lowest precedence first; each readable file
/// overwrites the keys it sets, so the highest-precedence file wins per key.
/// Only specifically-named keys are ever read: `model`, `effortLevel`,
/// `permissions.defaultMode`, `fastMode`/`fastModePerSessionOptIn`, and
/// `sandbox.enabled`/`sandbox.autoAllowBashIfSandboxed`. `env`,
/// `permissions.allow`/`ask`/`deny`, `apiKeyHelper`, `statusLine`,
/// `sandbox.credentials`, and `sandbox.filesystem` are never read, so no path,
/// environment value, token, or permission rule can ride along. Environment
/// variables are never consulted either, so `CLAUDE_CODE_EFFORT_LEVEL` cannot
/// leak in through this path.
pub(crate) fn load_claude_settings_defaults(
    scopes: &[ClaudeSettingsScope<'_>],
) -> ClaudeConfigDefaultsOutcome {
    let mut raw = ClaudeSettingsRaw::default();
    let mut any_readable = false;
    for scope in scopes {
        let Some(document) = load_claude_settings_document(scope.path) else {
            continue;
        };
        any_readable = true;
        apply_claude_settings_scope(&mut raw, scope.label, &document);
    }
    if !any_readable {
        return ClaudeConfigDefaultsOutcome::Unreadable;
    }

    let mut defaults = ClaudeConfigDefaults::default();
    let insert = |defaults: &mut ClaudeConfigDefaults, field: &str, value: String, source: &str| {
        defaults.selector_context.insert(field.to_string(), value);
        defaults
            .selector_sources
            .insert(field.to_string(), source.to_string());
    };

    if let Some((model, source)) = raw.model.clone() {
        insert(&mut defaults, "model", model.clone(), &source);
        defaults.model = Some(model);
    }
    // Reported exactly as configured. `low`/`medium`/`high`/`xhigh` persist
    // across sessions; `max` is session-only unless the environment sets it, but
    // if the settings file says `max` then that is what the file says, and the
    // Configuration tab's contract is to show the config file. Normalizing or
    // dropping a value here would misreport the customer's own config.
    if let Some((effort, source)) = raw.effort_level.clone() {
        insert(&mut defaults, "reasoning_effort", effort.clone(), &source);
        defaults.reasoning_effort = Some(effort);
    }
    if let Some((mode, source)) = raw.permission_mode.clone() {
        insert(&mut defaults, "approval_policy", mode.clone(), &source);
        defaults.approval_policy = Some(mode);
    }
    // `fastModePerSessionOptIn` means Fast never persists across sessions, so
    // the durable default is off regardless of a stored `fastMode` flag. This
    // mirrors how Codex's `fast_default_opt_out` overrides `[features].fast_mode`.
    let fast_mode = match (&raw.fast_mode_per_session_opt_in, &raw.fast_mode) {
        (Some((true, source)), _) => Some((false, source.clone())),
        (_, Some((enabled, source))) => Some((*enabled, source.clone())),
        _ => None,
    };
    if let Some((enabled, source)) = fast_mode {
        insert(
            &mut defaults,
            "fast_mode_enabled",
            enabled.to_string(),
            &source,
        );
        defaults.fast_mode_enabled = Some(enabled);
    }
    // `autoAllowBashIfSandboxed` only means something once the sandbox is on,
    // so an unset `sandbox.enabled` stays quiet rather than guessing a mode.
    let sandbox_mode = match &raw.sandbox_enabled {
        Some((false, source)) => Some(("disabled", source.clone())),
        Some((true, source)) => match &raw.sandbox_auto_allow_bash {
            Some((false, auto_allow_source)) => {
                Some(("regular_permissions", auto_allow_source.clone()))
            }
            // Auto-allow is Claude Code's default once the sandbox is enabled.
            _ => Some(("auto_allow", source.clone())),
        },
        None => None,
    };
    if let Some((mode, source)) = sandbox_mode {
        insert(&mut defaults, "sandbox_mode", mode.to_string(), &source);
        defaults.sandbox_mode = Some(mode.to_string());
    }

    if defaults.selector_context.is_empty() {
        return ClaudeConfigDefaultsOutcome::NothingConfigured;
    }
    ClaudeConfigDefaultsOutcome::Configured(defaults)
}

/// Read one Claude Code settings file into JSON.
///
/// Read line-by-line to satisfy the streaming guard (no whole-file reads in this
/// module); settings files are small, so the accumulated string is fine.
fn load_claude_settings_document(path: &Path) -> Option<Value> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_SETTINGS_FILE_BYTES {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut raw = String::new();
    for line in BufReader::new(file).lines() {
        let line = line.ok()?;
        raw.push_str(line.as_str());
        raw.push('\n');
    }
    serde_json::from_str::<Value>(&raw).ok()
}

fn apply_claude_settings_scope(raw: &mut ClaudeSettingsRaw, label: &str, document: &Value) {
    if let Some(model) = document
        .get("model")
        .and_then(Value::as_str)
        .and_then(display_safe_config_scalar)
    {
        raw.model = Some((model, format!("{label}.model")));
    }
    if let Some(effort) = document
        .get("effortLevel")
        .and_then(Value::as_str)
        .and_then(display_safe_config_scalar)
    {
        raw.effort_level = Some((effort, format!("{label}.effortLevel")));
    }
    if let Some(mode) = document
        .get("permissions")
        .and_then(|permissions| permissions.get("defaultMode"))
        .and_then(Value::as_str)
        .and_then(claude_permission_mode_default)
    {
        raw.permission_mode = Some((mode, format!("{label}.permissions.defaultMode")));
    }
    if let Some(fast_mode) = document.get("fastMode").and_then(Value::as_bool) {
        raw.fast_mode = Some((fast_mode, format!("{label}.fastMode")));
    }
    if let Some(opt_in) = document
        .get("fastModePerSessionOptIn")
        .and_then(Value::as_bool)
    {
        raw.fast_mode_per_session_opt_in =
            Some((opt_in, format!("{label}.fastModePerSessionOptIn")));
    }
    if let Some(sandbox) = document.get("sandbox") {
        if let Some(enabled) = sandbox.get("enabled").and_then(Value::as_bool) {
            raw.sandbox_enabled = Some((enabled, format!("{label}.sandbox.enabled")));
        }
        if let Some(auto_allow) = sandbox
            .get("autoAllowBashIfSandboxed")
            .and_then(Value::as_bool)
        {
            raw.sandbox_auto_allow_bash = Some((
                auto_allow,
                format!("{label}.sandbox.autoAllowBashIfSandboxed"),
            ));
        }
    }
}

/// Canonical display value for `permissions.defaultMode`.
///
/// `bypassPermissions` is a local safety posture, never a cost-relevant default,
/// so it is dropped rather than uploaded. Unknown values are dropped too: a
/// future mode name is not something we should forward blind.
fn claude_permission_mode_default(value: &str) -> Option<String> {
    match value.trim() {
        // `manual` is the CLI alias for the canonical `default` config value.
        "default" | "manual" => Some("default".to_string()),
        "acceptEdits" => Some("acceptEdits".to_string()),
        "plan" => Some("plan".to_string()),
        "auto" => Some("auto".to_string()),
        "dontAsk" => Some("dontAsk".to_string()),
        _ => None,
    }
}

/// Accept only short, scalar, display-safe config text.
///
/// Anything path-like, URL-like, quoted, whitespace-bearing, or long is dropped
/// instead of forwarded, so free-form settings text can never leak a path, an
/// environment value, or a credential through a config-defaults field. The
/// backend-facing `redacted_for_backend` guard is the second line of defence.
fn display_safe_config_scalar(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'))
    {
        return None;
    }
    Some(trimmed.to_string())
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

// Pre-semantic-sync indexes embedded one source-wide sidecar stat digest in
// every file fingerprint. Retain this derivation only to prove whether a legacy
// entry can be migrated without parsing; new entries never use it.
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

fn scan_traversal_context_fingerprint(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &ScanIndex,
    backfill_window_days: u64,
) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, b"ottto:snapshot-bounded-traversal:v1");
    update_length_prefixed(&mut digest, source.api_slug().as_bytes());
    // A persisted queue contains paths already consumed under the scanner that
    // created it. Resuming that queue after an upgrade without binding these
    // derivations can skip the consumed prefix under the new identity and
    // publish a mixed old/new terminal census. Parser-only releases remain
    // resumable; reviewed scan/open identity changes start a fresh bounded
    // traversal so every pre-existing candidate is reconsidered.
    update_length_prefixed(&mut digest, source.scan_identity_version().as_bytes());
    update_length_prefixed(&mut digest, LOCAL_SCAN_INDEX_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, OPENED_OBJECT_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, &backfill_window_days.to_be_bytes());
    update_length_prefixed(
        &mut digest,
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none")
            .as_bytes(),
    );
    update_length_prefixed(
        &mut digest,
        index
            .historical_replay_generation
            .as_deref()
            .unwrap_or("none")
            .as_bytes(),
    );
    for root in roots {
        update_length_prefixed(&mut digest, root.to_string_lossy().as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn rfc3339_unix_seconds(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()?
        .unix_timestamp()
        .try_into()
        .ok()
}

fn unhealthy_scan_retry_delay_seconds(attempt: u8) -> u64 {
    let exponent = u32::from(attempt.saturating_sub(1)).min(6);
    UNHEALTHY_SCAN_RETRY_BASE_SECONDS
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
}

fn ensure_bounded_traversal(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    backfill_window_days: u64,
) {
    let context_fingerprint =
        scan_traversal_context_fingerprint(source, roots, index, backfill_window_days);
    let prior_traversal_context_matches = index
        .traversal
        .as_ref()
        .is_some_and(|traversal| traversal.context_fingerprint == context_fingerprint);
    let retry_attempt = if let Some(traversal) = index
        .traversal
        .as_ref()
        .filter(|traversal| traversal.context_fingerprint == context_fingerprint)
    {
        let terminal_unhealthy = traversal.pending_directories.is_empty()
            && traversal.pending_candidates.is_empty()
            && traversal.counts.has_errors();
        let retry_due = match rfc3339_unix_seconds(collected_at) {
            Some(now) => traversal
                .unhealthy_retry_not_before_unix_seconds
                .is_some_and(|deadline| {
                    now >= deadline
                        || deadline > now.saturating_add(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
                }),
            // A malformed or backwards observation clock must not turn the
            // durable red witness into a permanent fence. Retrying remains
            // bounded by the per-tick traversal limits.
            None => true,
        };
        if !terminal_unhealthy || !retry_due {
            return;
        }
        traversal.unhealthy_retry_attempt
    } else {
        0
    };

    let mut census = ScanCensus::default();
    let resolved_roots = roots
        .iter()
        .map(|root| {
            let problems_before = census
                .unreadable_path_count
                .saturating_add(census.disappeared_file_count);
            let resolved = resolve_configured_scan_root(root, &mut census);
            let problems_after = census
                .unreadable_path_count
                .saturating_add(census.disappeared_file_count);
            (root, resolved, problems_after > problems_before)
        })
        .collect::<Vec<_>>();
    let currently_resolved = resolved_roots
        .iter()
        .filter_map(|(_, resolved, _)| resolved.as_ref())
        .collect::<Vec<_>>();
    let missing_roots = resolved_roots
        .iter()
        .filter(|(_, resolved, _)| resolved.is_none())
        .map(|(root, _, _)| *root)
        .collect::<Vec<_>>();
    let missing_root_reported_problem = resolved_roots
        .iter()
        .any(|(_, resolved, reported_problem)| resolved.is_none() && *reported_problem);
    // Upgrade compatibility: indexes written before the durable root witness
    // existed can still prove that a now-missing root was previously observed.
    // Direct roots are inferred by lexical containment below. A vanished
    // configured symlink has no recoverable canonical target, so retain the
    // exact prior index paths until a future resolved root covers them. This
    // avoids falsely promoting every unrelated optional root to required.
    if prior_traversal_context_matches {
        index.legacy_unresolved_root_file_witnesses.retain(|key| {
            index.files.contains_key(key)
                && !currently_resolved
                    .iter()
                    .any(|root| Path::new(key).starts_with(root))
        });
    } else {
        // A changed root set is an explicit new census scope, not evidence that
        // one of its absent optional roots owns every old out-of-scope path.
        index.legacy_unresolved_root_file_witnesses.clear();
    }
    if prior_traversal_context_matches && !missing_roots.is_empty() {
        index.legacy_unresolved_root_file_witnesses.extend(
            index
                .files
                .keys()
                .filter(|key| {
                    !currently_resolved
                        .iter()
                        .any(|root| Path::new(key).starts_with(root))
                        && !missing_roots
                            .iter()
                            .any(|root| Path::new(key).starts_with(root))
                })
                .cloned(),
        );
    }
    let mut scan_roots = Vec::new();
    let mut pending_directories = VecDeque::new();
    for (root, resolved, resolver_reported_problem) in resolved_roots {
        let root_key = local_index_key(root);
        if let Some(scan_root) = resolved {
            index.known_configured_scan_roots.insert(root_key);
            scan_roots.push(scan_root.clone());
            pending_directories.push_back(ScanTraversalPath {
                scan_root: scan_root.clone(),
                path: scan_root,
                census_member: true,
                watcher_hint: false,
            });
            continue;
        }
        let inferred_from_old_index = index
            .files
            .keys()
            .any(|key| Path::new(key).starts_with(root));
        if inferred_from_old_index {
            index.known_configured_scan_roots.insert(root_key.clone());
        }
        if index.known_configured_scan_roots.contains(&root_key) && !resolver_reported_problem {
            census.disappeared_file_count += 1;
        }
    }
    if !index.legacy_unresolved_root_file_witnesses.is_empty() && !missing_root_reported_problem {
        census.disappeared_file_count += 1;
    }
    let counts = ScanTraversalCounts {
        directory_entry_cap_exceeded_count: census.directory_entry_cap_exceeded_count,
        symlink_rejected_count: census.symlink_rejected_count,
        unreadable_path_count: census.unreadable_path_count,
        oversized_file_count: census.oversized_file_count,
        disappeared_file_count: census.disappeared_file_count,
        malformed_json_line_count: census.malformed_json_line_count,
        invalid_utf8_line_count: census.invalid_utf8_line_count,
        over_line_cap_count: census.over_line_cap_count,
        recognized_usage_drop_count: census.recognized_usage_drop_count,
        ..ScanTraversalCounts::default()
    };
    index.traversal = Some(ScanTraversalCheckpoint {
        context_fingerprint,
        census_window_end: collected_at.to_string(),
        scan_roots,
        pending_directories,
        pending_candidates: VecDeque::new(),
        observed_index_keys: BTreeSet::new(),
        reconciliation_upper_bound: index.files.keys().next_back().cloned(),
        reconciliation_after: None,
        reconciliation_started: false,
        watcher_hint_seen: false,
        unhealthy_retry_attempt: retry_attempt,
        unhealthy_retry_not_before_unix_seconds: None,
        counts,
    });
}

fn enqueue_watcher_hints(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) {
    // Ordinary, bounded watcher paths are exact path hints. They join the
    // durable traversal census and are revalidated by the same no-follow open
    // and post-read identity checks as directory-discovered candidates. Only
    // overflow/backend loss makes the watcher evidence incomplete and forces a
    // following clean generation.
    traversal.watcher_hint_seen |= watcher_overflowed;
    let mut pending = traversal
        .pending_candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<BTreeSet<_>>();
    for path in hinted_paths.iter().take(MAX_BACKFILL_FILES_PER_SOURCE) {
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl")
            || (source == SnapshotSource::ClaudeCode
                && claude_transcript_excluded_from_snapshots(path))
            || !pending.insert(path.clone())
        {
            continue;
        }
        let Some(scan_root) = traversal
            .scan_roots
            .iter()
            .find(|root| path.starts_with(root))
            .cloned()
        else {
            continue;
        };
        // FIFO keeps an actively rewritten path from repeatedly jumping ahead
        // of an older remove/rename hint in a small bounded page.
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root,
            path: path.clone(),
            census_member: true,
            watcher_hint: true,
        });
    }
}

fn advance_bounded_directory_traversal(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    backfill_window_days: u64,
) {
    advance_bounded_directory_traversal_with_budget(
        source,
        traversal,
        backfill_window_days,
        MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK,
    );
}

fn advance_bounded_directory_traversal_with_budget(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    backfill_window_days: u64,
    max_entries: usize,
) {
    // Eligibility belongs to the frozen census generation, not to whichever
    // later tick happens to reach a directory. Otherwise a multi-page walk can
    // silently age boundary files out while still publishing the earlier
    // `census_window_end` as its agreement scope.
    let census_unix_seconds = rfc3339_unix_seconds(&traversal.census_window_end);
    let mut remaining = max_entries;
    while remaining > 0 {
        let Some(directory) = traversal.pending_directories.pop_front() else {
            break;
        };
        let metadata = match fs::symlink_metadata(&directory.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                traversal.counts.disappeared_file_count += 1;
                continue;
            }
            Err(_) => {
                traversal.counts.unreadable_path_count += 1;
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            traversal.counts.symlink_rejected_count += 1;
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let entries = match fs::read_dir(&directory.path) {
            Ok(entries) => entries,
            Err(_) => {
                traversal.counts.unreadable_path_count += 1;
                continue;
            }
        };
        // Read only the budget still available in this tick, plus one entry as
        // a bounded proof that the directory must resume. If the full per-tick
        // budget was available, that same extra entry proves the directory is
        // too wide to scan truthfully and turns the generation red.
        let mut entries = entries.take(remaining + 1).collect::<Vec<_>>();
        if entries.len() > remaining {
            if remaining == max_entries {
                traversal.counts.directory_entry_cap_exceeded_count += 1;
            } else {
                traversal.pending_directories.push_front(directory);
            }
            break;
        }
        remaining -= entries.len();
        entries.sort_by(|left, right| {
            left.as_ref()
                .map(|entry| entry.file_name())
                .ok()
                .cmp(&right.as_ref().map(|entry| entry.file_name()).ok())
        });
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    traversal.counts.unreadable_path_count += 1;
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    traversal.counts.unreadable_path_count += 1;
                    continue;
                }
            };
            if file_type.is_symlink() {
                traversal.counts.symlink_rejected_count += 1;
                continue;
            }
            if file_type.is_dir() {
                traversal.pending_directories.push_back(ScanTraversalPath {
                    scan_root: directory.scan_root.clone(),
                    path,
                    census_member: true,
                    watcher_hint: false,
                });
                continue;
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("jsonl")
            {
                continue;
            }
            if source == SnapshotSource::ClaudeCode
                && claude_transcript_excluded_from_snapshots(&path)
            {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    traversal.counts.disappeared_file_count += 1;
                    continue;
                }
                Err(_) => {
                    traversal.counts.unreadable_path_count += 1;
                    continue;
                }
            };
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            if census_unix_seconds.is_some_and(|now| {
                !is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
            }) {
                continue;
            }
            traversal.counts.discovered_file_count += 1;
            traversal.observed_index_keys.insert(local_index_key(&path));
            if metadata.len() > max_jsonl_file_bytes(source) {
                traversal.counts.oversized_file_count += 1;
                continue;
            }
            if let Some(existing) = traversal
                .pending_candidates
                .iter_mut()
                .find(|candidate| candidate.path == path)
            {
                existing.census_member = true;
            } else {
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: directory.scan_root.clone(),
                    path,
                    census_member: true,
                    watcher_hint: false,
                });
            }
        }
    }
}

fn candidate_from_traversal_path(
    source: SnapshotSource,
    pending: ScanTraversalPath,
    census: &mut ScanCensus,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
) -> Option<CandidateFile> {
    let metadata = match fs::symlink_metadata(&pending.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if pending.watcher_hint {
                // Remove/rename events legitimately name an object that no
                // longer exists. They are not lossy census failures; remove an
                // earlier observation so terminal reconciliation can delete
                // the stale entry exactly.
                census
                    .removed_index_keys
                    .insert(local_index_key(&pending.path));
            } else if pending.census_member {
                census.disappeared_file_count += 1;
            }
            return None;
        }
        Err(_) => {
            if pending.census_member {
                census.unreadable_path_count += 1;
            }
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        if pending.census_member && metadata.file_type().is_symlink() {
            census.symlink_rejected_count += 1;
        }
        return None;
    }
    if metadata.len() > max_jsonl_file_bytes(source) {
        if pending.census_member {
            census.oversized_file_count += 1;
        }
        return None;
    }
    let modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(unix_seconds)
        .unwrap_or_default();
    if census_unix_seconds
        .is_some_and(|now| !is_recent_enough_at(modified_unix_seconds, now, backfill_window_days))
    {
        // Watcher hints must not widen the configured activity window. The
        // same revalidation also handles an ordinary candidate whose mtime was
        // restored behind the cutoff after directory discovery.
        if pending.census_member {
            census
                .removed_index_keys
                .insert(local_index_key(&pending.path));
        }
        return None;
    }
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(unix_nanos)
        .unwrap_or_else(|| modified_unix_seconds.saturating_mul(1_000_000_000));
    if pending.census_member {
        census
            .observed_index_keys
            .insert(local_index_key(&pending.path));
    }
    Some(CandidateFile {
        scan_root: pending.scan_root,
        source_file_fingerprint: String::new(),
        path: pending.path,
        size_bytes: metadata.len(),
        modified_unix_seconds,
        modified_unix_nanos,
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    })
}

fn reconcile_missing_index_entries_bounded(index: &mut ScanIndex) -> bool {
    reconcile_missing_index_entries_with_limit(index, MAX_BACKFILL_FILES_PER_SOURCE)
}

fn reconcile_missing_index_entries_with_limit(index: &mut ScanIndex, limit: usize) -> bool {
    let Some(snapshot) = index.traversal.as_ref() else {
        return false;
    };
    let Some(upper_bound) = snapshot.reconciliation_upper_bound.clone() else {
        return true;
    };
    let after = snapshot.reconciliation_after.clone();
    let lower_bound = after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
    let page = index
        .files
        .range((lower_bound, std::ops::Bound::Included(upper_bound.clone())))
        .take(limit)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    if page.is_empty() {
        return true;
    }
    for key in &page {
        let observed = index
            .traversal
            .as_ref()
            .is_some_and(|traversal| traversal.observed_index_keys.contains(key));
        if !observed {
            index.files.remove(key);
            index.confirmed_empty_files.remove(key);
            index.file_snapshot_fingerprints.remove(key);
        }
    }
    let done = page.last() == Some(&upper_bound) || page.len() < limit;
    if let Some(traversal) = index.traversal.as_mut() {
        traversal.reconciliation_started = true;
        traversal.reconciliation_after = page.last().cloned();
    }
    done
}

#[cfg(test)]
fn collect_recent_jsonl_files(
    source: SnapshotSource,
    scan_root: &Path,
    root: &Path,
    selection: &mut BoundedCandidateSelection,
    census: &mut ScanCensus,
    backfill_window_days: u64,
) {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            census.unreadable_path_count += 1;
            return;
        }
    };
    if root_metadata.file_type().is_symlink() {
        census.symlink_rejected_count += 1;
        return;
    }
    if !root_metadata.is_dir() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => {
            census.unreadable_path_count += 1;
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        if file_type.is_symlink() {
            census.symlink_rejected_count += 1;
            continue;
        }
        if file_type.is_dir() {
            collect_recent_jsonl_files(
                source,
                scan_root,
                &path,
                selection,
                census,
                backfill_window_days,
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        // Claude's Workflow-tool journal is bookkeeping, never a session. Drop
        // it before it can be fingerprinted, indexed, or parsed.
        if source == SnapshotSource::ClaudeCode && claude_transcript_excluded_from_snapshots(&path)
        {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                census.disappeared_file_count += 1;
                continue;
            }
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap_or_default();
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .unwrap_or_else(|| modified_unix_seconds.saturating_mul(1_000_000_000));
        if !is_recent_enough(modified_unix_seconds, backfill_window_days) {
            continue;
        }
        census.discovered_file_count += 1;
        census.observed_index_keys.insert(local_index_key(&path));
        // Skip pathologically large transcripts before they ever reach the
        // parser. metadata.len() is already read for fingerprinting, so this is
        // free; an oversized file is dropped from the candidate set rather than
        // opened, keeping the scan's memory bounded without aborting it.
        if metadata.len() > max_jsonl_file_bytes(source) {
            census.oversized_file_count += 1;
            continue;
        }
        selection.insert(CandidateFile {
            scan_root: scan_root.to_path_buf(),
            source_file_fingerprint: String::new(),
            path,
            size_bytes: metadata.len(),
            modified_unix_seconds,
            modified_unix_nanos,
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
        });
    }
}

#[cfg(test)]
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

fn opened_candidate_is_within_frozen_window(
    candidate: &CandidateFile,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
) -> bool {
    census_unix_seconds.map_or(true, |now| {
        is_recent_enough_at(candidate.modified_unix_seconds, now, backfill_window_days)
    })
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

/// Resolve one operator-configured root before discovery. A configured root
/// may itself be a symlink (for example a relocated home/support directory),
/// but every descendant remains subject to the component-wise `O_NOFOLLOW`
/// open below. Canonicalizing once also prevents the discovered path and the
/// later root-relative open from disagreeing about which root was trusted.
fn resolve_configured_scan_root(root: &Path, census: &mut ScanCensus) -> Option<PathBuf> {
    let configured = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            census.unreadable_path_count += 1;
            return None;
        }
    };
    if configured.is_dir() && !configured.file_type().is_symlink() {
        return Some(root.to_path_buf());
    }
    if !configured.file_type().is_symlink() {
        return None;
    }
    let resolved = match fs::canonicalize(root) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            census.disappeared_file_count += 1;
            return None;
        }
        Err(_) => {
            census.unreadable_path_count += 1;
            return None;
        }
    };
    match fs::symlink_metadata(&resolved) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Some(resolved),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            census.disappeared_file_count += 1;
            None
        }
        Err(_) => {
            census.unreadable_path_count += 1;
            None
        }
    }
}

/// Open the exact transcript object without following a final-component
/// symlink, capture its stable object identity and a bounded content witness,
/// then rewind it for the parser. Discovery metadata is never trusted as the
/// parse identity: a replacement between enumeration and open is reparsed.
fn open_candidate_file(
    source: SnapshotSource,
    candidate: &mut CandidateFile,
) -> std::io::Result<File> {
    let mut file = open_candidate_beneath_root(candidate)?;
    candidate.opened_object_identity = opened_object_identity(source, &mut file)?;
    let metadata = file.metadata()?;
    let modified = metadata.modified().ok();
    candidate.size_bytes = metadata.len();
    candidate.modified_unix_seconds = modified.and_then(unix_seconds).unwrap_or_default();
    candidate.modified_unix_nanos = modified.and_then(unix_nanos).unwrap_or_else(|| {
        candidate
            .modified_unix_seconds
            .saturating_mul(1_000_000_000)
    });

    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(unix)]
fn open_candidate_beneath_root(candidate: &CandidateFile) -> std::io::Result<File> {
    let relative = candidate
        .path
        .strip_prefix(&candidate.scan_root)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "snapshot candidate escaped configured root",
            )
        })?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "snapshot candidate path is not root-relative",
        ));
    }

    let mut root_options = fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = root_options.open(&candidate.scan_root)?;
    for (position, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            unreachable!("components validated above")
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "snapshot candidate contains a NUL byte",
            )
        })?;
        let is_final = position + 1 == components.len();
        let flags = if is_final {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        if is_final {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!("non-empty component list returns its final object")
}

#[cfg(not(unix))]
fn open_candidate_beneath_root(candidate: &CandidateFile) -> std::io::Result<File> {
    let relative = candidate
        .path
        .strip_prefix(&candidate.scan_root)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "snapshot candidate escaped configured root",
            )
        })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "snapshot candidate path is not root-relative",
        ));
    }
    fs::OpenOptions::new().read(true).open(&candidate.path)
}

fn opened_object_identity(source: SnapshotSource, file: &mut File) -> std::io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot candidate is not a regular file",
        ));
    }
    if metadata.len() > max_jsonl_file_bytes(source) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot candidate exceeds source file cap",
        ));
    }
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, OPENED_OBJECT_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, &metadata.len().to_be_bytes());
    #[cfg(unix)]
    {
        update_length_prefixed(&mut digest, &metadata.dev().to_be_bytes());
        update_length_prefixed(&mut digest, &metadata.ino().to_be_bytes());
        // ctime is an opened-object mutation witness, not business time. It
        // catches an in-place middle rewrite even when size and mtime are
        // deliberately restored and the bounded first/last samples are
        // unchanged. Hash both signed fields byte-for-byte for nanosecond
        // precision on macOS/Linux.
        update_length_prefixed(&mut digest, &metadata.ctime().to_be_bytes());
        update_length_prefixed(&mut digest, &metadata.ctime_nsec().to_be_bytes());
    }
    let mut sample = vec![0_u8; FILE_CONTENT_SAMPLE_BYTES];
    let first_len = file.read(&mut sample)?;
    update_length_prefixed(&mut digest, &sample[..first_len]);
    if metadata.len() > FILE_CONTENT_SAMPLE_BYTES as u64 {
        file.seek(SeekFrom::End(-(FILE_CONTENT_SAMPLE_BYTES as i64)))?;
        let last_len = file.read(&mut sample)?;
        update_length_prefixed(&mut digest, &sample[..last_len]);
    }
    let identity = format!("{:x}", digest.finalize());
    file.seek(SeekFrom::Start(0))?;
    Ok(identity)
}

fn unix_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn unix_nanos(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateDecision {
    Skip,
    Migrate,
    ReconcileLegacy,
    Parse,
}

struct CheckpointLock {
    file: File,
}

impl CheckpointLock {
    fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create checkpoint directory {}", parent.display()))?;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .context("open local snapshot checkpoint lock")?;
        #[cfg(unix)]
        {
            let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if status != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("local snapshot checkpoint is owned by another daemon");
            }
        }
        Ok(Self { file })
    }
}

impl Drop for CheckpointLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn sync_checkpoint_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync checkpoint directory {}", parent.display()))
}

fn unique_checkpoint_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

fn valid_snapshot_activity(value: &Option<String>) -> bool {
    match value.as_deref() {
        Some(timestamp) => OffsetDateTime::parse(timestamp, &Rfc3339).is_ok(),
        None => true,
    }
}

fn quarantine_invalid_scan_index(path: &Path) -> Result<ScanIndex> {
    // The index is only a local incremental-scan optimization. A crash or
    // corrupt semantic-clock witness must not permanently block collection,
    // but never overwrite the unreadable witness in place.
    let quarantine_path = unique_checkpoint_sibling(path, "corrupt");
    fs::rename(path, &quarantine_path).context("quarantine invalid local snapshot scan index")?;
    sync_checkpoint_parent(path)?;
    eprintln!("local snapshot scan index was invalid and quarantined; rebuilding");
    Ok(ScanIndex::default())
}

impl ScanIndex {
    pub fn activate_upload_context(&mut self, fingerprint: String) {
        self.active_upload_context_fingerprint = Some(fingerprint);
    }

    pub fn mark_bounded_sweep_unsettled(&mut self) {
        self.bounded_sweep_had_unsettled_upload = true;
    }

    pub fn prepare_historical_replay(&mut self, generation: String) {
        if self.historical_replay_generation.as_ref() == Some(&generation) {
            return;
        }
        self.historical_replay_generation = Some(generation);
        self.upload_context_fingerprint = None;
        self.files.clear();
        self.codex_state_only_snapshot_fingerprints.clear();
        self.resume_after_path = None;
        self.resume_upper_bound_path = None;
        self.resume_census_window_end = None;
        self.bounded_sweep_had_unsettled_upload = false;
        self.traversal = None;
        self.confirmed_empty_files.clear();
        self.file_snapshot_fingerprints.clear();
        self.snapshot_activity_at.clear();
    }

    fn activate_quarantine_witness(&mut self, source: SnapshotSource) {
        self.active_quarantine_witness = Some(snapshot_quarantine_witness(source));
    }

    fn quarantine_requires_retry(&self, fingerprint: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        self.quarantined_snapshot_fingerprints
            .get(fingerprint)
            .zip(self.active_quarantine_witness.as_ref())
            .is_some_and(|(persisted, active)| {
                &persisted.witness != active || persisted.retry_after_unix_seconds <= now
            })
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let _lock = CheckpointLock::acquire(path)?;
        let file =
            File::open(path).with_context(|| format!("open scan index {}", path.display()))?;
        match serde_json::from_reader::<_, Self>(file) {
            Ok(index)
                if index.schema_version == SCAN_INDEX_SCHEMA_VERSION
                    && index
                        .snapshot_activity_at
                        .values()
                        .all(valid_snapshot_activity)
                    && index
                        .quarantined_snapshot_fingerprints
                        .values()
                        .all(snapshot_quarantine_deadline_is_bounded) =>
            {
                Ok(index)
            }
            Ok(index) if index.schema_version == SCAN_INDEX_SCHEMA_VERSION => {
                quarantine_invalid_scan_index(path)
            }
            Ok(_) => Err(anyhow::anyhow!(
                "unsupported local snapshot scan index schema"
            )),
            Err(error) if !error.is_io() => quarantine_invalid_scan_index(path),
            Err(error) => {
                Err(error).with_context(|| format!("parse scan index {}", path.display()))
            }
        }
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create scan index directory {}", parent.display()))?;
        }
        let _lock = CheckpointLock::acquire(path)?;
        if path.exists() {
            let current: Self = serde_json::from_reader(
                File::open(path).context("open current local snapshot scan index")?,
            )
            .context("parse current local snapshot scan index for compare-and-swap")?;
            if current.schema_version != SCAN_INDEX_SCHEMA_VERSION
                || current.generation != self.generation
            {
                return Err(anyhow::anyhow!(
                    "local snapshot scan index changed concurrently"
                ));
            }
        } else if self.generation != 0 {
            return Err(anyhow::anyhow!(
                "local snapshot scan index disappeared concurrently"
            ));
        }
        let previous_generation = self.generation;
        self.schema_version = SCAN_INDEX_SCHEMA_VERSION;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("local snapshot scan index generation overflow"))?;
        // Never truncate the live index in place. The flock serializes new
        // daemons; the v2-only path isolates this state from older daemons.
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file = File::create(&temp_path)
            .with_context(|| format!("create scan index temp {}", temp_path.display()))?;
        let result = (|| -> Result<()> {
            serde_json::to_writer_pretty(&mut file, &self)
                .with_context(|| format!("write scan index temp {}", temp_path.display()))?;
            file.sync_all()
                .with_context(|| format!("sync scan index temp {}", temp_path.display()))?;
            fs::rename(&temp_path, path)
                .with_context(|| format!("replace scan index {}", path.display()))?;
            sync_checkpoint_parent(path)
        })();
        if result.is_err() {
            self.generation = previous_generation;
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    /// The scan-index manifest for `source`: how many entities this machine
    /// believes the server holds, and one hash that summarises which.
    ///
    /// This is the only independent witness the server has that its own entity
    /// set matches the machine's before the multiplexed sync cycle exists: it
    /// can recompute the same fold over the fingerprints it stored for this
    /// (user, machine, source) and compare. It is also the denominator a
    /// backfill-progress reading needs, because "how many entities exist
    /// locally" is not derivable from anything the server already receives.
    ///
    /// Grain, stated precisely because a consumer cannot infer it: one entity
    /// per final snapshot fingerprint, including every entity when one indexed
    /// transcript produces several snapshots, plus each Codex state-only
    /// entity. The separate per-file group fingerprint is only an incremental
    /// no-op witness and never substitutes for this exact entity set.
    ///
    /// Scope is the exact half-open semantic activity window `[start, end)`.
    /// Membership uses the same producer-side activity clock as accepted-log
    /// `occurred_at`, never local path or file mtime.
    ///
    /// No local path, session id, title, or byte offset participates: the fold
    /// is over semantic fingerprints only, which are already on the wire.
    #[cfg(test)]
    pub fn manifest(&self, source: SnapshotSource, _window_days: u64) -> SnapshotSourceManifest {
        let mut index = self.clone();
        let fingerprints = index
            .file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .chain(
                index
                    .files
                    .values()
                    .filter_map(|entry| entry.last_snapshot_fingerprint.as_ref()),
            )
            .chain(index.codex_state_only_snapshot_fingerprints.values())
            .cloned()
            .collect::<BTreeSet<_>>();
        for fingerprint in fingerprints {
            index
                .snapshot_activity_at
                .entry(fingerprint)
                .or_insert_with(|| Some("2050-01-01T00:00:00Z".to_string()));
        }
        index
            .manifest_for_window(source, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z")
            .expect("static test manifest window is valid")
    }

    pub fn manifest_for_window(
        &self,
        source: SnapshotSource,
        window_start: &str,
        window_end: &str,
    ) -> Result<SnapshotSourceManifest> {
        let window_start_at = OffsetDateTime::parse(window_start, &Rfc3339)
            .context("parse snapshot manifest window start")?;
        let window_end_at = OffsetDateTime::parse(window_end, &Rfc3339)
            .context("parse snapshot manifest window end")?;
        if window_start_at >= window_end_at {
            return Err(anyhow::anyhow!(
                "snapshot manifest window must be non-empty and increasing"
            ));
        }
        let all_fingerprints = self.current_snapshot_fingerprints();
        let fingerprints = all_fingerprints
            .iter()
            .map(String::as_str)
            .filter(|fingerprint| {
                !self
                    .quarantined_snapshot_fingerprints
                    .contains_key(*fingerprint)
            })
            .filter(|fingerprint| {
                self.snapshot_activity_at
                    .get(*fingerprint)
                    .and_then(|activity| activity.as_deref())
                    .and_then(|activity| OffsetDateTime::parse(activity, &Rfc3339).ok())
                    .is_some_and(|activity| window_start_at <= activity && activity < window_end_at)
            })
            .collect::<BTreeSet<_>>();
        let mut digest = Sha256::new();
        update_length_prefixed(&mut digest, SNAPSHOT_MANIFEST_CONTRACT_VERSION.as_bytes());
        update_length_prefixed(&mut digest, SNAPSHOT_MANIFEST_SCOPE.as_bytes());
        update_length_prefixed(&mut digest, source.api_slug().as_bytes());
        for fingerprint in &fingerprints {
            update_length_prefixed(&mut digest, fingerprint.as_bytes());
        }
        if !all_fingerprints
            .iter()
            .filter(|fingerprint| {
                !self
                    .quarantined_snapshot_fingerprints
                    .contains_key(*fingerprint)
            })
            .all(|fingerprint| {
                self.snapshot_activity_at
                    .get(fingerprint)
                    .is_some_and(valid_snapshot_activity)
            })
        {
            return Err(anyhow::anyhow!(
                "snapshot manifest semantic activity witness is incomplete"
            ));
        }
        Ok(SnapshotSourceManifest {
            contract_version: SNAPSHOT_MANIFEST_CONTRACT_VERSION,
            scope: SNAPSHOT_MANIFEST_SCOPE,
            source: source.api_slug().to_string(),
            window_start: window_start.to_string(),
            window_end: window_end.to_string(),
            entity_count: fingerprints.len() as u64,
            rolling_hash: format!("{:x}", digest.finalize()),
        })
    }

    pub(crate) fn current_snapshot_fingerprints(&self) -> BTreeSet<String> {
        let exact_file_fingerprints = self
            .file_snapshot_fingerprints
            .values()
            .flat_map(|values| values.iter().cloned());
        let legacy_file_fingerprints = self
            .files
            .iter()
            .filter(|(key, _)| !self.file_snapshot_fingerprints.contains_key(*key))
            .filter_map(|(_, entry)| entry.last_snapshot_fingerprint.clone());
        exact_file_fingerprints
            .chain(legacy_file_fingerprints)
            .chain(
                self.codex_state_only_snapshot_fingerprints
                    .values()
                    .cloned(),
            )
            .collect()
    }

    /// The subset of this scan's index that is safe to commit when the upload
    /// did not finish.
    ///
    /// Committing the whole index after a partial upload would drop every entity
    /// the server never received: the next scan skips an unchanged transcript, so
    /// its snapshot would never be re-derived. Committing nothing is the current
    /// behaviour and is just as wrong in the other direction — a shed request
    /// today means the entire cycle replays, forever, every five minutes.
    ///
    /// An entry is safe when the server demonstrably holds its content:
    ///
    /// * it produced no snapshot at all (nothing to lose), or
    /// * its snapshot was accepted in this pass, or
    /// * its fingerprint is unchanged from the committed index, which is what
    ///   "semantic no-op" means — the server already has that exact content.
    ///
    /// Anything else keeps its previously committed entry, so the next scan
    /// re-parses it and re-uploads. `previous` is the index as loaded from disk,
    /// before this scan mutated it.
    pub fn committable_subset(
        &self,
        previous: &ScanIndex,
        accepted: &BTreeSet<String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) -> ScanIndex {
        let settled = |fingerprint: &str| {
            accepted.contains(fingerprint) || quarantined.contains_key(fingerprint)
        };
        let safe = |key: &String, fingerprint: Option<&str>| {
            if self.confirmed_empty_files.contains(key) {
                // A newly discovered empty file has no remote entity to lose.
                // A file that PREVIOUSLY produced an entity is different: a
                // shed/partial pass has not acknowledged removal of that old
                // server entity, so retain the prior checkpoint and retry the
                // complete generation instead of publishing false agreement.
                let previous_had_entity = previous
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|fingerprints| !fingerprints.is_empty())
                    || previous
                        .files
                        .get(key)
                        .and_then(|entry| entry.last_snapshot_fingerprint.as_ref())
                        .is_some();
                return !previous_had_entity;
            }
            if let Some(exact) = self.file_snapshot_fingerprints.get(key) {
                return exact.iter().all(|fingerprint| settled(fingerprint));
            }
            match fingerprint {
                None => true,
                Some(fingerprint) => {
                    settled(fingerprint)
                        || previous
                            .files
                            .get(key)
                            .and_then(|entry| entry.last_snapshot_fingerprint.as_deref())
                            == Some(fingerprint)
                }
            }
        };
        let mut files = BTreeMap::new();
        let mut safe_keys = BTreeSet::new();
        for (key, entry) in &self.files {
            if safe(key, entry.last_snapshot_fingerprint.as_deref()) {
                files.insert(key.clone(), entry.clone());
                safe_keys.insert(key.clone());
            } else if let Some(committed) = previous.files.get(key) {
                files.insert(key.clone(), committed.clone());
            }
        }
        // A complete census may prune vanished/aged paths from `self`, but a
        // partial upload must never make that deletion durable. Only the final
        // all-accepted save may publish pruning.
        for (key, entry) in &previous.files {
            files.entry(key.clone()).or_insert_with(|| entry.clone());
        }
        let mut codex_state_only_snapshot_fingerprints = BTreeMap::new();
        for (session_id, fingerprint) in &self.codex_state_only_snapshot_fingerprints {
            let committed = previous
                .codex_state_only_snapshot_fingerprints
                .get(session_id);
            if settled(fingerprint) || committed == Some(fingerprint) {
                codex_state_only_snapshot_fingerprints
                    .insert(session_id.clone(), fingerprint.clone());
            } else if let Some(committed) = committed {
                codex_state_only_snapshot_fingerprints
                    .insert(session_id.clone(), committed.clone());
            }
        }
        // A partial upload cannot make an absent state-only entity authoritative
        // any more than it can publish a vanished transcript. No request in
        // this pass settled deletion of the old server entity, so preserve it
        // until a fully completed census can commit the absence.
        for (session_id, fingerprint) in &previous.codex_state_only_snapshot_fingerprints {
            codex_state_only_snapshot_fingerprints
                .entry(session_id.clone())
                .or_insert_with(|| fingerprint.clone());
        }
        let mut confirmed_empty_files = previous.confirmed_empty_files.clone();
        let mut file_snapshot_fingerprints = previous.file_snapshot_fingerprints.clone();
        for key in &safe_keys {
            if self.confirmed_empty_files.contains(key) {
                confirmed_empty_files.insert(key.clone());
            } else {
                confirmed_empty_files.remove(key);
            }
            match self.file_snapshot_fingerprints.get(key) {
                Some(fingerprints) => {
                    file_snapshot_fingerprints.insert(key.clone(), fingerprints.clone());
                }
                None => {
                    file_snapshot_fingerprints.remove(key);
                }
            }
        }
        let committable_fingerprints = file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .chain(codex_state_only_snapshot_fingerprints.values())
            .collect::<BTreeSet<_>>();
        let mut retained_quarantine = quarantined.clone();
        // If an old quarantine was retried under a newer contract but this
        // pass stopped before settlement, preserve the old witness. Its
        // mismatch is the durable instruction to retry again next cycle.
        for (fingerprint, witness) in &previous.quarantined_snapshot_fingerprints {
            if committable_fingerprints.contains(fingerprint)
                && !accepted.contains(fingerprint)
                && !quarantined.contains_key(fingerprint)
            {
                retained_quarantine.insert(fingerprint.clone(), witness.clone());
            }
        }
        let mut snapshot_activity_at = BTreeMap::new();
        for fingerprint in committable_fingerprints {
            if let Some(activity_at) = self
                .snapshot_activity_at
                .get(fingerprint)
                .or_else(|| previous.snapshot_activity_at.get(fingerprint))
            {
                snapshot_activity_at.insert(fingerprint.clone(), activity_at.clone());
            }
        }
        let mut result = ScanIndex {
            schema_version: SCAN_INDEX_SCHEMA_VERSION,
            generation: previous.generation,
            upload_context_fingerprint: previous.upload_context_fingerprint.clone(),
            files,
            known_configured_scan_roots: self.known_configured_scan_roots.clone(),
            legacy_unresolved_root_file_witnesses: self
                .legacy_unresolved_root_file_witnesses
                .clone(),
            codex_state_only_snapshot_fingerprints,
            claude_desktop_title_files: self.claude_desktop_title_files.clone(),
            claude_desktop_store_cursor: self.claude_desktop_store_cursor.clone(),
            claude_desktop_store_upper_bound: self.claude_desktop_store_upper_bound.clone(),
            claude_desktop_store_sweep_had_errors: self.claude_desktop_store_sweep_had_errors,
            claude_desktop_store_retry_attempt: self.claude_desktop_store_retry_attempt,
            claude_desktop_store_retry_not_before_unix_seconds: self
                .claude_desktop_store_retry_not_before_unix_seconds,
            resume_after_path: self.resume_after_path.clone(),
            resume_upper_bound_path: self.resume_upper_bound_path.clone(),
            resume_census_window_end: self.resume_census_window_end.clone(),
            bounded_sweep_had_unsettled_upload: self.bounded_sweep_had_unsettled_upload,
            traversal: self.traversal.clone(),
            historical_replay_generation: self.historical_replay_generation.clone(),
            confirmed_empty_files,
            file_snapshot_fingerprints,
            snapshot_activity_at,
            quarantined_snapshot_fingerprints: retained_quarantine.clone(),
            active_quarantine_witness: self.active_quarantine_witness.clone(),
            active_upload_context_fingerprint: self.active_upload_context_fingerprint.clone(),
        };
        result.retain_quarantined_fingerprints(&retained_quarantine);
        result
    }

    pub fn retain_quarantined_fingerprints(
        &mut self,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) {
        let current = self
            .file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .chain(self.codex_state_only_snapshot_fingerprints.values())
            .collect::<BTreeSet<_>>();
        self.quarantined_snapshot_fingerprints = quarantined
            .iter()
            .filter(|(fingerprint, _)| current.contains(*fingerprint))
            .map(|(fingerprint, witness)| (fingerprint.clone(), witness.clone()))
            .collect();
    }

    fn remove_file_entry(&mut self, key: &str) {
        self.files.remove(key);
        self.confirmed_empty_files.remove(key);
        self.file_snapshot_fingerprints.remove(key);
    }

    fn candidate_decision(&self, candidate: &CandidateFile) -> CandidateDecision {
        let key = local_index_key(&candidate.path);
        let Some(entry) = self.files.get(&key) else {
            return CandidateDecision::Parse;
        };
        if self.upload_context_fingerprint != self.active_upload_context_fingerprint {
            return CandidateDecision::Parse;
        }
        if self
            .file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|fingerprints| {
                fingerprints.iter().any(|fingerprint| {
                    !self
                        .snapshot_activity_at
                        .get(fingerprint)
                        .is_some_and(valid_snapshot_activity)
                        || self.quarantine_requires_retry(fingerprint)
                })
            })
        {
            return CandidateDecision::Parse;
        }
        let transcript_changed = entry.size_bytes != candidate.size_bytes
            || entry.modified_unix_seconds != candidate.modified_unix_seconds
            || entry
                .modified_unix_nanos
                .is_some_and(|value| value != candidate.modified_unix_nanos);
        if transcript_changed {
            return CandidateDecision::Parse;
        }
        if entry.last_snapshot_fingerprint.is_none() && !self.confirmed_empty_files.contains(&key) {
            return CandidateDecision::Parse;
        }
        if !self.file_snapshot_fingerprints.contains_key(&key)
            && entry
                .last_snapshot_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| {
                    !self
                        .snapshot_activity_at
                        .get(fingerprint)
                        .is_some_and(valid_snapshot_activity)
                })
        {
            return CandidateDecision::Parse;
        }
        if entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION) {
            return if entry.source_file_fingerprint == candidate.legacy_source_file_fingerprint {
                if candidate.legacy_config_reconciliation_required {
                    CandidateDecision::ReconcileLegacy
                } else {
                    CandidateDecision::Migrate
                }
            } else {
                // The legacy source-wide sidecar identity changed while this
                // entry was not observed. We cannot prove which session was
                // affected from the irreversible old digest, so correctness
                // requires a one-time parse instead of silently absorbing it.
                CandidateDecision::Parse
            };
        }
        if entry.source_file_fingerprint != candidate.source_file_fingerprint {
            CandidateDecision::Parse
        } else {
            CandidateDecision::Skip
        }
    }

    fn last_snapshot_fingerprint(&self, candidate: &CandidateFile) -> Option<String> {
        self.files
            .get(&local_index_key(&candidate.path))
            .and_then(|entry| entry.last_snapshot_fingerprint.clone())
    }

    fn migrate(&mut self, candidate: CandidateFile) {
        let key = local_index_key(&candidate.path);
        let last_snapshot_fingerprint = self
            .files
            .get(&key)
            .and_then(|entry| entry.last_snapshot_fingerprint.clone());
        self.files.insert(
            key,
            ScanIndexEntry {
                size_bytes: candidate.size_bytes,
                modified_unix_seconds: candidate.modified_unix_seconds,
                modified_unix_nanos: Some(candidate.modified_unix_nanos),
                source_file_fingerprint: candidate.source_file_fingerprint,
                last_snapshot_fingerprint,
                scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
            },
        );
    }

    fn record(
        &mut self,
        candidate: CandidateFile,
        last_snapshot_fingerprint: Option<String>,
        parse_outcome: ScanParseOutcome,
    ) {
        let key = local_index_key(&candidate.path);
        self.files.insert(
            key.clone(),
            ScanIndexEntry {
                size_bytes: candidate.size_bytes,
                modified_unix_seconds: candidate.modified_unix_seconds,
                modified_unix_nanos: Some(candidate.modified_unix_nanos),
                source_file_fingerprint: candidate.source_file_fingerprint,
                last_snapshot_fingerprint,
                scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
            },
        );
        match parse_outcome {
            ScanParseOutcome::ConfirmedEmpty | ScanParseOutcome::PolicySuppressed => {
                self.confirmed_empty_files.insert(key);
            }
            ScanParseOutcome::Snapshot | ScanParseOutcome::Unknown => {
                self.confirmed_empty_files.remove(&key);
            }
        }
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

#[cfg(test)]
fn scan_file_fingerprint_with_context(
    path: &Path,
    size_bytes: u64,
    modified_unix_nanos: u64,
    scan_identity_version: &str,
    session_sidecar_fingerprint: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_nanos.to_string(),
        scan_identity_version,
        session_sidecar_fingerprint,
    ])
}

fn scan_file_fingerprint_with_opened_identity(
    path: &Path,
    size_bytes: u64,
    modified_unix_nanos: u64,
    scan_identity_version: &str,
    session_sidecar_fingerprint: &str,
    opened_object_identity: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_nanos.to_string(),
        scan_identity_version,
        session_sidecar_fingerprint,
        opened_object_identity,
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

fn first_prompt_display_title(source: SnapshotSource, value: String) -> Option<String> {
    let raw = value.trim();
    if raw.is_empty()
        || contains_blocked_prompt_fragment(raw)
        || looks_like_resume_boilerplate(&raw.to_ascii_lowercase())
    {
        return None;
    }
    if source == SnapshotSource::Codex {
        if let Some(role_title) = agent_role_prompt_display_title(raw) {
            return Some(role_title);
        }
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

fn agent_role_prompt_display_title(raw: &str) -> Option<String> {
    let first_line = raw.lines().find_map(|line| {
        let trimmed = line.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })?;
    let lowered = first_line.to_ascii_lowercase();
    let mut role = lowered.strip_prefix("you are ")?;
    role = role
        .strip_prefix("the ")
        .or_else(|| role.strip_prefix("an "))
        .or_else(|| role.strip_prefix("a "))
        .unwrap_or(role);

    let role_end = [" agent", " worker", " orchestrator"]
        .into_iter()
        .filter_map(|suffix| {
            role.match_indices(suffix).find_map(|(index, _)| {
                let end = index + suffix.len();
                let boundary = role[end..].chars().next();
                (boundary.is_none()
                    || boundary.is_some_and(|character| {
                        character.is_whitespace()
                            || matches!(character, '.' | ',' | ':' | ';' | '(' | ')' | '—' | '–')
                    }))
                .then_some(end)
            })
        })
        .min()?;
    let role = role[..role_end].trim();
    let word_count = role.split_whitespace().count();
    if !(2..=8).contains(&word_count)
        || role.chars().count() > 64
        || role.contains(['/', '\\', '<', '>', '{', '}', '@'])
    {
        return None;
    }

    let mut words = role
        .split_whitespace()
        .map(|word| match word {
            "ai" | "api" | "ci" | "mcp" | "pr" | "qa" | "ui" => word.to_ascii_uppercase(),
            _ => word.to_string(),
        })
        .collect::<Vec<_>>();
    let first = words.first_mut()?;
    if !matches!(
        first.as_str(),
        "AI" | "API" | "CI" | "MCP" | "PR" | "QA" | "UI"
    ) {
        let mut chars = first.chars();
        let initial = chars.next()?.to_uppercase().collect::<String>();
        *first = initial + chars.as_str();
    }
    normalize_display_title(words.join(" "), "first_prompt")
}

fn claude_custom_title_display_title(value: String) -> Option<String> {
    let normalized = normalize_title(value)?;
    let lowered = normalized.to_ascii_lowercase();
    if let Some(rest) = lowered.strip_prefix("pr-fixer-") {
        let pr_number = rest.split('-').next()?;
        if !pr_number.is_empty() && pr_number.chars().all(|ch| ch.is_ascii_digit()) {
            return Some(format!("Fix PR #{pr_number}"));
        }
    }
    normalize_display_title(normalized, "custom_title")
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

fn looks_like_resume_boilerplate(lowered: &str) -> bool {
    let stripped = lowered
        .strip_prefix("continue ")
        .map(str::trim_start)
        .and_then(|value| value.strip_prefix("the ").or(Some(value)))
        .map(|value| value.trim_start_matches(['"', '\'']));
    stripped.is_some_and(|value| value.starts_with("same "))
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

/// Where a Claude Code subagent transcript sits inside its parent session's
/// on-disk tree.
///
/// Claude Code writes exactly four JSONL layouts under `~/.claude/projects`:
///
/// 1. `<projectDir>/<sessionId>.jsonl` — the human top-level session.
/// 2. `<projectDir>/<sessionId>/subagents/agent-<agentId>.jsonl` — Task tool.
/// 3. `<projectDir>/<sessionId>/subagents/workflows/<wfId>/agent-<agentId>.jsonl`
///    — Workflow tool (dynamic multi-agent orchestration).
/// 4. `<projectDir>/<sessionId>/subagents/workflows/<wfId>/journal.jsonl` — the
///    Workflow tool's bookkeeping log (no usage rows; excluded from snapshots,
///    see `claude_transcript_excluded_from_snapshots`).
///
/// Every line of layouts 2-4 is stamped with the *parent's* `sessionId`, so the
/// path -- not the file contents -- is the authority on which session a
/// transcript belongs to. `root_session_id` is therefore read from the directory
/// whose child is `subagents`; the in-file `sessionId` is corroboration only and
/// is deliberately never used to build the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeSubagentIdentity {
    /// Directory name of the top-level session that owns this `subagents` tree.
    /// Always the raw human-session UUID, at any nesting depth.
    root_session_id: String,
    /// The transcript's file stem, e.g. `agent-a4d1585d310070d0f`. Stems are
    /// unique within one parent session across all of its subagent directories.
    file_stem: String,
    /// The `wf_*` directory name when the transcript sits under a `workflows/`
    /// directory inside the `subagents` tree (layout 3), else `None`.
    workflow_ref: Option<String>,
}

impl ClaudeSubagentIdentity {
    /// The re-keyed `source_session_id`, `<parentSessionId>_<fileStem>`.
    ///
    /// The id must stay URL-path-safe: the backend uses `source_session_id`
    /// verbatim as its `Session.session_id`, which rides in
    /// `/sessions/{session_id}/...` routes, so the join uses `_` (never `/`).
    /// The scheme is unchanged from v13 so ids already minted for layout 2 keep
    /// resolving to the same backend session.
    fn source_session_id(&self) -> String {
        format!("{}_{}", self.root_session_id, self.file_stem)
    }

    /// The bare provider agent id (`agent-` prefix stripped), when the stem
    /// carries one.
    fn agent_ref(&self) -> Option<&str> {
        self.file_stem
            .strip_prefix("agent-")
            .filter(|value| !value.is_empty())
    }
}

/// Resolve a Claude Code transcript path to its subagent identity.
///
/// Fires when ANY ancestor directory (not merely the immediate parent) is named
/// `subagents`, which is what separates this from the v13 behaviour: layouts 3
/// and 4 nest one or two directories deeper and were previously left keyed on
/// their parent's `sessionId`. Ordinary top-level transcripts return `None` and
/// keep their raw in-file `sessionId`.
pub(crate) fn claude_subagent_identity(path: &Path) -> Option<ClaudeSubagentIdentity> {
    let file_stem = path.file_stem()?.to_str()?;
    if file_stem.is_empty() {
        return None;
    }
    let directories: Vec<&str> = path
        .parent()?
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect();
    // Nearest enclosing `subagents` directory wins, so a project directory that
    // happens to contain the word higher up cannot capture the transcript.
    let marker = directories
        .iter()
        .rposition(|value| *value == "subagents")?;
    let root_session_id = *directories.get(marker.checked_sub(1)?)?;
    if root_session_id.is_empty() {
        return None;
    }
    // Segments BETWEEN `subagents` and the file. Layout 2 has none; layout 3/4
    // has `workflows/<wfId>`.
    let nested = &directories[marker + 1..];
    let workflow_ref = nested
        .iter()
        .position(|value| *value == "workflows")
        .and_then(|index| nested.get(index + 1))
        .filter(|value| !value.is_empty())
        .map(|value| (*value).to_string());
    Some(ClaudeSubagentIdentity {
        root_session_id: root_session_id.to_string(),
        file_stem: file_stem.to_string(),
        workflow_ref,
    })
}

/// Convenience wrapper: the re-keyed `source_session_id` for a subagent
/// transcript, or `None` for an ordinary top-level transcript. The production
/// path uses `claude_subagent_identity` directly because it also needs the
/// workflow and agent references.
#[cfg(test)]
fn claude_subagent_source_session_id(path: &Path) -> Option<String> {
    claude_subagent_identity(path).map(|identity| identity.source_session_id())
}

/// Claude transcripts that must never produce a snapshot.
///
/// The Workflow tool's `journal.jsonl` (layout 4) is bookkeeping, not a
/// transcript: it has no `message.usage` rows and no `sessionId` field at all,
/// and its `journal` file stem is NOT unique within a parent session -- a
/// session with two workflow directories has two `journal.jsonl` files that
/// would both re-key to `<parentSessionId>_journal` and fight over one backend
/// session. Excluding it at collection time keeps that id from ever existing.
fn claude_transcript_excluded_from_snapshots(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some("journal.jsonl")
        && claude_subagent_identity(path).is_some()
}

/// Upper bound for a subagent `*.meta.json` sidecar read. The observed files are
/// a few hundred bytes; the cap only stops a pathological local file from being
/// slurped into the per-user daemon.
const MAX_CLAUDE_AGENT_META_BYTES: u64 = 64 * 1024;

/// Provider-written sidecar describing one Claude Code subagent, read from
/// `<transcript>.meta.json` (e.g. `agent-a4d15....meta.json`).
///
/// Only the fields that are safe to forward are retained. `worktreePath` and
/// `worktreeBranch` are deliberately NOT read: they carry local filesystem
/// paths. `description` (the Task tool's 3-8 word task summary) IS read as
/// display-title material — an operator decision (2026-07-27) that partially
/// revisits the original exclusion: short agent titles are wanted, full prompt
/// bodies and paths stay out, and `safe_claude_agent_display_label` enforces
/// that shape (char allowlist + hard truncation) so a pathological description
/// cannot smuggle prompt content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeAgentMeta {
    /// `agentType`, e.g. `workflow-subagent`, `Explore`, `general-purpose`.
    agent_kind: Option<String>,
    /// `spawnDepth` rendered as a string (1 for a directly spawned agent).
    spawn_depth: Option<String>,
    /// `parentAgentId` when this agent was spawned by another agent rather than
    /// by the top-level session.
    parent_agent_id: Option<String>,
    /// `description` — the short title-shaped Task summary (e.g. "Fix flaky
    /// backend tests"). Sanitized display-label material, never a prompt body.
    description: Option<String>,
}

/// Best-effort read of a subagent's `*.meta.json` sidecar.
///
/// Every failure mode (absent file, oversized file, unreadable bytes, invalid
/// JSON, unexpected value types, unsafe characters) degrades to an absent field.
/// A malformed sidecar must never drop or fail the session it describes.
fn read_claude_agent_meta(transcript_path: &Path) -> ClaudeAgentMeta {
    let meta_path = transcript_path.with_extension("meta.json");
    let Ok(metadata) = fs::metadata(&meta_path) else {
        return ClaudeAgentMeta::default();
    };
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_AGENT_META_BYTES {
        return ClaudeAgentMeta::default();
    }
    let Ok(file) = File::open(&meta_path) else {
        return ClaudeAgentMeta::default();
    };
    // Bounded read, never a slurp: the same streaming discipline the transcript
    // reader uses, so a sidecar that grew pathologically cannot be materialized
    // whole in the per-user daemon.
    let mut raw = Vec::new();
    if file
        .take(MAX_CLAUDE_AGENT_META_BYTES)
        .read_to_end(&mut raw)
        .is_err()
    {
        return ClaudeAgentMeta::default();
    }
    let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
        return ClaudeAgentMeta::default();
    };
    ClaudeAgentMeta {
        agent_kind: string_at(&value, &["agentType"]).and_then(safe_attribution_token),
        spawn_depth: value
            .get("spawnDepth")
            .and_then(Value::as_u64)
            .map(|depth| depth.to_string()),
        parent_agent_id: string_at(&value, &["parentAgentId"]).and_then(safe_attribution_token),
        description: string_at(&value, &["description"]).and_then(safe_claude_agent_display_label),
    }
}

/// Hard cap for a subagent display label (workflow `label` or Task
/// `description`). Longer values are truncated, not rejected: the leading
/// characters of a title-shaped value are still a useful title, and the cap is
/// what keeps a pathological description from smuggling prompt content.
const MAX_CLAUDE_AGENT_LABEL_CHARS: usize = 80;

/// Sanitize a provider-supplied subagent display label.
///
/// Unlike `safe_attribution_token` (identifiers only), a label is short human
/// text: whitespace is collapsed, then the value must pass a conservative
/// printable-ASCII allowlist — anything with control characters, non-ASCII, or
/// separator-smuggling backslashes is dropped rather than repaired. Values are
/// truncated to `MAX_CLAUDE_AGENT_LABEL_CHARS`, and anything that still looks
/// like a path escapes the allowlist via the same forbidden fragments the
/// attribution tokens use.
fn safe_claude_agent_display_label(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '.'
                    | ','
                    | ':'
                    | ';'
                    | '_'
                    | '-'
                    | '+'
                    | '#'
                    | '('
                    | ')'
                    | '\''
                    | '&'
                    | '/'
                    | '?'
                    | '!'
            )
    }) {
        return None;
    }
    let truncated: String = normalized
        .chars()
        .take(MAX_CLAUDE_AGENT_LABEL_CHARS)
        .collect();
    let lowered = truncated.to_ascii_lowercase();
    if ATTRIBUTION_TOKEN_FORBIDDEN_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
        || lowered.contains("/users/")
        || lowered.contains("/home/")
    {
        return None;
    }
    Some(truncated)
}

/// Upper bound for a Workflow run-manifest read (`workflows/wf_*.json`).
/// Observed manifests are a few hundred KB (they carry per-agent progress rows
/// including result previews); the cap only stops a pathological file from
/// being slurped into the per-user daemon.
const MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// `<sessionDir>/workflows/<wfId>.json` — the Workflow tool's run manifest,
/// sibling of the `subagents/` tree that holds the agent transcripts. Resolved
/// from the transcript path by walking up to the nearest `subagents` ancestor
/// (the same anchor `claude_subagent_identity` keys on).
fn claude_workflow_manifest_path(transcript_path: &Path, workflow_ref: &str) -> Option<PathBuf> {
    let mut directory = transcript_path.parent();
    while let Some(current) = directory {
        if current.file_name().and_then(|value| value.to_str()) == Some("subagents") {
            return Some(
                current
                    .parent()?
                    .join("workflows")
                    .join(format!("{workflow_ref}.json")),
            );
        }
        directory = current.parent();
    }
    None
}

/// The human-readable label a Workflow run assigned to one of its agents (e.g.
/// `probe:data-model`, `verify:daemon-scan-claim`).
///
/// Labels are durably recorded in the run manifest's `workflowProgress` array
/// as `{type:"workflow_agent", agentId, label, ...}` rows — the agent's own
/// `meta.json` sidecar does NOT carry them. Only `label` is extracted; the
/// prompt/result previews that ride the same rows are never read past the
/// serde parse. Best-effort: every failure mode degrades to `None`.
fn claude_workflow_agent_label(
    transcript_path: &Path,
    identity: &ClaudeSubagentIdentity,
) -> Option<String> {
    let workflow_ref = identity.workflow_ref.as_deref()?;
    let agent_ref = identity.agent_ref()?;
    let manifest_path = claude_workflow_manifest_path(transcript_path, workflow_ref)?;
    let metadata = fs::metadata(&manifest_path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES {
        return None;
    }
    let file = File::open(&manifest_path).ok()?;
    let mut raw = Vec::new();
    file.take(MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    let value = serde_json::from_slice::<Value>(&raw).ok()?;
    let progress = value.get("workflowProgress")?.as_array()?;
    progress
        .iter()
        .find(|entry| {
            string_eq_at(entry, &["type"], "workflow_agent")
                && string_eq_at(entry, &["agentId"], agent_ref)
        })
        .and_then(|entry| string_at(entry, &["label"]))
        .and_then(safe_claude_agent_display_label)
}

/// `size:mtime_nanos` stat token for a naming-material sidecar, or empty when
/// the file is absent/unreadable. Stat-only on purpose: this runs during
/// candidate enumeration for every subagent transcript on every scan cycle, so
/// it must never read file contents.
fn file_stat_token(path: &Path) -> String {
    fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| {
            let nanos = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            format!("{}:{nanos}", metadata.len())
        })
        .unwrap_or_default()
}

/// Scan-fingerprint contribution of a subagent transcript's naming material:
/// the `meta.json` sidecar (Task `description` / `agentType`) and the Workflow
/// run manifest (agent `label`). Changing either re-selects the transcript even
/// when the transcript bytes are unchanged.
fn claude_subagent_sidecar_fingerprint(
    transcript_path: &Path,
    identity: &ClaudeSubagentIdentity,
) -> String {
    let meta_stat = file_stat_token(&transcript_path.with_extension("meta.json"));
    let manifest_stat = identity
        .workflow_ref
        .as_deref()
        .and_then(|workflow_ref| claude_workflow_manifest_path(transcript_path, workflow_ref))
        .map(|manifest_path| file_stat_token(&manifest_path))
        .unwrap_or_default();
    sha256_hex(&["claude_subagent_sidecar:v1", &meta_stat, &manifest_stat])
}

/// Path-like fragments the backend fact validator rejects outright. One
/// rejected fact fails the WHOLE upload batch, so a provider-supplied token that
/// would trip the remote check is dropped locally instead. Kept in sync with
/// `_ARTIFACT_FORBIDDEN_FRAGMENTS` in the backend snapshot schema; the
/// separator-bearing entries there are unreachable through the character
/// allowlist below.
const ATTRIBUTION_TOKEN_FORBIDDEN_FRAGMENTS: [&str; 4] =
    [".codex", ".claude", "workspace_path", "transcript_path"];

/// Conservative allowlist for provider-supplied identifiers that become
/// attribution fact values. Anything outside `[A-Za-z0-9._:-]`, or longer than
/// 64 characters, is dropped rather than sanitized: a value that does not look
/// like a provider identifier is not one, and no local path can survive this.
fn safe_attribution_token(value: String) -> Option<String> {
    if value.is_empty() || value.len() > 64 {
        return None;
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
    }) {
        return None;
    }
    let lowered = value.to_ascii_lowercase();
    ATTRIBUTION_TOKEN_FORBIDDEN_FRAGMENTS
        .iter()
        .all(|fragment| !lowered.contains(fragment))
        .then_some(value)
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

/// Feed `bytes` into `digest` behind a 4-byte big-endian length.
///
/// The length prefix is the whole point: a bare concatenation of variable-length
/// fields lets two different field splits produce identical bytes, so the fold
/// would not actually pin the set it claims to summarise.
fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u32).to_be_bytes());
    digest.update(bytes);
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

    fn terminal_unhealthy_traversal(context_fingerprint: String) -> ScanTraversalCheckpoint {
        ScanTraversalCheckpoint {
            context_fingerprint,
            census_window_end: "2026-07-31T00:00:00Z".to_string(),
            scan_roots: Vec::new(),
            pending_directories: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            observed_index_keys: BTreeSet::new(),
            reconciliation_upper_bound: None,
            reconciliation_after: None,
            reconciliation_started: false,
            watcher_hint_seen: false,
            unhealthy_retry_attempt: 1,
            unhealthy_retry_not_before_unix_seconds: Some(0),
            counts: ScanTraversalCounts {
                disappeared_file_count: 1,
                ..ScanTraversalCounts::default()
            },
        }
    }

    #[test]
    fn scan_index_recovers_from_truncated_json_and_replaces_it_atomically() {
        let root = temp_dir("scan-index-recovery");
        let path = root.join("codex-scan-index.json");
        fs::write(&path, r#"{"files":{"partial""#).expect("write truncated index");

        let recovered = ScanIndex::load(&path).expect("truncated index should self-heal");
        assert!(recovered.files.is_empty());

        let mut replacement = ScanIndex {
            files: BTreeMap::from([(
                "content-free-key".to_string(),
                ScanIndexEntry {
                    size_bytes: 42,
                    modified_unix_seconds: 1_700_000_000,
                    modified_unix_nanos: Some(1_700_000_000_000_000_000),
                    source_file_fingerprint: "sha256:test".to_string(),
                    last_snapshot_fingerprint: Some("sha256:snapshot".to_string()),
                    scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
                },
            )]),
            ..ScanIndex::default()
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
    fn scan_index_quarantines_syntactically_valid_corrupt_activity_witness() {
        let root = temp_dir("scan-index-corrupt-activity");
        let path = root.join("codex-scan-index-v2.json");
        let fingerprint = "a".repeat(64);
        let mut corrupt = ScanIndex {
            file_snapshot_fingerprints: BTreeMap::from([(
                "content-free-key".to_string(),
                BTreeSet::from([fingerprint.clone()]),
            )]),
            snapshot_activity_at: BTreeMap::from([(
                fingerprint,
                Some("syntactically-json-but-not-rfc3339".to_string()),
            )]),
            ..ScanIndex::default()
        };
        corrupt.save(&path).expect("persist corrupt semantic clock");

        let recovered = ScanIndex::load(&path).expect("corrupt semantic clock should self-heal");
        assert!(recovered.file_snapshot_fingerprints.is_empty());
        assert!(recovered.snapshot_activity_at.is_empty());
        assert!(!path.exists());
        assert_eq!(
            fs::read_dir(&root)
                .expect("read quarantine directory")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
                .count(),
            1
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn quarantine_deadline_never_becomes_authoritative_after_clock_rollback() {
        let original_now = 1_000_000;
        let record = SnapshotQuarantineRecord {
            witness: snapshot_quarantine_witness(SnapshotSource::Codex),
            retry_after_unix_seconds: original_now
                + SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(2),
        };
        assert!(snapshot_quarantine_deadline_is_bounded_at(
            &record,
            original_now
        ));
        assert!(!snapshot_quarantine_deadline_is_bounded_at(
            &record,
            original_now - 1
        ));
        let far_future = SnapshotQuarantineRecord {
            retry_after_unix_seconds: u64::MAX,
            ..record
        };
        assert!(!snapshot_quarantine_deadline_is_bounded_at(
            &far_future,
            original_now
        ));
    }

    #[test]
    fn scan_index_compare_and_swap_rejects_a_stale_overlapping_daemon() {
        let root = temp_dir("scan-index-cas");
        let path = root.join("codex-scan-index-v2.json");
        let mut initial = ScanIndex::default();
        initial.save(&path).expect("save initial generation");
        assert_eq!(initial.generation, 1);

        let mut stale = ScanIndex::load(&path).expect("load stale view");
        let mut winner = ScanIndex::load(&path).expect("load winning view");
        winner.resume_after_path = Some("winner".to_string());
        winner.save(&path).expect("winner advances generation");
        stale.resume_after_path = Some("stale".to_string());
        stale
            .save(&path)
            .expect_err("stale generation must not clobber winner");

        let observed = ScanIndex::load(&path).expect("load winner");
        assert_eq!(observed.generation, 2);
        assert_eq!(observed.resume_after_path.as_deref(), Some("winner"));
        let _ = fs::remove_dir_all(root);
    }

    fn test_candidate(path: PathBuf) -> CandidateFile {
        let scan_root = path
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();
        CandidateFile {
            scan_root,
            path,
            size_bytes: 0,
            modified_unix_seconds: 0,
            modified_unix_nanos: 0,
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
        }
    }

    #[test]
    fn bounded_candidate_selection_is_lexicographic_and_resumes_after_cursor() {
        let root = Path::new("/opaque-root");
        let mut first = BoundedCandidateSelection::new(None, None, 2);
        for name in ["c.jsonl", "a.jsonl", "b.jsonl"] {
            first.insert(test_candidate(root.join(name)));
        }
        let (selected, complete, cursor, upper_bound) = first.finish(3);
        assert_eq!(
            selected
                .iter()
                .map(|candidate| candidate.path.file_name().unwrap().to_string_lossy())
                .collect::<Vec<_>>(),
            ["a.jsonl", "b.jsonl"]
        );
        assert!(!complete);

        let mut resumed = BoundedCandidateSelection::new(cursor, upper_bound, 2);
        for name in ["z-new.jsonl", "c.jsonl", "a.jsonl", "b.jsonl"] {
            resumed.insert(test_candidate(root.join(name)));
        }
        let (selected, complete, cursor, upper_bound) = resumed.finish(4);
        assert_eq!(
            selected
                .iter()
                .map(|candidate| candidate.path.file_name().unwrap().to_string_lossy())
                .collect::<Vec<_>>(),
            ["c.jsonl"]
        );
        assert!(complete, "the frozen preexisting range completes");
        assert!(cursor.is_none());
        assert!(upper_bound.is_none());

        let mut next_generation = BoundedCandidateSelection::new(None, None, 2);
        for name in ["z-new.jsonl", "c.jsonl", "a.jsonl", "b.jsonl"] {
            next_generation.insert(test_candidate(root.join(name)));
        }
        let (selected, complete, _, _) = next_generation.finish(4);
        assert_eq!(
            selected
                .iter()
                .map(|candidate| candidate.path.file_name().unwrap().to_string_lossy())
                .collect::<Vec<_>>(),
            ["a.jsonl", "b.jsonl"]
        );
        assert!(!complete);
    }

    #[test]
    fn frozen_sweep_visits_every_preexisting_key_despite_sustained_tail_churn() {
        let root = Path::new("/opaque-root");
        let preexisting = [
            "a.jsonl", "b.jsonl", "c.jsonl", "d.jsonl", "e.jsonl", "f.jsonl",
        ];
        let mut cursor = None;
        let mut upper_bound = None;
        let mut visited = BTreeSet::new();
        for cycle in 0..3 {
            let mut selection =
                BoundedCandidateSelection::new(cursor.clone(), upper_bound.clone(), 2);
            for name in preexisting {
                selection.insert(test_candidate(root.join(name)));
            }
            for tail in 0..cycle {
                selection.insert(test_candidate(root.join(format!("z-{tail}.jsonl"))));
            }
            let (selected, complete, next_cursor, next_upper_bound) =
                selection.finish(preexisting.len() + cycle);
            visited.extend(selected.into_iter().filter_map(|candidate| {
                candidate
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_string)
            }));
            cursor = next_cursor;
            upper_bound = next_upper_bound;
            assert_eq!(complete, cycle == 2);
        }
        assert_eq!(
            visited,
            preexisting.into_iter().map(str::to_string).collect()
        );
    }

    #[test]
    fn upload_context_transition_forces_a_complete_a_b_a_reparse() {
        let root = temp_dir("upload-context-aba");
        let path = root.join("session-019e2700-1111-7000-9000-111111111111.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write fixture");
        let mut index = ScanIndex::default();

        let mut scan_with_context = |context: &str| {
            index.activate_upload_context(context.to_string());
            let mut result = scan_source_roots_with_limit(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                "2026-07-22T08:02:00Z",
                BACKFILL_WINDOW_DAYS,
                MAX_BACKFILL_FILES_PER_SOURCE,
                true,
            )
            .expect("scan");
            finalize_scan_after_policy(SnapshotSource::Pi, &mut result, &mut index);
            result
        };

        assert_eq!(scan_with_context("context-a").scanned_file_count, 1);
        assert_eq!(scan_with_context("context-a").scanned_file_count, 0);
        assert_eq!(scan_with_context("context-b").scanned_file_count, 1);
        assert_eq!(scan_with_context("context-a").scanned_file_count, 1);
        assert_eq!(
            index.upload_context_fingerprint.as_deref(),
            Some("context-a")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn historical_replay_generation_clears_once_then_resumes_its_frozen_cursor() {
        let mut index = ScanIndex {
            files: BTreeMap::from([("old.jsonl".to_string(), manifest_index_entry(Some("old")))]),
            resume_after_path: Some("page-one.jsonl".to_string()),
            resume_upper_bound_path: Some("page-three.jsonl".to_string()),
            ..ScanIndex::default()
        };
        index.prepare_historical_replay("replay-v1".to_string());
        assert!(index.files.is_empty());
        assert!(index.resume_after_path.is_none());

        index.files.insert(
            "page-one.jsonl".to_string(),
            manifest_index_entry(Some("accepted-page-one")),
        );
        index.resume_after_path = Some("page-one.jsonl".to_string());
        index.resume_upper_bound_path = Some("page-three.jsonl".to_string());
        index.prepare_historical_replay("replay-v1".to_string());
        assert!(index.files.contains_key("page-one.jsonl"));
        assert_eq!(
            index.resume_after_path.as_deref(),
            Some("page-one.jsonl"),
            "a restart of the same replay generation resumes instead of clearing"
        );

        index.prepare_historical_replay("replay-v2".to_string());
        assert!(index.files.is_empty());
        assert!(index.resume_after_path.is_none());
    }

    #[test]
    fn opened_object_identity_moves_when_same_inode_content_sample_changes() {
        let root = temp_dir("opened-object-sample");
        let path = root.join("session.jsonl");
        fs::write(&path, b"aaaaaaaa\n").expect("write first content");
        let mut first = test_candidate(path.clone());
        open_candidate_file(SnapshotSource::ClaudeCode, &mut first).expect("open first content");

        fs::write(&path, b"bbbbbbbb\n").expect("replace content on same inode");
        let mut second = test_candidate(path);
        open_candidate_file(SnapshotSource::ClaudeCode, &mut second).expect("open second content");
        assert_ne!(first.opened_object_identity, second.opened_object_identity);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn opened_replacement_is_rechecked_against_the_frozen_lookback_window() {
        let root = temp_dir("opened-object-age-recheck");
        let path = root.join("session.jsonl");
        fs::write(&path, b"{}\n").expect("write recent discovery object");
        let census_at = rfc3339_unix_seconds("2026-07-31T00:00:00Z");
        let mut census = ScanCensus::default();
        let mut candidate = candidate_from_traversal_path(
            SnapshotSource::Pi,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            census_at,
            BACKFILL_WINDOW_DAYS,
        )
        .expect("recent path is discovered");

        let replacement = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open replacement");
        replacement
            .set_times(
                fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000)),
            )
            .expect("restore replacement to old mtime");
        drop(replacement);
        open_candidate_file(SnapshotSource::Pi, &mut candidate)
            .expect("open exact replacement object");

        assert!(
            !opened_candidate_is_within_frozen_window(&candidate, census_at, BACKFILL_WINDOW_DAYS,),
            "eligibility must follow the opened object's mtime"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn opened_object_identity_moves_on_middle_rewrite_with_size_and_mtime_restored() {
        use std::io::Write;

        let root = temp_dir("opened-object-middle-rewrite");
        let path = root.join("session.jsonl");
        fs::write(&path, vec![b'a'; FILE_CONTENT_SAMPLE_BYTES * 3])
            .expect("write original content");
        let original_metadata = fs::metadata(&path).expect("original metadata");
        let mut first = test_candidate(path.clone());
        open_candidate_file(SnapshotSource::ClaudeCode, &mut first).expect("open first content");

        let mut rewrite = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open middle rewrite");
        rewrite
            .seek(SeekFrom::Start((FILE_CONTENT_SAMPLE_BYTES + 128) as u64))
            .expect("seek middle");
        rewrite
            .write_all(b"changed-middle")
            .expect("rewrite middle");
        rewrite.sync_all().expect("sync middle rewrite");
        let times = [
            libc::timespec {
                tv_sec: original_metadata.atime(),
                tv_nsec: original_metadata.atime_nsec(),
            },
            libc::timespec {
                tv_sec: original_metadata.mtime(),
                tv_nsec: original_metadata.mtime_nsec(),
            },
        ];
        assert_eq!(
            unsafe { libc::futimens(rewrite.as_raw_fd(), times.as_ptr()) },
            0
        );
        drop(rewrite);

        let mut second = test_candidate(path);
        open_candidate_file(SnapshotSource::ClaudeCode, &mut second).expect("open rewritten file");
        assert_eq!(first.size_bytes, second.size_bytes);
        assert_eq!(first.modified_unix_nanos, second.modified_unix_nanos);
        assert_ne!(first.opened_object_identity, second.opened_object_identity);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn scanner_rejects_symlinks_without_crossing_the_root() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("scan-symlink-root");
        let outside = temp_dir("scan-symlink-outside");
        fs::write(outside.join("session.jsonl"), b"{}\n").expect("outside transcript");
        symlink(&outside, root.join("escape")).expect("create directory symlink");
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
        .expect("symlink is quarantined per path");
        assert_eq!(scan.symlink_rejected_count, 1);
        assert_eq!(scan.discovered_file_count, 0);
        assert!(!scan.census_complete);
        assert!(index.files.is_empty());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[cfg(unix)]
    #[test]
    fn scanner_allows_one_configured_root_symlink_but_not_nested_symlinks() {
        use std::os::unix::fs::symlink;

        let parent = temp_dir("scan-configured-root-symlink");
        let real_root = parent.join("real-sessions");
        let configured_root = parent.join("configured-sessions");
        fs::create_dir_all(&real_root).expect("create real scan root");
        fs::write(
            real_root.join("session.jsonl"),
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write transcript");
        symlink(&real_root, &configured_root).expect("create configured root symlink");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&configured_root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("trusted configured root is resolved once");
        assert!(scan.census_complete);
        assert_eq!(scan.symlink_rejected_count, 0);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(index.files.len(), 1);

        let _ = fs::remove_dir_all(parent);
    }

    #[cfg(unix)]
    #[test]
    fn opened_candidate_cannot_escape_through_replaced_intermediate_directory() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("scan-intermediate-root");
        let outside = temp_dir("scan-intermediate-outside");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("nested root");
        fs::write(nested.join("session.jsonl"), b"{}\n").expect("inside transcript");
        fs::write(outside.join("session.jsonl"), b"{\"outside\":true}\n")
            .expect("outside transcript");
        let mut candidate = test_candidate(nested.join("session.jsonl"));
        candidate.scan_root = root.clone();

        fs::rename(&nested, root.join("nested-original")).expect("move discovered directory");
        symlink(&outside, &nested).expect("replace intermediate component with symlink");
        open_candidate_file(SnapshotSource::ClaudeCode, &mut candidate)
            .expect_err("component-wise O_NOFOLLOW must reject the escape");

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn quarantined_entities_are_excluded_from_non_vacuous_manifest() {
        let keep = "a".repeat(64);
        let quarantine = "b".repeat(64);
        let mut index = ScanIndex {
            file_snapshot_fingerprints: BTreeMap::from([(
                "opaque-file".to_string(),
                BTreeSet::from([keep.clone(), quarantine.clone()]),
            )]),
            snapshot_activity_at: BTreeMap::from([(
                keep.clone(),
                Some("2050-01-01T00:00:00Z".to_string()),
            )]),
            quarantined_snapshot_fingerprints: BTreeMap::from([(
                quarantine.clone(),
                snapshot_quarantine_record(SnapshotSource::Codex),
            )]),
            ..ScanIndex::default()
        };
        let manifest = index.manifest(SnapshotSource::Codex, 183);
        assert_eq!(manifest.entity_count, 1);

        index
            .snapshot_activity_at
            .insert(quarantine.clone(), Some("2050-01-01T00:00:00Z".to_string()));
        index.retain_quarantined_fingerprints(&BTreeMap::new());
        assert_eq!(index.manifest(SnapshotSource::Codex, 183).entity_count, 2);
    }

    #[test]
    fn scan_index_retries_same_fingerprint_after_quarantine_contract_upgrade() {
        let path = PathBuf::from("/opaque/session.jsonl");
        let fingerprint = "e".repeat(64);
        let candidate = CandidateFile {
            scan_root: PathBuf::from("/opaque"),
            path: path.clone(),
            size_bytes: 42,
            modified_unix_seconds: 7,
            modified_unix_nanos: 7_000_000_001,
            source_file_fingerprint: "same-source-file".to_string(),
            legacy_source_file_fingerprint: "legacy".to_string(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".to_string(),
        };
        let mut stale_witness = snapshot_quarantine_witness(SnapshotSource::Codex);
        stale_witness.collector_version.push_str("-old");
        let mut index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: candidate.size_bytes,
                    modified_unix_seconds: candidate.modified_unix_seconds,
                    modified_unix_nanos: Some(candidate.modified_unix_nanos),
                    source_file_fingerprint: candidate.source_file_fingerprint.clone(),
                    last_snapshot_fingerprint: Some("group".to_string()),
                    scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
                },
            )]),
            file_snapshot_fingerprints: BTreeMap::from([(
                local_index_key(&path),
                BTreeSet::from([fingerprint.clone()]),
            )]),
            snapshot_activity_at: BTreeMap::from([(
                fingerprint.clone(),
                Some("2050-01-01T00:00:00Z".to_string()),
            )]),
            quarantined_snapshot_fingerprints: BTreeMap::from([(
                fingerprint,
                SnapshotQuarantineRecord {
                    witness: stale_witness,
                    retry_after_unix_seconds: u64::MAX,
                },
            )]),
            ..ScanIndex::default()
        };
        index.activate_quarantine_witness(SnapshotSource::Codex);
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Parse
        );
    }

    #[test]
    fn legacy_scan_index_reparses_once_to_establish_semantic_activity_witness() {
        let root = temp_dir("scan-index-migration");
        let path = root.join("rollout-019e253c-6666-7000-9000-ffffffffffff.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-ffffffffffff\"}}\n",
                "{\"timestamp\":\"2026-07-22T08:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = fs::metadata(&path).expect("metadata");
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .expect("mtime seconds");
        let legacy_metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&root));
        let legacy_source_file_fingerprint = source_file_fingerprint_with_context(
            &path,
            metadata.len(),
            modified_unix_seconds,
            CODEX_SNAPSHOT_PARSER_VERSION,
            &legacy_metadata.legacy_sidecar_fingerprint,
        );
        let mut index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: metadata.len(),
                    modified_unix_seconds,
                    modified_unix_nanos: None,
                    source_file_fingerprint: legacy_source_file_fingerprint,
                    last_snapshot_fingerprint: Some("legacy-snapshot-fingerprint".to_string()),
                    scan_identity_version: None,
                },
            )]),
            ..ScanIndex::default()
        };

        let scan = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(scan.snapshots.len(), 1);
        let migrated = index.files.get(&local_index_key(&path)).expect("entry");
        assert_eq!(
            migrated.scan_identity_version.as_deref(),
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
        );
        assert_ne!(
            migrated.last_snapshot_fingerprint.as_deref(),
            Some("legacy-snapshot-fingerprint")
        );
        assert!(migrated.modified_unix_nanos.is_some());
        assert!(index
            .file_snapshot_fingerprints
            .get(&local_index_key(&path))
            .expect("exact entity set")
            .iter()
            .all(|fingerprint| index.snapshot_activity_at.contains_key(fingerprint)));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_codex_config_presence_forces_one_corrective_snapshot() {
        let home = temp_dir("legacy-config-cutover");
        let codex_dir = home.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        // The current parser extracts no selector from this valid config. Its
        // mere presence still cannot prove what the old stat-only index saw.
        fs::write(
            codex_dir.join("config.toml"),
            "personality = \"pragmatic\"\n",
        )
        .expect("write config");
        let path = sessions_dir.join("rollout-019e253c-6666-7000-9000-aaaaaaaaaaaa.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-07-22T08:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write transcript");
        let file_metadata = fs::metadata(&path).expect("metadata");
        let modified_unix_seconds = file_metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .expect("mtime seconds");
        let legacy_metadata =
            CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));
        assert!(legacy_metadata.legacy_config_file_present);
        let legacy_file_fingerprint = source_file_fingerprint_with_context(
            &path,
            file_metadata.len(),
            modified_unix_seconds,
            CODEX_SNAPSHOT_PARSER_VERSION,
            &legacy_metadata.legacy_sidecar_fingerprint,
        );
        let mut index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: file_metadata.len(),
                    modified_unix_seconds,
                    modified_unix_nanos: None,
                    source_file_fingerprint: legacy_file_fingerprint,
                    last_snapshot_fingerprint: Some("legacy-snapshot".to_string()),
                    scan_identity_version: None,
                },
            )]),
            ..ScanIndex::default()
        };

        let scan = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions_dir),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");
        assert_eq!(scan.snapshots.len(), 1);
        assert!(scan.snapshots[0].model_usage[0].selector_context.is_empty());
        assert_eq!(
            index
                .files
                .get(&local_index_key(&path))
                .and_then(|entry| entry.scan_identity_version.as_deref()),
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn nanosecond_mtime_change_forces_parse_inside_same_second() {
        let path = PathBuf::from("/redacted/session.jsonl");
        let candidate = CandidateFile {
            scan_root: PathBuf::from("/redacted"),
            path: path.clone(),
            size_bytes: 42,
            modified_unix_seconds: 1_777_777_777,
            modified_unix_nanos: 1_777_777_777_000_000_002,
            source_file_fingerprint: "new".to_string(),
            legacy_source_file_fingerprint: "legacy".to_string(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".to_string(),
        };
        let index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: 42,
                    modified_unix_seconds: 1_777_777_777,
                    modified_unix_nanos: Some(1_777_777_777_000_000_001),
                    source_file_fingerprint: "old".to_string(),
                    last_snapshot_fingerprint: Some("snapshot".to_string()),
                    scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
                },
            )]),
            ..ScanIndex::default()
        };
        // A legacy row has no nullable semantic-activity witness. A narrow
        // config reconciliation cannot manufacture one, so v2 requires the
        // one-time full parse before it can publish a complete manifest.
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Parse
        );
    }

    #[test]
    fn legacy_index_reparses_when_old_sidecar_identity_cannot_be_proven() {
        let path = PathBuf::from("/redacted/session.jsonl");
        let candidate = CandidateFile {
            scan_root: PathBuf::from("/redacted"),
            path: path.clone(),
            size_bytes: 42,
            modified_unix_seconds: 1_777_777_777,
            modified_unix_nanos: 1_777_777_777_000_000_001,
            source_file_fingerprint: "semantic-sync".to_string(),
            legacy_source_file_fingerprint: "legacy-current-sidecar".to_string(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".to_string(),
        };
        let index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: 42,
                    modified_unix_seconds: 1_777_777_777,
                    modified_unix_nanos: None,
                    source_file_fingerprint: "legacy-previous-sidecar".to_string(),
                    last_snapshot_fingerprint: Some("snapshot".to_string()),
                    scan_identity_version: None,
                },
            )]),
            ..ScanIndex::default()
        };
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Parse
        );
    }

    #[test]
    fn legacy_index_targets_config_derived_rows_for_reconciliation() {
        let path = PathBuf::from("/redacted/session.jsonl");
        let candidate = CandidateFile {
            scan_root: PathBuf::from("/redacted"),
            path: path.clone(),
            size_bytes: 42,
            modified_unix_seconds: 1_777_777_777,
            modified_unix_nanos: 1_777_777_777_000_000_001,
            source_file_fingerprint: "semantic-sync".to_string(),
            legacy_source_file_fingerprint: "legacy-matching-sidecar".to_string(),
            legacy_config_reconciliation_required: true,
            opened_object_identity: "opened".to_string(),
        };
        let index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&path),
                ScanIndexEntry {
                    size_bytes: 42,
                    modified_unix_seconds: 1_777_777_777,
                    modified_unix_nanos: None,
                    source_file_fingerprint: "legacy-matching-sidecar".to_string(),
                    last_snapshot_fingerprint: Some("snapshot".to_string()),
                    scan_identity_version: None,
                },
            )]),
            ..ScanIndex::default()
        };
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Parse
        );
    }

    #[test]
    fn parsed_semantic_noop_is_not_returned_for_upload() {
        let root = temp_dir("semantic-noop");
        let path = root.join("session-019e2700-1111-7000-9000-111111111111.jsonl");
        let base = concat!(
            "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
            "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n"
        );
        fs::write(&path, base).expect("write first fixture");
        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_eq!(first.snapshots.len(), 1);

        fs::write(&path, format!("{base}{{}}\n")).expect("add ignored row");
        let noop = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("noop scan");
        assert_eq!(noop.scanned_file_count, 1);
        assert_eq!(noop.scanned_session_count, 1);
        assert_eq!(noop.semantic_noop_count, 1);
        assert!(noop.snapshots.is_empty());

        fs::write(
            &path,
            format!(
                "{base}{{\"type\":\"message_end\",\"message\":{{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707202000,\"usage\":{{\"input\":3,\"output\":1,\"cacheRead\":0,\"cacheWrite\":0}}}}}}\n"
            ),
        )
        .expect("add real usage");
        let changed = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("changed scan");
        assert_eq!(changed.snapshots.len(), 1);
        assert_eq!(changed.semantic_noop_count, 0);
        assert_eq!(changed.snapshots[0].input_tokens, 15);

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
        let first = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            file_limit,
            true,
        )
        .expect("scan");

        assert_eq!(first.backfill_window_days, BACKFILL_WINDOW_DAYS);
        assert_eq!(first.backfill_file_limit, file_limit);
        assert_eq!(first.discovered_file_count, file_limit + 1);
        assert_eq!(first.skipped_file_count_due_to_limit, 1);
        assert!(first.scan_cap_hit);
        assert!(!first.census_complete);
        assert_eq!(first.scanned_file_count, file_limit);
        assert_eq!(first.census_window_end, "2026-05-14T10:04:00Z");

        let second = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:09:00Z",
            BACKFILL_WINDOW_DAYS,
            file_limit,
            true,
        )
        .expect("complete frozen sweep");
        assert!(second.census_complete);
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(
            second.census_window_end, "2026-05-14T10:04:00Z",
            "a multi-cycle manifest cannot claim through its later finishing tick"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wide_single_directory_fails_red_without_materializing_past_budget() {
        let root = temp_dir("bounded-wide-directory");
        for index in 0..4 {
            fs::write(root.join(format!("session-{index}.jsonl")), b"{}\n")
                .expect("write wide directory fixture");
        }
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().expect("traversal");
        advance_bounded_directory_traversal_with_budget(
            SnapshotSource::Pi,
            traversal,
            BACKFILL_WINDOW_DAYS,
            3,
        );
        assert_eq!(traversal.counts.directory_entry_cap_exceeded_count, 1);
        assert!(traversal.pending_candidates.is_empty());
        assert!(traversal.counts.has_errors());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn traversal_restart_after_scan_derivation_upgrade_revisits_consumed_prefix() {
        let root = temp_dir("bounded-traversal-derivation-upgrade");
        fs::write(
            root.join("session.jsonl"),
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":3,\"output\":1}}}\n",
        )
        .expect("write traversal fixture");
        let roots = vec![root.clone()];
        let mut index = ScanIndex::default();

        // Exact pre-repair context: it bound scope/policy but not the scan,
        // local-index, or exact-open derivations. Its empty queue represents a
        // prefix already consumed by the older daemon before restart.
        let mut legacy = Sha256::new();
        update_length_prefixed(&mut legacy, b"ottto:snapshot-bounded-traversal:v1");
        update_length_prefixed(&mut legacy, SnapshotSource::Pi.api_slug().as_bytes());
        update_length_prefixed(&mut legacy, &BACKFILL_WINDOW_DAYS.to_be_bytes());
        update_length_prefixed(&mut legacy, b"none");
        update_length_prefixed(&mut legacy, b"none");
        for scan_root in &roots {
            update_length_prefixed(&mut legacy, scan_root.to_string_lossy().as_bytes());
        }
        index.traversal = Some(ScanTraversalCheckpoint {
            context_fingerprint: format!("{:x}", legacy.finalize()),
            census_window_end: "2026-07-31T00:00:00Z".to_string(),
            scan_roots: roots.clone(),
            pending_directories: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            observed_index_keys: BTreeSet::new(),
            reconciliation_upper_bound: None,
            reconciliation_after: None,
            reconciliation_started: false,
            watcher_hint_seen: false,
            unhealthy_retry_attempt: 0,
            unhealthy_retry_not_before_unix_seconds: None,
            counts: ScanTraversalCounts::default(),
        });

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            &roots,
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan derivation change starts a fresh bounded traversal");

        assert_eq!(scan.census_window_end, "2026-07-31T00:05:00Z");
        assert_eq!(scan.discovered_file_count, 1);
        assert_eq!(scan.scanned_file_count, 1);
        assert!(scan.census_complete);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_traversal_resumes_after_scan_index_restart() {
        let root = temp_dir("bounded-traversal-restart");
        for index in 0..4 {
            fs::write(
                root.join(format!("session-{index}.jsonl")),
                format!(
                    "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n",
                    index + 1
                ),
            )
            .expect("write traversal fixture");
        }
        let index_path = root.join("scan-index.json");
        let mut index = ScanIndex::default();
        let first = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("first page");
        assert!(!first.census_complete);
        assert_eq!(first.scanned_file_count, 3);
        index.save(&index_path).expect("save traversal checkpoint");

        let mut resumed = ScanIndex::load(&index_path).expect("reload traversal checkpoint");
        let second = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut resumed,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("resume second page");
        assert!(second.census_complete);
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(second.census_window_end, "2026-07-31T00:00:00Z");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn new_tail_waits_for_next_bounded_traversal_generation() {
        let root = temp_dir("bounded-traversal-new-tail");
        let fixture = |tokens: usize| {
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{tokens},\"output\":1}}}}}}\n"
            )
        };
        for index in 0..4 {
            fs::write(
                root.join(format!("session-{index}.jsonl")),
                fixture(index + 1),
            )
            .expect("write frozen generation fixture");
        }
        let mut index = ScanIndex::default();
        let mut first = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("first page");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut first, &mut index);
        assert!(!first.census_complete);
        fs::write(root.join("session-4.jsonl"), fixture(5)).expect("write new tail");

        let mut second = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("finish frozen generation");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut second, &mut index);
        assert!(second.census_complete);
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(second.census_window_end, "2026-07-31T00:00:00Z");

        let mut third = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:10:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("next generation sees tail");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut third, &mut index);
        assert!(!third.census_complete);
        assert_eq!(third.discovered_file_count, 5);
        let fourth = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:15:00Z",
            BACKFILL_WINDOW_DAYS,
            3,
            true,
        )
        .expect("next generation drains tail");
        assert!(fourth.census_complete);
        assert_eq!(fourth.scanned_file_count, 1);
        assert_eq!(fourth.snapshots.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deletion_reconciliation_is_bounded_and_resumable() {
        let mut index = ScanIndex {
            files: ["a", "b", "c", "d"]
                .into_iter()
                .map(|key| (key.to_string(), manifest_index_entry(Some(key))))
                .collect(),
            traversal: Some(ScanTraversalCheckpoint {
                context_fingerprint: "context".to_string(),
                census_window_end: "2026-07-31T00:00:00Z".to_string(),
                scan_roots: Vec::new(),
                pending_directories: VecDeque::new(),
                pending_candidates: VecDeque::new(),
                observed_index_keys: ["b".to_string(), "d".to_string()].into_iter().collect(),
                reconciliation_upper_bound: Some("d".to_string()),
                reconciliation_after: None,
                reconciliation_started: false,
                watcher_hint_seen: false,
                unhealthy_retry_attempt: 0,
                unhealthy_retry_not_before_unix_seconds: None,
                counts: ScanTraversalCounts::default(),
            }),
            ..ScanIndex::default()
        };
        assert!(!reconcile_missing_index_entries_with_limit(&mut index, 2));
        assert_eq!(
            index.files.keys().cloned().collect::<Vec<_>>(),
            ["b", "c", "d"]
        );
        assert!(reconcile_missing_index_entries_with_limit(&mut index, 2));
        assert_eq!(index.files.keys().cloned().collect::<Vec<_>>(), ["b", "d"]);
    }

    #[test]
    fn bounded_watcher_hint_joins_complete_durable_census() {
        let root = temp_dir("bounded-watcher-hint");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":1}}}\n",
        )
        .expect("write watcher fixture");
        let mut index = ScanIndex::default();
        let mut hinted = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
            None,
            None,
            std::slice::from_ref(&path),
            false,
        )
        .expect("hinted scan");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut hinted, &mut index);
        assert_eq!(hinted.snapshots.len(), 1);
        assert!(hinted.census_complete);
        assert!(!hinted.scan_cap_hit);
        assert!(index.traversal.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_watcher_hints_cannot_starve_bounded_census() {
        let root = temp_dir("bounded-repeated-watcher-hint");
        let fixture = |tokens: u64| {
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{tokens},\"output\":1}}}}}}\n"
            )
        };
        let active_path = root.join("a-active.jsonl");
        fs::write(&active_path, fixture(1)).expect("write active fixture");
        fs::write(root.join("b.jsonl"), fixture(2)).expect("write second fixture");
        fs::write(root.join("c.jsonl"), fixture(3)).expect("write third fixture");
        let mut index = ScanIndex::default();

        for tick in 0..3 {
            let scan = scan_source_roots_with_limit_and_attribution(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                &format!("2026-07-31T00:0{tick}:00Z"),
                BACKFILL_WINDOW_DAYS,
                1,
                true,
                None,
                None,
                std::slice::from_ref(&active_path),
                false,
            )
            .expect("bounded hinted scan");
            if tick < 2 {
                assert!(!scan.census_complete);
                assert_eq!(scan.census_window_end, "2026-07-31T00:00:00Z");
            } else {
                assert!(scan.census_complete);
                assert!(index.traversal.is_none());
            }
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rename_hint_removes_old_index_key_despite_repeated_active_hints() {
        let root = temp_dir("bounded-watcher-rename");
        let fixture = |tokens: u64| {
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{tokens},\"output\":1}}}}}}\n"
            )
        };
        let old_path = root.join("a-old.jsonl");
        let new_path = root.join("b-new.jsonl");
        let active_path = root.join("c-active.jsonl");
        fs::write(&old_path, fixture(1)).expect("write old fixture");
        fs::write(&active_path, fixture(2)).expect("write active fixture");
        let mut index = ScanIndex::default();

        let initial = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("initial complete scan");
        assert!(initial.census_complete);
        assert!(index.files.contains_key(&local_index_key(&old_path)));

        fs::rename(&old_path, &new_path).expect("rename fixture");
        let initial_hints = vec![old_path.clone(), new_path.clone(), active_path.clone()];
        let mut completed = false;
        for tick in 1..=6 {
            let hints = if tick == 1 {
                initial_hints.as_slice()
            } else {
                std::slice::from_ref(&active_path)
            };
            let mut scan = scan_source_roots_with_limit_and_attribution(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                &format!("2026-07-31T00:0{tick}:00Z"),
                BACKFILL_WINDOW_DAYS,
                1,
                true,
                None,
                None,
                hints,
                false,
            )
            .expect("bounded rename scan");
            finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut index);
            assert_eq!(scan.disappeared_file_count, 0);
            if scan.census_complete {
                completed = true;
                break;
            }
        }

        assert!(completed, "rename/remove hint must settle under activity");
        assert!(!index.files.contains_key(&local_index_key(&old_path)));
        assert!(index.files.contains_key(&local_index_key(&new_path)));
        assert!(index.files.contains_key(&local_index_key(&active_path)));
        assert_eq!(index.files.len(), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn late_remove_hint_retires_key_already_passed_by_reconciliation() {
        let root = temp_dir("bounded-watcher-late-remove");
        let fixture = |tokens: u64| {
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{tokens},\"output\":1}}}}}}\n"
            )
        };
        let removed_path = root.join("a-removed.jsonl");
        let retained_path = root.join("b-retained.jsonl");
        fs::write(&removed_path, fixture(1)).expect("write removed fixture");
        fs::write(&retained_path, fixture(2)).expect("write retained fixture");
        let mut index = ScanIndex::default();

        let initial = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("initial complete scan");
        assert!(initial.census_complete);

        let removed_key = local_index_key(&removed_path);
        let retained_key = local_index_key(&retained_path);
        ensure_bounded_traversal(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().expect("traversal");
        traversal.pending_directories.clear();
        traversal.pending_candidates.clear();
        traversal.observed_index_keys = BTreeSet::from([removed_key.clone(), retained_key.clone()]);
        traversal.reconciliation_upper_bound = Some(retained_key.clone());
        traversal.reconciliation_after = Some(removed_key.clone());
        traversal.reconciliation_started = true;

        fs::remove_file(&removed_path).expect("remove already-reconciled fixture");
        let scan = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:05:30Z",
            BACKFILL_WINDOW_DAYS,
            1,
            true,
            None,
            None,
            std::slice::from_ref(&removed_path),
            false,
        )
        .expect("settle late remove hint");

        assert!(scan.census_complete);
        assert!(!index.files.contains_key(&removed_key));
        assert!(index.files.contains_key(&retained_key));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn watcher_overflow_dirties_generation_and_clean_sweep_repairs_missed_change() {
        let root = temp_dir("bounded-watcher-overflow");
        let first_path = root.join("a.jsonl");
        let second_path = root.join("b.jsonl");
        let fixture = |tokens: u64| {
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{tokens},\"output\":1}}}}}}\n"
            )
        };
        fs::write(&first_path, fixture(1)).expect("write first fixture");
        fs::write(&second_path, fixture(2)).expect("write second fixture");
        let mut index = ScanIndex::default();

        let mut first = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
            1,
            true,
            None,
            None,
            &[],
            false,
        )
        .expect("start frozen generation");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut first, &mut index);
        assert!(!first.census_complete);
        assert_eq!(first.snapshots[0].input_tokens, 1);

        // The raw watcher overflow loses this exact path after its directory
        // was already traversed. The overflow witness must prevent the current
        // generation from publishing a terminal manifest.
        fs::write(&first_path, fixture(99)).expect("change already traversed file");
        let mut overflowed = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:30Z",
            BACKFILL_WINDOW_DAYS,
            1,
            true,
            None,
            None,
            &[],
            true,
        )
        .expect("finish dirty generation");
        finalize_scan_after_policy(SnapshotSource::Pi, &mut overflowed, &mut index);
        assert!(!overflowed.census_complete);
        assert!(overflowed.scan_cap_hit);
        assert!(index.traversal.is_none());

        let mut repaired = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:01:00Z",
            BACKFILL_WINDOW_DAYS,
            1,
            true,
            None,
            None,
            &[],
            false,
        )
        .expect("clean repair generation");
        assert_eq!(repaired.snapshots.len(), 1);
        assert_eq!(repaired.snapshots[0].input_tokens, 99);
        finalize_scan_after_policy(SnapshotSource::Pi, &mut repaired, &mut index);
        assert!(!repaired.census_complete);

        let final_page = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:01:30Z",
            BACKFILL_WINDOW_DAYS,
            1,
            true,
            None,
            None,
            &[],
            false,
        )
        .expect("finish clean repair generation");
        assert!(final_page.census_complete);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unhealthy_generation_retries_with_backoff_while_hints_still_progress() {
        let root = temp_dir("bounded-unhealthy-retry");
        let malformed = root.join("a-malformed.jsonl");
        fs::write(
            &malformed,
            concat!(
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":1,\"output\":1}}}\n",
                "not-json\n"
            ),
        )
        .expect("write malformed fixture");
        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first unhealthy scan");
        assert_eq!(first.scanned_file_count, 1);
        assert!(!first.census_complete);
        assert!(index.traversal.is_some(), "red witness stays durable");

        let quiet = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("retry remains backed off");
        assert_eq!(quiet.scanned_file_count, 0);
        assert!(!quiet.census_complete);

        let sibling = root.join("z-healthy.jsonl");
        fs::write(
            &sibling,
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":7,\"output\":1}}}\n",
        )
        .expect("write healthy sibling");
        let hinted = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:40Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
            None,
            None,
            std::slice::from_ref(&sibling),
            false,
        )
        .expect("healthy hint progresses under red witness");
        assert_eq!(hinted.snapshots.len(), 1);
        assert_eq!(hinted.snapshots[0].input_tokens, 7);
        assert!(!hinted.census_complete);

        let retried = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:01:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("bounded retry becomes due");
        assert_eq!(retried.scanned_file_count, 2);
        assert!(!retried.census_complete);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn periodic_scan_discovers_root_created_after_watcher_startup() {
        let parent = temp_dir("late-scan-root-parent");
        let root = parent.join("sessions-created-later");
        let mut index = ScanIndex::default();
        let absent = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("missing optional root is complete-empty");
        assert!(absent.census_complete);
        assert!(index.known_configured_scan_roots.is_empty());

        fs::create_dir_all(&root).expect("create root after watcher startup");
        fs::write(
            root.join("session.jsonl"),
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":3,\"output\":1}}}\n",
        )
        .expect("write late session");
        let found = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("periodic scan finds late root");
        assert!(found.census_complete);
        assert_eq!(found.snapshots.len(), 1);
        assert!(index
            .known_configured_scan_roots
            .contains(&local_index_key(&root)));
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn previously_observed_root_disappearance_fails_red_until_root_returns() {
        let parent = temp_dir("disappearing-scan-root-parent");
        let root = parent.join("sessions");
        fs::create_dir_all(&root).expect("create observed root");
        fs::write(
            root.join("session.jsonl"),
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":3,\"output\":1}}}\n",
        )
        .expect("write observed entity");
        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("observe configured root");
        assert!(first.census_complete);
        assert_eq!(index.files.len(), 1);

        fs::remove_dir_all(&root).expect("temporarily remove configured root");
        let missing = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("missing root is a source-local red witness");
        assert!(!missing.census_complete);
        assert_eq!(missing.disappeared_file_count, 1);
        assert_eq!(index.files.len(), 1, "prior entities remain authoritative");

        fs::create_dir_all(&root).expect("restore configured root empty");
        let restored = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("restored root converges through a fresh complete census");
        assert!(restored.census_complete);
        assert!(index.files.is_empty());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn old_index_without_root_witness_infers_missing_previously_observed_root() {
        let parent = temp_dir("old-index-missing-root");
        let root = parent.join("sessions");
        let index_path = parent.join("scan-index.json");
        let prior_path = root.join("session.jsonl");
        let mut old_index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&prior_path),
                manifest_index_entry(Some("prior-entity")),
            )]),
            ..ScanIndex::default()
        };
        old_index
            .save(&index_path)
            .expect("write pre-witness index");
        let serialized: Value =
            serde_json::from_slice(&fs::read(&index_path).expect("read pre-witness index"))
                .expect("parse pre-witness index");
        assert!(serialized.get("known_configured_scan_roots").is_none());
        let mut upgraded = ScanIndex::load(&index_path).expect("load pre-witness index");

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut upgraded,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("upgrade inference remains source-local");

        assert!(!scan.census_complete);
        assert_eq!(scan.disappeared_file_count, 1);
        assert!(upgraded.files.contains_key(&local_index_key(&prior_path)));
        assert!(upgraded
            .known_configured_scan_roots
            .contains(&local_index_key(&root)));
        assert!(upgraded.legacy_unresolved_root_file_witnesses.is_empty());
        let _ = fs::remove_dir_all(parent);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_vanished_symlink_witness_does_not_promote_optional_roots() {
        use std::os::unix::fs::symlink;

        let parent = temp_dir("legacy-vanished-symlink-root");
        let target = parent.join("relocated-sessions");
        let configured_link = parent.join("configured-sessions");
        let optional_root = parent.join("optional-sessions");
        fs::create_dir_all(&target).expect("create prior canonical target");
        let prior_path = fs::canonicalize(&target)
            .expect("canonicalize prior target")
            .join("session.jsonl");
        fs::remove_dir_all(&target).expect("remove prior canonical target");
        let index_path = parent.join("scan-index.json");
        let mut old_index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&prior_path),
                manifest_index_entry(Some("prior-entity")),
            )]),
            ..ScanIndex::default()
        };
        let roots = vec![optional_root.clone(), configured_link.clone()];
        old_index.traversal = Some(terminal_unhealthy_traversal(
            scan_traversal_context_fingerprint(
                SnapshotSource::Pi,
                &roots,
                &old_index,
                BACKFILL_WINDOW_DAYS,
            ),
        ));
        old_index
            .save(&index_path)
            .expect("write pre-witness symlink index");
        let mut upgraded = ScanIndex::load(&index_path).expect("load pre-witness symlink index");

        let missing = scan_source_roots(
            SnapshotSource::Pi,
            &roots,
            &mut upgraded,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("unresolved legacy symlink remains source-local");

        assert!(!missing.census_complete);
        assert_eq!(missing.disappeared_file_count, 1);
        assert_eq!(
            upgraded.legacy_unresolved_root_file_witnesses,
            BTreeSet::from([local_index_key(&prior_path)])
        );
        assert!(!upgraded
            .known_configured_scan_roots
            .contains(&local_index_key(&optional_root)));

        fs::create_dir_all(&target).expect("restore canonical target");
        symlink(&target, &configured_link).expect("restore configured symlink");
        let restored = scan_source_roots(
            SnapshotSource::Pi,
            &roots,
            &mut upgraded,
            "2026-07-31T00:10:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("restored symlink covers its durable legacy witness");

        assert_eq!(
            restored.disappeared_file_count,
            0,
            "legacy_witnesses={} optional_known={} link_known={}",
            upgraded.legacy_unresolved_root_file_witnesses.len(),
            upgraded
                .known_configured_scan_roots
                .contains(&local_index_key(&optional_root)),
            upgraded
                .known_configured_scan_roots
                .contains(&local_index_key(&configured_link)),
        );
        assert!(restored.census_complete, "restored scan: {restored:#?}");
        assert!(upgraded.files.is_empty());
        assert!(upgraded.legacy_unresolved_root_file_witnesses.is_empty());
        assert!(upgraded
            .known_configured_scan_roots
            .contains(&local_index_key(&configured_link)));
        assert!(!upgraded
            .known_configured_scan_roots
            .contains(&local_index_key(&optional_root)));
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn legacy_root_context_change_does_not_claim_unrelated_optional_root() {
        let parent = temp_dir("legacy-root-context-change");
        let old_root = parent.join("old-sessions");
        let new_optional_root = parent.join("new-optional-sessions");
        let prior_path = old_root.join("session.jsonl");
        let mut index = ScanIndex {
            files: BTreeMap::from([(
                local_index_key(&prior_path),
                manifest_index_entry(Some("prior-entity")),
            )]),
            ..ScanIndex::default()
        };
        let old_roots = vec![old_root];
        index.traversal = Some(terminal_unhealthy_traversal(
            scan_traversal_context_fingerprint(
                SnapshotSource::Pi,
                &old_roots,
                &index,
                BACKFILL_WINDOW_DAYS,
            ),
        ));

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&new_optional_root),
            &mut index,
            "2026-07-31T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("changed root context starts a fresh authoritative scope");

        assert!(scan.census_complete);
        assert_eq!(scan.disappeared_file_count, 0);
        assert!(index.files.is_empty());
        assert!(index.legacy_unresolved_root_file_witnesses.is_empty());
        assert!(!index
            .known_configured_scan_roots
            .contains(&local_index_key(&new_optional_root)));
        let _ = fs::remove_dir_all(parent);
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
        let report = read_bounded_jsonl_lines(input.as_bytes(), cap, |value| {
            seen.push(value.clone());
        })
        .expect("bounded read");

        assert_eq!(seen.len(), 2, "only the two valid lines survive");
        assert_eq!(seen[0], json!({ "n": 1 }));
        assert_eq!(seen[1], json!({ "n": 2 }));
        // The dropped line never reaches the callback as a (truncated) value.
        assert!(seen.iter().all(|value| value.get("big").is_none()));
        assert_eq!(report.over_line_cap_count, 1);
        assert!(!report.complete());
    }

    #[test]
    fn bounded_reader_parses_normal_transcript_unchanged() {
        // A normal multi-line transcript (no line near the cap) parses exactly
        // as the old `lines()` loop would, including a final line without a
        // trailing newline.
        let input = "{\"type\":\"a\",\"v\":1}\n{\"type\":\"b\",\"v\":2}\n{\"type\":\"c\",\"v\":3}";
        let mut seen = Vec::new();
        let report = read_bounded_jsonl_lines(input.as_bytes(), MAX_JSONL_LINE_BYTES, |value| {
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
        assert!(report.complete());
    }

    #[test]
    fn bounded_reader_preserves_empty_and_malformed_line_semantics() {
        // Blank/whitespace lines and unparseable lines are skipped exactly as
        // before; a trailing newline does not emit a spurious empty value.
        let input = "\n   \n{\"ok\":true}\nnot json at all\n\n{\"ok\":false}\n";
        let mut seen = Vec::new();
        let report = read_bounded_jsonl_lines(input.as_bytes(), MAX_JSONL_LINE_BYTES, |value| {
            seen.push(value.clone());
        })
        .expect("bounded read");

        assert_eq!(seen, vec![json!({ "ok": true }), json!({ "ok": false })],);
        assert_eq!(report.malformed_json_line_count, 1);
        assert!(!report.complete());
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

        // The census sees the path, records the explicit oversized reason, and
        // never admits it to the bounded parse candidate set.
        assert_eq!(scan.discovered_file_count, 1);
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.oversized_file_count, 1);
        assert!(!scan.census_complete);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_traversal_uses_frozen_census_time_for_age_cutoff() {
        let root = temp_dir("bounded-frozen-age-cutoff");
        fs::write(
            root.join("session.jsonl"),
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":1,\"output\":1}}}\n",
        )
        .expect("write age-cutoff fixture");
        let future_boundary = (OffsetDateTime::now_utc() + time::Duration::days(365))
            .format(&Rfc3339)
            .expect("format future frozen boundary");
        let mut index = ScanIndex::default();

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            &future_boundary,
            1,
        )
        .expect("scan against frozen future boundary");

        assert!(scan.census_complete);
        assert_eq!(scan.discovered_file_count, 0);
        assert!(scan.snapshots.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn watcher_hint_cannot_widen_the_frozen_age_scope() {
        let root = temp_dir("bounded-watcher-age-cutoff");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":1,\"output\":1}}}\n",
        )
        .expect("write watcher age-cutoff fixture");
        let future_boundary = (OffsetDateTime::now_utc() + time::Duration::days(365))
            .format(&Rfc3339)
            .expect("format future frozen boundary");
        let mut index = ScanIndex::default();

        let scan = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            &future_boundary,
            1,
            1,
            true,
            None,
            None,
            std::slice::from_ref(&path),
            false,
        )
        .expect("scan out-of-scope watcher hint");

        assert!(scan.census_complete);
        assert!(scan.snapshots.is_empty());
        assert!(index.files.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn incomplete_jsonl_never_settles_the_scan_index() {
        let root = temp_dir("scan-incomplete-jsonl");
        let path = root.join("session-incomplete.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n",
                "this is not valid json\n"
            ),
        )
        .expect("write incomplete transcript");
        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("scan quarantines parse loss");
        assert_eq!(scan.malformed_json_line_count, 1);
        assert!(!scan.census_complete);
        assert_eq!(scan.scanned_session_count, 1);
        assert!(
            scan.snapshots.is_empty(),
            "a partial entity from a lossy file must never reach upload"
        );
        assert!(index.files.is_empty(), "incomplete file stays retryable");
        assert!(index.confirmed_empty_files.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_lossy_line_class_quarantines_the_whole_file_entity() {
        let session = "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n";
        let usage = "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n";
        let cases = ["invalid-utf8", "over-line-cap", "recognized-drop"];
        for case in cases {
            let root = temp_dir(case);
            let path = root.join("session.jsonl");
            let mut bytes = format!("{session}{usage}").into_bytes();
            match case {
                "invalid-utf8" => bytes.extend_from_slice(&[0xff, b'\n']),
                "over-line-cap" => {
                    bytes.extend_from_slice(b"{\"ignored\":\"");
                    bytes.extend(std::iter::repeat(b'x').take(MAX_JSONL_LINE_BYTES + 1));
                    bytes.extend_from_slice(b"\"}\n");
                }
                "recognized-drop" => bytes.extend_from_slice(
                    b"{\"type\":\"message_end\",\"message\":{\"usage\":{\"input\":\"invalid\"}}}\n",
                ),
                _ => unreachable!(),
            }
            fs::write(&path, bytes).expect("write lossy fixture");
            let mut index = ScanIndex::default();
            let scan = scan_source_roots_with_limit(
                SnapshotSource::Pi,
                std::slice::from_ref(&root),
                &mut index,
                "2026-07-22T08:02:00Z",
                BACKFILL_WINDOW_DAYS,
                MAX_BACKFILL_FILES_PER_SOURCE,
                true,
            )
            .expect("lossy file is isolated");
            assert!(!scan.census_complete, "{case}");
            assert!(scan.snapshots.is_empty(), "{case}");
            assert!(index.files.is_empty(), "{case}");
            match case {
                "invalid-utf8" => assert_eq!(scan.invalid_utf8_line_count, 1),
                "over-line-cap" => assert_eq!(scan.over_line_cap_count, 1),
                "recognized-drop" => assert_eq!(scan.recognized_usage_drop_count, 1),
                _ => unreachable!(),
            }
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn positive_usage_without_an_emittable_entity_stays_retryable() {
        let root = temp_dir("positive-usage-without-entity");
        fs::write(
            root.join("session.jsonl"),
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-1111-7000-9000-111111111111\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n"
            ),
        )
        .expect("write positive usage without an activity timestamp");
        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("lossy positive usage remains retryable");

        assert_eq!(scan.recognized_usage_drop_count, 1);
        assert!(!scan.census_complete);
        assert!(scan.snapshots.is_empty());
        assert!(index.files.is_empty());
        assert!(index.confirmed_empty_files.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lossy_file_has_no_finalization_side_effects_while_healthy_sibling_progresses() {
        let root = temp_dir("scan-lossy-with-healthy-sibling");
        let valid_session = |session_id: &str| {
            format!(
                concat!(
                    "{{\"type\":\"session\",\"session_id\":\"{}\",\"cwd\":\"/tmp/ottto\",\"timestamp\":\"2026-07-22T08:00:00Z\"}}\n",
                    "{{\"type\":\"message_end\",\"message\":{{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}}}}\n"
                ),
                session_id
            )
        };
        fs::write(
            root.join("a-healthy.jsonl"),
            valid_session("019e2700-1111-7000-9000-111111111111"),
        )
        .expect("write healthy sibling");
        fs::write(
            root.join("b-lossy.jsonl"),
            format!(
                "{}this is not valid json\n",
                valid_session("019e2700-2222-7000-9000-222222222222")
            ),
        )
        .expect("write lossy sibling");

        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("lossy sibling is isolated");
        assert!(!scan.census_complete);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(index.files.len(), 1);
        assert_eq!(index.file_snapshot_fingerprints.len(), 0);

        finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut index);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(index.files.len(), 1);
        assert_eq!(index.file_snapshot_fingerprints.len(), 1);
        assert_eq!(index.snapshot_activity_at.len(), 1);
        assert!(index
            .files
            .keys()
            .all(|path| path.ends_with("a-healthy.jsonl")));
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
            &[sessions_dir.clone(), archived_dir.clone()],
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
    fn codex_parser_forwards_top_level_originator_for_chatgpt_work() {
        // The unified ChatGPT desktop app writes its local "Work" sessions as
        // normal Codex rollout JSONLs with session_meta.originator ==
        // "codex_work_desktop". The daemon forwards that verbatim on the
        // forward-looking top-level `originator` field (the backend derives the
        // display sub-surface). The raw value must also stay on
        // `origin.originator` for the fallback path.
        let path = temp_file("codex-originator-work");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-21T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-work-codex\",\"source\":\"exec\",\"originator\":\"codex_work_desktop\",\"thread_source\":\"user\"}}\n",
                "{\"timestamp\":\"2026-07-21T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":5,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(&path, "2026-07-21T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        assert_eq!(item.originator.as_deref(), Some("codex_work_desktop"));
        assert_eq!(
            item.origin.as_ref().and_then(|o| o.originator.as_deref()),
            Some("codex_work_desktop")
        );
        // Serializes as a top-level `originator` string (what the backend reads).
        let wire = serde_json::to_value(&item).expect("serialize");
        assert_eq!(wire["originator"], serde_json::json!("codex_work_desktop"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_omits_originator_when_session_meta_lacks_it() {
        // Backward compat: a Codex session_meta with no `originator` yields None,
        // and the field is skipped on the wire (additive/optional).
        let path = temp_file("codex-originator-absent");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-21T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-noorig-codex\",\"source\":\"cli\",\"thread_source\":\"user\"}}\n",
                "{\"timestamp\":\"2026-07-21T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":5,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(&path, "2026-07-21T10:04:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        assert_eq!(item.originator, None);
        let wire = serde_json::to_value(&item).expect("serialize");
        assert!(
            wire.get("originator").is_none(),
            "None originator must be skipped on the wire"
        );

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
        let mut automation = parse_codex_jsonl_file(
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
        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut automation),
            SnapshotUploadPolicy {
                session_attribution_enabled: true,
                ..SnapshotUploadPolicy::default()
            },
        );
        let automation_wire = serde_json::to_value(&automation).expect("serialize automation");
        assert!(automation_wire["attribution_facts"]
            .as_array()
            .is_some_and(|facts| facts.iter().any(|fact| {
                fact["field"] == "origin_kind" && fact["value"] == "provider_scheduled_task"
            })));
        let mut unattributed = automation.clone();
        let attributed_fingerprint = unattributed.snapshot_fingerprint.clone();
        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut unattributed),
            SnapshotUploadPolicy::default(),
        );
        let unattributed_wire = serde_json::to_value(&unattributed).expect("serialize empty facts");
        assert!(unattributed_wire.get("attribution_facts").is_none());
        assert_ne!(unattributed.snapshot_fingerprint, attributed_fingerprint);

        let subagent_path = temp_file("codex-subagent-attribution");
        fs::write(
            &subagent_path,
            concat!(
                "{\"timestamp\":\"2026-07-19T11:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"subagent-session\",\"source\":{\"subagent\":{\"thread_spawn\":{\"parent_thread_id\":\"parent-session\",\"depth\":1}}},\"thread_source\":\"subagent\"}}\n",
                "{\"timestamp\":\"2026-07-19T11:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":8,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.6-sol\"}}}\n"
            ),
        )
        .expect("write subagent fixture");
        let mut subagent = parse_codex_jsonl_file(
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
        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut subagent),
            SnapshotUploadPolicy {
                session_attribution_enabled: true,
                ..SnapshotUploadPolicy::default()
            },
        );
        let subagent_wire = serde_json::to_value(&subagent).expect("serialize subagent");
        assert!(subagent_wire["attribution_facts"]
            .as_array()
            .is_some_and(|facts| facts
                .iter()
                .any(|fact| { fact["field"] == "origin_kind" && fact["value"] == "subagent" })));
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
    fn codex_parser_gates_bounded_template_labels_on_existing_title_consent() {
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

        let mut item = parse_codex_jsonl_file_with_title_metadata_and_attribution(
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
        assert!(local_facts.contains(scheduled_prompt));
        assert!(!local_facts.contains(path.to_string_lossy().as_ref()));

        let mut labels_disabled = item.clone();
        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut labels_disabled),
            SnapshotUploadPolicy {
                session_attribution_enabled: true,
                ..SnapshotUploadPolicy::default()
            },
        );
        let disabled_wire = serde_json::to_value(&labels_disabled).expect("disabled snapshot wire");
        let disabled_facts = serde_json::to_string(&disabled_wire["attribution_facts"])
            .expect("disabled wire attribution facts");
        assert!(disabled_wire["attribution_facts"].is_array());
        assert!(!disabled_facts.contains("display_label"));
        assert!(!disabled_facts.contains(scheduled_prompt));

        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut item),
            SnapshotUploadPolicy {
                session_attribution_enabled: true,
                session_attribution_labels_enabled: true,
                ..SnapshotUploadPolicy::default()
            },
        );
        let enabled_wire = serde_json::to_value(&item).expect("enabled snapshot wire");
        let enabled_facts = serde_json::to_string(&enabled_wire["attribution_facts"])
            .expect("enabled wire attribution facts");
        assert!(enabled_facts.contains(scheduled_prompt));
        assert!(enabled_facts.contains("prompt_prefix"));
        assert!(!enabled_facts.contains(path.to_string_lossy().as_ref()));

        let mut title_opted_out = item.clone();
        apply_upload_policy(
            SnapshotSource::Codex,
            std::slice::from_mut(&mut title_opted_out),
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                session_attribution_enabled: true,
                session_attribution_labels_enabled: true,
                ..SnapshotUploadPolicy::default()
            },
        );
        let opted_out_wire = serde_json::to_string(&title_opted_out).expect("opted out wire");
        assert!(!opted_out_wire.contains("display_label"));
        assert!(!opted_out_wire.contains(scheduled_prompt));

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
    fn malformed_codex_session_index_discards_partial_titles_without_blocking_usage() {
        let codex_dir = temp_dir("codex-session-index-partial");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        fs::write(
            sessions_dir.join(
                "rollout-2026-05-14T10-00-00-019e253c-2222-7000-9000-bbbbbbbbbbbb.jsonl",
            ),
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":20,\"output_tokens\":5},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write usage fixture");
        fs::write(
            codex_dir.join("session_index.jsonl"),
            concat!(
                "{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\",\"thread_name\":\"Must not partially settle\"}\n",
                "{not valid json}\n"
            ),
        )
        .expect("write partial sidecar");

        let mut index = ScanIndex {
            upload_context_fingerprint: Some("prior-context".to_string()),
            ..ScanIndex::default()
        };
        index.activate_upload_context("next-context".to_string());
        let mut scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("malformed sidecar is quarantined without fencing usage");
        assert!(!scan.sidecar_census_complete);
        assert!(!scan.census_complete);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(scan.snapshots[0].input_tokens, 20);
        assert_ne!(
            scan.snapshots[0].session_display_name.as_deref(),
            Some("Must not partially settle")
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        assert_eq!(
            index.upload_context_fingerprint.as_deref(),
            Some("prior-context")
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
            &[sessions_dir.clone(), archived_dir.clone()],
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
        assert_eq!(
            index
                .codex_state_only_snapshot_fingerprints
                .get(&state_only.source_session_id),
            Some(&state_only.snapshot_fingerprint),
            "durable state-only witness must use the final emitted fingerprint"
        );

        let no_titles_context = "policy-no-titles".to_string();
        index.activate_upload_context(no_titles_context.clone());
        let mut suppressed = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &[sessions_dir.clone(), archived_dir.clone()],
            &mut index,
            "2026-05-14T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("privacy suppression scan");
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut suppressed.snapshots,
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                ..SnapshotUploadPolicy::default()
            },
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut suppressed, &mut index);
        let suppressed_state = suppressed
            .snapshots
            .iter()
            .find(|snapshot| snapshot.provenance.collector == "codex_state_sqlite")
            .expect("state-only privacy correction");
        assert!(suppressed_state.session_display_name.is_none());
        assert_eq!(
            index
                .codex_state_only_snapshot_fingerprints
                .get(&suppressed_state.source_session_id),
            Some(&suppressed_state.snapshot_fingerprint)
        );

        index.activate_upload_context("policy-titles-restored".to_string());
        let mut restored = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &[sessions_dir, archived_dir],
            &mut index,
            "2026-05-14T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("privacy restoration scan");
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut restored.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut restored, &mut index);
        assert!(restored.snapshots.iter().any(|snapshot| {
            snapshot.provenance.collector == "codex_state_sqlite"
                && snapshot.session_display_name.as_deref() == Some("Archived State Only")
        }));

        index.activate_upload_context("account-cutoff".to_string());
        let mut cutoff = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &[
                codex_dir.join("sessions"),
                codex_dir.join("archived_sessions"),
            ],
            &mut index,
            "2026-05-14T10:07:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("account cutoff scan");
        cutoff.snapshots.clear();
        finalize_scan_after_policy(SnapshotSource::Codex, &mut cutoff, &mut index);
        assert!(
            index.codex_state_only_snapshot_fingerprints.is_empty(),
            "a cutoff-filtered state-only entity must not remain in the manifest index"
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn unreadable_codex_state_census_preserves_prior_durable_state_only_entities() {
        let codex_dir = temp_dir("codex-state-census-failure");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        fs::write(codex_dir.join("state_5.sqlite"), b"not a sqlite database")
            .expect("write corrupt state fixture");

        let session_id = "019e253c-8888-7000-9000-bbbbbbbbbbbb";
        let fingerprint = "a".repeat(64);
        let activity = Some("2026-05-14T10:03:00Z".to_string());
        let mut index = ScanIndex {
            upload_context_fingerprint: Some("prior-context".to_string()),
            codex_state_only_snapshot_fingerprints: BTreeMap::from([(
                session_id.to_string(),
                fingerprint.clone(),
            )]),
            snapshot_activity_at: BTreeMap::from([(fingerprint.clone(), activity.clone())]),
            ..ScanIndex::default()
        };
        index.activate_upload_context("next-context".to_string());

        let mut scan = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("state DB failure is source-local evidence, not a process failure");
        assert!(!scan.state_census_complete);
        assert!(!scan.census_complete);
        assert!(scan.snapshots.is_empty());

        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        assert_eq!(
            index.codex_state_only_snapshot_fingerprints,
            BTreeMap::from([(session_id.to_string(), fingerprint.clone())])
        );
        assert_eq!(
            index.snapshot_activity_at.get(&fingerprint),
            Some(&activity)
        );
        assert_eq!(
            index.upload_context_fingerprint.as_deref(),
            Some("prior-context"),
            "an incomplete state census cannot advance the policy/cutoff epoch"
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
    fn codex_state_only_replaces_a_deleted_rollout_in_the_same_complete_census() {
        let codex_dir = temp_dir("codex-state-deleted-rollout");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        let session_id = "019e253c-bbbb-7000-9000-ffffffffffff";
        let rollout = sessions_dir.join(format!("rollout-2026-05-14T10-00-00-{session_id}.jsonl"));
        fs::write(
            &rollout,
            format!(
                "{{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session_id}\"}}}}\n{{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":50,\"output_tokens\":9}},\"model\":\"gpt-5.5\"}}}}}}\n"
            ),
        )
        .expect("write rollout");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(CODEX_THREADS_DDL, [])
            .expect("create threads");
        connection
            .execute(
                CODEX_THREADS_INSERT,
                (
                    session_id,
                    "Deleted Rollout",
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
        let mut index = ScanIndex::default();

        let first = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions_dir),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan file-backed session");
        assert!(first.census_complete);
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first.snapshots[0].unattributed_total_tokens, 0);

        fs::remove_file(&rollout).expect("remove rollout while state row remains");
        let replacement = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions_dir),
            &mut index,
            "2026-05-14T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("reconcile deletion and state fallback together");

        assert!(replacement.census_complete);
        assert!(index.files.is_empty());
        let state_only = replacement
            .snapshots
            .iter()
            .find(|snapshot| snapshot.source_session_id == session_id)
            .expect("same complete generation emits the state-only replacement");
        assert_eq!(state_only.unattributed_total_tokens, 59);
        assert_eq!(
            state_only.provenance.input_token_scope.as_deref(),
            Some("total_only")
        );
        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_state_only_preserved_when_rollout_parses_to_no_usage() {
        // Regression guard: a rollout that exists but yields zero usage rows
        // (e.g. only session_meta, or a legacy/unknown token payload) is still
        // recorded in the scan index, but it produced NO split snapshot. Such a
        // thread must surface its tokens as a state-only "Other" once, suppress
        // identical observations after acknowledgement, and emit again when
        // the state-backed semantic payload really changes.
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

        // Incremental re-scan: the state-only snapshot is evaluated but its
        // already-acknowledged semantic identity is not returned for upload.
        let second = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T11:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second scan");
        assert!(second.snapshots.is_empty());
        assert_eq!(second.scanned_session_count, 1);
        assert_eq!(second.semantic_noop_count, 1);
        assert_eq!(index.codex_state_only_snapshot_fingerprints.len(), 1);

        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("reopen sqlite");
        connection
            .execute(
                concat!(
                    "UPDATE threads SET tokens_used = ?1, updated_at = ?2, updated_at_ms = ?3 ",
                    "WHERE id = ?4",
                ),
                (
                    4_322_i64,
                    1_777_777_200_i64,
                    1_777_777_200_000_i64,
                    "019e253c-aaaa-7000-9000-eeeeeeeeeeee",
                ),
            )
            .expect("update semantic state");
        drop(connection);

        let changed = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T12:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("changed scan");
        let changed_state = changed
            .snapshots
            .iter()
            .find(|snapshot| snapshot.source_session_id == "019e253c-aaaa-7000-9000-eeeeeeeeeeee")
            .expect("changed state-only snapshot");
        assert_eq!(changed_state.unattributed_total_tokens, 4_322);
        assert_eq!(changed.semantic_noop_count, 0);

        let settled = scan_source_roots(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            "2026-05-14T13:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert!(settled.snapshots.is_empty());
        assert_eq!(settled.semantic_noop_count, 1);

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn scan_checkpoints_pi_zero_parsed_file_until_it_changes() {
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
        assert_eq!(first.scanned_file_count, 1);
        assert_eq!(first.scanned_session_count, 0);
        assert_eq!(first.zero_snapshot_usage_evidence_count, 0);

        let unchanged_empty = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("unchanged empty scan");
        assert_eq!(unchanged_empty.snapshots.len(), 0);
        assert_eq!(unchanged_empty.scanned_file_count, 0);
        assert_eq!(unchanged_empty.scanned_session_count, 0);
        assert_eq!(unchanged_empty.zero_snapshot_usage_evidence_count, 0);

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
    fn scan_checkpoints_codex_zero_parsed_file_until_it_changes() {
        let root = temp_dir("codex-retry-zero-parsed");
        let path =
            root.join("rollout-2026-05-14T10-00-00-019e2700-3333-7000-9000-333333333333.jsonl");
        let session_meta = "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-3333-7000-9000-333333333333\"}}\n";
        fs::write(&path, session_meta).expect("write empty usage fixture");

        let mut index = ScanIndex::default();
        let first_empty = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first empty scan");
        assert_eq!(first_empty.snapshots.len(), 0);
        assert_eq!(first_empty.scanned_file_count, 1);
        assert_eq!(first_empty.scanned_session_count, 0);

        let settled_empty = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled empty scan");
        assert_eq!(settled_empty.snapshots.len(), 0);
        assert_eq!(settled_empty.scanned_file_count, 0);
        assert_eq!(settled_empty.scanned_session_count, 0);

        fs::write(
            &path,
            format!(
                "{session_meta}{}",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write usage fixture");

        let populated = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("populated scan");
        assert_eq!(populated.snapshots.len(), 1);
        assert_eq!(populated.scanned_session_count, 1);

        let settled = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:07:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert_eq!(settled.snapshots.len(), 0);
        assert_eq!(settled.scanned_file_count, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn zero_snapshot_usage_evidence_stays_visible_across_bounded_retries() {
        let root = temp_dir("pi-zero-snapshot-usage-evidence");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"assistant_v2\",\"message\":{\"billing\":{\"usage\":{\"input\":12,\"output\":4}}}}\n",
            ),
        )
        .expect("write schema-drift fixture");
        let mut index = ScanIndex::default();

        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first schema-drift scan");
        assert_eq!(first.scanned_file_count, 1);
        assert_eq!(first.scanned_session_count, 0);
        assert_eq!(first.zero_snapshot_usage_evidence_count, 1);

        let retry = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("bounded schema-drift retry");
        assert_eq!(retry.scanned_file_count, 1);
        assert_eq!(retry.scanned_session_count, 0);
        assert_eq!(retry.zero_snapshot_usage_evidence_count, 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn usage_evidence_is_structural_and_ignores_metadata_limits_and_budgets() {
        let positive = [
            serde_json::json!({"token_count": {"info": {"total_token_usage": {"input_tokens": 12}}}}),
            serde_json::json!({"message": {"usage": {"output_tokens": 4}}}),
            serde_json::json!({"message": {"usage": {"input": 2, "cost": {"total": 0.01}}}}),
            serde_json::json!({"unknown": {"nested": {"usage": {"future": {"request_count": 1}}}}}),
            serde_json::json!({"provider_response": {"content": {"billing": {"usage": {"input_tokens": 7}}}}}),
            serde_json::json!({"message": {"role": "assistant", "content": {"example": true}, "usage": {"output_tokens": 5}}}),
        ];
        for value in positive {
            assert!(
                json_has_positive_usage_evidence(&value),
                "recognized consumption must stay visible"
            );
        }

        let negative = [
            serde_json::json!({"usage_version": 25}),
            serde_json::json!({"usage_limit": 1000}),
            serde_json::json!({"usage": {"version": 25, "limits": {"input_tokens": 1000}}}),
            serde_json::json!({"usage": {"budget": {"usd": 500}, "timestamp": 1784707201000_i64}}),
            serde_json::json!({"usage": {"future": {"opaque_positive": 99}}}),
            serde_json::json!({"billing_usage": {"quota": {"requests": 100}}}),
            serde_json::json!({"message": {"role": "user", "content": {"usage": {"input_tokens": 12}}}}),
            serde_json::json!({"message": {"role": "user", "usage": {"input_tokens": 12}}}),
            serde_json::json!({"message": {"role": "assistant", "content": {"usage": {"output_tokens": 4}}}}),
            serde_json::json!({"type": "tool_result", "payload": {"usage": {"output_tokens": 4}}}),
        ];
        for value in negative {
            assert!(
                !json_has_positive_usage_evidence(&value),
                "metadata and unknown numerics must not page"
            );
        }
    }

    #[test]
    fn authored_usage_shaped_content_does_not_hold_empty_transcript_red() {
        let root = temp_dir("pi-authored-usage-content");
        fs::write(
            root.join("session.jsonl"),
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"example\"},{\"type\":\"tool_result\",\"content\":{\"usage\":{\"input_tokens\":12}}}]}}\n",
            ),
        )
        .expect("write authored-content fixture");
        let mut index = ScanIndex::default();

        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan authored-content fixture");

        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.zero_snapshot_usage_evidence_count, 0);
        assert!(scan.census_complete);
        assert_eq!(scan.zero_snapshot_confirmed_count, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_parser_quarantines_hostile_partial_timestamps_until_corrected() {
        let root = temp_dir("pi-hostile-timestamps");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"bad-max\",\"model\":\"gpt-5.4\",\"timestamp\":9223372036854775807,\"usage\":{\"input\":100,\"output\":10}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"bad-min\",\"model\":\"gpt-5.4\",\"timestamp\":-9223372036854775808,\"usage\":{\"input\":200,\"output\":20}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"bad-text\",\"model\":\"gpt-5.4\",\"timestamp\":\"not-a-time\",\"usage\":{\"input\":300,\"output\":30}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"healthy\",\"model\":\"gpt-5.4\",\"timestamp\":\"1784707201000\",\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write hostile timestamp fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");
        assert!(scan.snapshots.is_empty());
        assert!(!scan.census_complete);
        assert_eq!(scan.dropped_usage_record_count, 3);
        assert_eq!(bounded_rfc3339_millis(i64::MIN), None);
        assert_eq!(bounded_rfc3339_millis(i64::MAX), None);

        let mixed_settled = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:05:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled mixed scan");
        assert_eq!(mixed_settled.scanned_file_count, 0);
        assert_eq!(mixed_settled.dropped_usage_record_count, 3);

        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"bad-only\",\"model\":\"gpt-5.4\",\"timestamp\":\"not-a-time\",\"usage\":{\"input\":300,\"output\":30}}}\n",
            ),
        )
        .expect("rewrite with nonzero usage behind a malformed timestamp");
        let regressed = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan malformed-only usage");
        assert!(regressed.snapshots.is_empty());
        assert_eq!(regressed.zero_snapshot_usage_evidence_count, 1);
        assert_eq!(regressed.dropped_usage_record_count, 1);
        assert_eq!(
            index
                .manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS)
                .entity_count,
            0,
            "the incomplete file never advances the durable manifest"
        );

        let settled = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:07:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled malformed-usage checkpoint");
        assert_eq!(settled.scanned_file_count, 0);
        assert_eq!(settled.zero_snapshot_usage_evidence_count, 1);
        assert_eq!(settled.dropped_usage_record_count, 1);

        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"responseId\":\"corrected\",\"model\":\"gpt-5.4\",\"timestamp\":\"1784707201000\",\"usage\":{\"input\":30,\"output\":3}}}\n",
            ),
        )
        .expect("correct malformed timestamp");
        let corrected = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:08:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("corrected scan");
        assert_eq!(corrected.snapshots.len(), 1);
        assert_eq!(corrected.zero_snapshot_usage_evidence_count, 0);
        assert_eq!(corrected.dropped_usage_record_count, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_invalid_provider_timestamp_does_not_fall_back_to_envelope_time() {
        let root = temp_dir("pi-invalid-provider-valid-envelope");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T09:00:00Z\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"bad-provider-time\",\"timestamp\":\"not-a-time\",\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write invalid provider timestamp fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T09:01:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan invalid provider timestamp fixture");

        assert!(scan.snapshots.is_empty());
        assert!(!scan.census_complete);
        assert_eq!(scan.dropped_usage_record_count, 1);
        assert!(index.files.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_and_claude_partial_timestamp_loss_stays_visible() {
        let codex_root = temp_dir("codex-partial-timestamp-loss");
        let codex_path = codex_root.join("rollout-019e253c-6666-7000-9000-aaaaaaaaaaaa.jsonl");
        fs::write(
            &codex_path,
            concat!(
                "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"not-a-time\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":2},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-07-22T08:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":15,\"output_tokens\":3},\"model\":\"gpt-5.5\"}}}\n",
            ),
        )
        .expect("write Codex partial-loss fixture");
        let mut codex_index = ScanIndex::default();
        let codex = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&codex_root),
            &mut codex_index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan Codex partial-loss fixture");
        assert!(codex.snapshots.is_empty());
        assert!(!codex.census_complete);
        assert_eq!(codex.dropped_usage_record_count, 1);

        let claude_root = temp_dir("claude-partial-timestamp-loss");
        let claude_path = claude_root.join("019e2700-4444-7000-9000-444444444444.jsonl");
        fs::write(
            &claude_path,
            concat!(
                "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"sessionId\":\"019e2700-4444-7000-9000-444444444444\",\"type\":\"system\"}\n",
                "{\"timestamp\":\"not-a-time\",\"sessionId\":\"019e2700-4444-7000-9000-444444444444\",\"type\":\"assistant\",\"requestId\":\"bad\",\"message\":{\"id\":\"bad\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}}\n",
                "{\"timestamp\":\"2026-07-22T08:01:00Z\",\"sessionId\":\"019e2700-4444-7000-9000-444444444444\",\"type\":\"assistant\",\"requestId\":\"good\",\"message\":{\"id\":\"good\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n",
            ),
        )
        .expect("write Claude partial-loss fixture");
        let mut claude_index = ScanIndex::default();
        let claude = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&claude_root),
            &mut claude_index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan Claude partial-loss fixture");
        assert!(claude.snapshots.is_empty());
        assert!(!claude.census_complete);
        assert_eq!(claude.dropped_usage_record_count, 1);

        let _ = fs::remove_dir_all(codex_root);
        let _ = fs::remove_dir_all(claude_root);
    }

    #[test]
    fn scan_checkpoints_claude_zero_parsed_file_until_it_changes() {
        let root = temp_dir("claude-retry-zero-parsed");
        let path = root.join("019e2700-4444-7000-9000-444444444444.jsonl");
        let session_header = "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"sessionId\":\"019e2700-4444-7000-9000-444444444444\",\"type\":\"system\"}\n";
        fs::write(&path, session_header).expect("write empty usage fixture");

        let mut index = ScanIndex::default();
        let first_empty = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first empty scan");
        assert_eq!(first_empty.snapshots.len(), 0);
        assert_eq!(first_empty.scanned_file_count, 1);
        assert_eq!(first_empty.scanned_session_count, 0);

        let settled_empty = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:05:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled empty scan");
        assert_eq!(settled_empty.snapshots.len(), 0);
        assert_eq!(settled_empty.scanned_file_count, 0);
        assert_eq!(settled_empty.scanned_session_count, 0);

        fs::write(
            &path,
            format!(
                "{session_header}{}",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"sessionId\":\"019e2700-4444-7000-9000-444444444444\",\"type\":\"assistant\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n"
            ),
        )
        .expect("write usage fixture");

        let populated = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("populated scan");
        assert_eq!(populated.snapshots.len(), 1);
        assert_eq!(populated.scanned_session_count, 1);

        let settled = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:07:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert_eq!(settled.snapshots.len(), 0);
        assert_eq!(settled.scanned_file_count, 0);

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
            modified_unix_nanos: None,
            source_file_fingerprint: v6_key.clone(),
            last_snapshot_fingerprint: None,
            scan_identity_version: None,
        };

        let mut index = ScanIndex {
            files: std::collections::BTreeMap::from([(
                path.to_string_lossy().to_string(),
                legacy_entry,
            )]),
            ..ScanIndex::default()
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
        assert_eq!(entry.source_file_fingerprint.len(), 64);
        assert!(entry
            .source_file_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            entry.scan_identity_version.as_deref(),
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
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
                "{\"timestamp\":\"2026-05-14T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Investigate the upload timeout\"}}\n",
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
        assert_eq!(
            noisy_item.session_display_name.as_deref(),
            Some("Investigate the upload timeout")
        );
        assert_eq!(
            noisy_item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let continuation_path = temp_file("codex-continuation-first-prompt");
        fs::write(
            &continuation_path,
            concat!(
                "{\"timestamp\":\"2026-07-29T08:39:04Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019fac62-33a0-7750-a4fc-9a7f9621993c\"}}\n",
                "{\"timestamp\":\"2026-07-29T08:40:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Continue the SAME Phase-2 PR 2.14 Codex session and worktree.\"}}\n",
                "{\"timestamp\":\"2026-07-29T08:41:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.6\"}}}\n"
            ),
        )
        .expect("write continuation fixture");
        let continuation_item = parse_codex_jsonl_file(
            &continuation_path,
            "2026-07-29T08:42:00Z",
            "continuation-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(continuation_item.session_display_name, None);
        assert_eq!(continuation_item.session_display_name_source, None);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(noisy_path);
        let _ = fs::remove_file(continuation_path);
    }

    #[test]
    fn codex_agent_role_prompt_has_a_bounded_title() {
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are the LANDING OWNER AGENT for ottto-ai/coding-agents-observability — \
                 coordinate the queue and keep the full operating contract private."
                    .to_string()
            )
            .as_deref(),
            Some("Landing owner agent")
        );
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are a PR REPAIR AGENT for ottto-ai/coding-agents-observability.".to_string()
            )
            .as_deref(),
            Some("PR repair agent")
        );
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are a Phase-2 projector implementation worker (GPT-5.6 Sol via Codex CLI)."
                    .to_string()
            )
            .as_deref(),
            Some("Phase-2 projector implementation worker")
        );
    }

    #[test]
    fn codex_agent_role_prompt_rejects_unbounded_or_path_like_roles() {
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are the extraordinarily detailed multi-stage cross-repository production \
                 incident response coordination agent for this task."
                    .to_string()
            ),
            None
        );
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are the /root repair agent for this task.".to_string()
            ),
            None
        );
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::Codex,
                "You are the diligent agentless helper.".to_string()
            ),
            None
        );
        assert_eq!(
            first_prompt_display_title(
                SnapshotSource::ClaudeCode,
                "You are the LANDING OWNER AGENT for this task.".to_string()
            ),
            None
        );
    }

    #[test]
    fn first_prompt_material_skips_injected_scaffolding() {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.set_first_prompt_title(Some(
            "# AGENTS.md instructions for /repo\n\
             <INSTRUCTIONS>Shared setup</INSTRUCTIONS>\n\
             <environment_context><cwd>/repo</cwd></environment_context>"
                .to_string(),
        ));
        accumulator.set_first_prompt_title(Some("Investigate the upload timeout".to_string()));

        assert_eq!(
            accumulator.first_prompt_material.as_deref(),
            Some("Investigate the upload timeout")
        );
        assert_eq!(
            accumulator.first_prompt_title.as_deref(),
            Some("Investigate the upload timeout")
        );
    }

    #[test]
    fn first_prompt_material_keeps_human_marker_mentions() {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.set_first_prompt_title(Some(
            "Update the AGENTS.md instructions and parse the current date: field".to_string(),
        ));

        assert_eq!(
            accumulator.first_prompt_material.as_deref(),
            Some("Update the AGENTS.md instructions and parse the current date: field")
        );
    }

    #[test]
    fn first_prompt_material_keeps_task_after_injected_prefix() {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.set_first_prompt_title(Some(
            "<recommended_plugins>Plugins</recommended_plugins>\n\
             # AGENTS.md instructions for /repo\n\
             <INSTRUCTIONS>Shared setup</INSTRUCTIONS>\n\
             <environment_context><cwd>/repo</cwd></environment_context>\n\
             Explain how this XML is parsed"
                .to_string(),
        ));

        assert_eq!(
            accumulator.first_prompt_material.as_deref(),
            Some("Explain how this XML is parsed")
        );
        assert_eq!(
            accumulator.first_prompt_title.as_deref(),
            Some("Explain how this XML is parsed")
        );
    }

    #[test]
    fn codex_response_item_skips_separate_injected_content_elements() {
        let scaffold_message: Value = serde_json::from_str(concat!(
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[",
            "{\"type\":\"input_text\",\"text\":\"<recommended_plugins>Here is a deliberately long injected plugin catalog whose closing tag falls beyond the old title normalization boundary. Plugin one. Plugin two. Plugin three. Plugin four. Plugin five. Plugin six. Plugin seven. Plugin eight. Plugin nine. Plugin ten. Plugin eleven. Plugin twelve. Plugin thirteen. Plugin fourteen. Plugin fifteen.</recommended_plugins>\"},",
            "{\"type\":\"input_text\",\"text\":\"# AGENTS.md instructions for /repo\\n<INSTRUCTIONS>Shared setup that must not become prompt material.</INSTRUCTIONS>\"},",
            "{\"type\":\"input_text\",\"text\":\"<environment_context><cwd>/repo</cwd></environment_context>\"}]}}"
        ))
        .expect("parse scaffold message");
        assert_eq!(codex_first_user_prompt(&scaffold_message), None);

        let path = temp_file("codex-response-item-scaffolding");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-29T08:39:04Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019facf4-d985-7081-bb16-5c4af8e8d44b\"}}\n",
                "{\"timestamp\":\"2026-07-29T08:39:05Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[",
                "{\"type\":\"input_text\",\"text\":\"<recommended_plugins>Here is a deliberately long injected plugin catalog whose closing tag falls beyond the old title normalization boundary. Plugin one. Plugin two. Plugin three. Plugin four. Plugin five. Plugin six. Plugin seven. Plugin eight. Plugin nine. Plugin ten. Plugin eleven. Plugin twelve. Plugin thirteen. Plugin fourteen. Plugin fifteen.</recommended_plugins>\"},",
                "{\"type\":\"input_text\",\"text\":\"# AGENTS.md instructions for /repo\\n<INSTRUCTIONS>Shared setup that must not become prompt material.</INSTRUCTIONS>\"},",
                "{\"type\":\"input_text\",\"text\":\"<environment_context><cwd>/repo</cwd></environment_context>\"}]}}\n",
                "{\"timestamp\":\"2026-07-29T08:40:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Continue Stage 3 from the verified checkpoint.\"}]}}\n",
                "{\"timestamp\":\"2026-07-29T08:41:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.6\"}}}\n"
            ),
        )
        .expect("write response-item fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-07-29T08:42:00Z",
            "response-item-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Continue Stage 3 from the verified checkpoint.")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let _ = fs::remove_file(path);
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
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
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
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
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
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
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
            compaction_timestamps: Vec::new(),
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
            originator: None,
            attribution_facts: Vec::new(),
        };
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
        item
    }

    #[test]
    fn semantic_fingerprint_excludes_observation_and_parser_metadata() {
        let mut item = sample_session_artifact_item();
        let origin = SnapshotOrigin {
            thread_source: Some("automation".to_string()),
            ..Default::default()
        };
        item.origin = Some(origin.clone());
        item.attribution_facts = crate::session_attribution::direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            &item.source_session_id,
            "2026-07-22T08:00:00Z",
            "codex_jsonl:v22",
        );
        let baseline = snapshot_fingerprint(SnapshotSource::Codex, &item);

        let mut later_observation = item.clone();
        later_observation.collected_at = "2026-07-22T09:00:00Z".to_string();
        later_observation.source_file_fingerprint = Some("different-local-file-fp".to_string());
        later_observation.provenance.collector = "codex_jsonl:v23-build".to_string();
        for fact in &mut later_observation.attribution_facts {
            fact.evidence.observed_at = "2026-07-22T09:00:00Z".to_string();
            fact.evidence.source_version = "codex_jsonl:v23".to_string();
            fact.evidence.evidence_ref = "sha256:lineage-only-change".to_string();
        }
        assert_eq!(
            snapshot_fingerprint(SnapshotSource::Codex, &later_observation),
            baseline
        );
    }

    #[test]
    fn semantic_fingerprint_tracks_real_usage_lifecycle_and_latency_changes() {
        let item = sample_session_artifact_item();
        let baseline = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);

        let mut usage = item.clone();
        usage.input_tokens += 1;
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &usage),
            baseline
        );

        let mut lifecycle = item.clone();
        lifecycle.status = "active".to_string();
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &lifecycle),
            baseline
        );

        let mut latency = item;
        latency.max_duration_ms = Some(42);
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &latency),
            baseline
        );
    }

    #[test]
    fn semantic_fingerprint_tracks_selector_evidence_source() {
        let path = temp_file("selector-evidence-semantic");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-eeeeeeeeeeee\"}}\n",
                "{\"timestamp\":\"2026-07-22T08:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"service_tier\":\"fast\",\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let item = parse_codex_jsonl_file(&path, "2026-07-22T08:02:00Z", "file-fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        let baseline = snapshot_fingerprint(SnapshotSource::Codex, &item);
        let mut changed_source = item;
        changed_source.model_usage[0].selector_sources.insert(
            "service_tier".to_string(),
            "different_evidence_source".to_string(),
        );
        changed_source.usage_buckets[0].model_usage[0]
            .selector_sources
            .insert(
                "service_tier".to_string(),
                "different_evidence_source".to_string(),
            );
        assert_ne!(
            snapshot_fingerprint(SnapshotSource::Codex, &changed_source),
            baseline
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_title_changes_affect_only_that_sessions_sidecar_identity() {
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

        insert_codex_sidecar_title(
            &mut first.titles,
            "unrelated-session".to_string(),
            Some("Unrelated title".to_string()),
            "session_index",
            true,
        );
        insert_codex_sidecar_title(
            &mut second.titles,
            "unrelated-session".to_string(),
            Some("Unrelated title".to_string()),
            "session_index",
            true,
        );
        assert_ne!(
            first.session_sidecar_fingerprint("019e253c-6666-7000-9000-ffffffffffff"),
            second.session_sidecar_fingerprint("019e253c-6666-7000-9000-ffffffffffff")
        );
        assert_eq!(
            first.session_sidecar_fingerprint("unrelated-session"),
            second.session_sidecar_fingerprint("unrelated-session")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn scan_identity_is_decoupled_from_parser_build_version() {
        let path = Path::new("/redacted/session.jsonl");
        let before_parser_upgrade = scan_file_fingerprint_with_context(
            path,
            100,
            1_777_777_777_123_456_789,
            SnapshotSource::Codex.scan_identity_version(),
            "session-sidecar",
        );
        let after_parser_upgrade = scan_file_fingerprint_with_context(
            path,
            100,
            1_777_777_777_123_456_789,
            CODEX_SCAN_IDENTITY_VERSION,
            "session-sidecar",
        );

        assert_eq!(before_parser_upgrade, after_parser_upgrade);
        assert_ne!(
            CODEX_SNAPSHOT_PARSER_VERSION,
            "codex_jsonl:future-parser-build"
        );
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
    fn codex_parser_does_not_apply_mutable_config_defaults_to_history() {
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
        assert!(selector.is_empty());
        assert!(item.model_usage[0].selector_sources.is_empty());

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

    /// Build the ordered Claude Code settings chain for a fake home directory.
    fn claude_settings_chain(claude_dir: &Path, managed: &Path) -> Vec<(String, PathBuf)> {
        vec![
            (
                "claude_code.settings".to_string(),
                claude_dir.join("settings.json"),
            ),
            (
                "claude_code.settings_local".to_string(),
                claude_dir.join("settings.local.json"),
            ),
            (
                "claude_code.managed_settings".to_string(),
                managed.to_path_buf(),
            ),
        ]
    }

    fn load_claude_defaults(paths: &[(String, PathBuf)]) -> ClaudeConfigDefaultsOutcome {
        let scopes: Vec<ClaudeSettingsScope<'_>> = paths
            .iter()
            .map(|(label, path)| ClaudeSettingsScope {
                label: label.as_str(),
                path: path.as_path(),
            })
            .collect();
        load_claude_settings_defaults(&scopes)
    }

    #[test]
    fn claude_settings_defaults_capture_model_permission_mode_fast_and_sandbox() {
        let root = temp_dir("claude-settings-defaults");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            concat!(
                "{\n",
                "  \"model\": \"claude-opus-4-7\",\n",
                "  \"effortLevel\": \"high\",\n",
                "  \"fastMode\": true,\n",
                "  \"permissions\": {\"defaultMode\": \"acceptEdits\"},\n",
                "  \"sandbox\": {\"enabled\": true}\n",
                "}\n"
            ),
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(
            defaults
                .selector_sources
                .get("reasoning_effort")
                .map(String::as_str),
            Some("claude_code.settings.effortLevel")
        );
        assert_eq!(defaults.approval_policy.as_deref(), Some("acceptEdits"));
        assert_eq!(defaults.fast_mode_enabled, Some(true));
        // `sandbox.enabled` with no `autoAllowBashIfSandboxed` override is
        // Claude Code's auto-allow default.
        assert_eq!(defaults.sandbox_mode.as_deref(), Some("auto_allow"));
        assert_eq!(
            defaults.selector_sources.get("model").map(String::as_str),
            Some("claude_code.settings.model")
        );
        assert_eq!(
            defaults
                .selector_sources
                .get("approval_policy")
                .map(String::as_str),
            Some("claude_code.settings.permissions.defaultMode")
        );
        assert_eq!(
            defaults
                .selector_context
                .get("fast_mode_enabled")
                .map(String::as_str),
            Some("true")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_prefer_local_then_managed_scope() {
        let root = temp_dir("claude-settings-precedence");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\"model\": \"claude-haiku-4-5\", \"effortLevel\": \"low\", \"fastMode\": true, \"permissions\": {\"defaultMode\": \"acceptEdits\"}}\n",
        )
        .expect("write user settings");
        fs::write(
            claude_dir.join("settings.local.json"),
            "{\"model\": \"claude-sonnet-4-5\", \"effortLevel\": \"medium\", \"permissions\": {\"defaultMode\": \"plan\"}}\n",
        )
        .expect("write local settings");
        let managed = root.join("managed-settings.json");
        fs::write(
            &managed,
            "{\"model\": \"claude-opus-4-7\", \"effortLevel\": \"xhigh\", \"sandbox\": {\"enabled\": true, \"autoAllowBashIfSandboxed\": false}}\n",
        )
        .expect("write managed settings");

        let paths = claude_settings_chain(&claude_dir, &managed);
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        // Managed settings win outright for the keys they set.
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(
            defaults.selector_sources.get("model").map(String::as_str),
            Some("claude_code.managed_settings.model")
        );
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(
            defaults
                .selector_sources
                .get("reasoning_effort")
                .map(String::as_str),
            Some("claude_code.managed_settings.effortLevel")
        );
        // Local settings win over user settings for a key managed does not set.
        assert_eq!(defaults.approval_policy.as_deref(), Some("plan"));
        assert_eq!(
            defaults
                .selector_sources
                .get("approval_policy")
                .map(String::as_str),
            Some("claude_code.settings_local.permissions.defaultMode")
        );
        // A key only the lowest scope sets still survives.
        assert_eq!(defaults.fast_mode_enabled, Some(true));
        assert_eq!(
            defaults
                .selector_sources
                .get("fast_mode_enabled")
                .map(String::as_str),
            Some("claude_code.settings.fastMode")
        );
        assert_eq!(
            defaults.sandbox_mode.as_deref(),
            Some("regular_permissions")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_prefer_local_effort_level_over_user() {
        let root = temp_dir("claude-settings-effort-precedence");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\"effortLevel\": \"low\"}\n",
        )
        .expect("write user settings");
        fs::write(
            claude_dir.join("settings.local.json"),
            "{\"effortLevel\": \"high\"}\n",
        )
        .expect("write local settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(
            defaults
                .selector_sources
                .get("reasoning_effort")
                .map(String::as_str),
            Some("claude_code.settings_local.effortLevel")
        );

        let _ = fs::remove_dir_all(root);
    }

    /// The Configuration tab's contract is "what your config file says", so an
    /// effort value is forwarded verbatim rather than normalized against a
    /// known-value list. `max` is session-only in Claude Code unless the
    /// environment sets it, but if the settings file says `max` then that is
    /// what the file says.
    #[test]
    fn claude_settings_defaults_report_effort_level_verbatim() {
        let root = temp_dir("claude-settings-effort-verbatim");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\"effortLevel\": \"max\"}\n",
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("max"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_reject_unsafe_effort_level_values() {
        let root = temp_dir("claude-settings-effort-unsafe");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        // A path-shaped effort value fails the display-safe scalar guard, so it
        // is dropped while a sibling key still resolves.
        fs::write(
            claude_dir.join("settings.json"),
            "{\"effortLevel\": \"/Users/someone/.claude/effort-profile\", \"model\": \"claude-opus-4-7\"}\n",
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.reasoning_effort, None);
        assert!(!defaults.selector_context.contains_key("reasoning_effort"));
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));

        // A non-string effort value is also ignored rather than coerced.
        fs::write(
            claude_dir.join("settings.json"),
            "{\"effortLevel\": 4, \"model\": \"claude-opus-4-7\"}\n",
        )
        .expect("rewrite settings");
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.reasoning_effort, None);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_treat_per_session_fast_opt_in_as_off() {
        let root = temp_dir("claude-settings-fast-opt-in");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\"fastMode\": true, \"fastModePerSessionOptIn\": true}\n",
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        // Fast does not persist across sessions, so the durable default is off.
        assert_eq!(defaults.fast_mode_enabled, Some(false));
        assert_eq!(
            defaults
                .selector_sources
                .get("fast_mode_enabled")
                .map(String::as_str),
            Some("claude_code.settings.fastModePerSessionOptIn")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_report_nothing_configured_and_unreadable_apart() {
        let root = temp_dir("claude-settings-empty");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));

        // No settings file at all: we could not look, which is not the same as
        // "nothing configured".
        assert_eq!(
            load_claude_defaults(&paths),
            ClaudeConfigDefaultsOutcome::Unreadable
        );

        // Unparseable settings are also "we could not read it".
        fs::write(claude_dir.join("settings.json"), "not json\n").expect("write settings");
        assert_eq!(
            load_claude_defaults(&paths),
            ClaudeConfigDefaultsOutcome::Unreadable
        );

        // Readable settings that configure none of the mapped keys.
        fs::write(
            claude_dir.join("settings.json"),
            "{\"agentPushNotifEnabled\": true, \"cleanupPeriodDays\": 30}\n",
        )
        .expect("write settings");
        assert_eq!(
            load_claude_defaults(&paths),
            ClaudeConfigDefaultsOutcome::NothingConfigured
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_never_emit_paths_secrets_or_bypass_permissions() {
        let root = temp_dir("claude-settings-redaction");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            concat!(
                "{\n",
                "  \"model\": \"claude-opus-4-7\",\n",
                "  \"apiKeyHelper\": \"/Users/someone/bin/print-key.sh\",\n",
                "  \"env\": {\"ANTHROPIC_API_KEY\": \"sk-ant-secret-value\",\n",
                "            \"OTEL_EXPORTER_OTLP_HEADERS\": \"Authorization=Bearer otsi_secret\"},\n",
                "  \"statusLine\": {\"type\": \"command\", \"command\": \"/Users/someone/.claude/statusline.sh\"},\n",
                "  \"permissions\": {\n",
                "    \"defaultMode\": \"bypassPermissions\",\n",
                "    \"allow\": [\"Read(~/.zshrc)\", \"Bash(aws s3 *)\"],\n",
                "    \"deny\": [\"Read(./.env)\"]\n",
                "  },\n",
                "  \"sandbox\": {\n",
                "    \"enabled\": true,\n",
                "    \"filesystem\": {\"allowWrite\": [\"/Users/someone/.kube\"]},\n",
                "    \"credentials\": {\"envVars\": [{\"name\": \"GH_TOKEN\", \"mode\": \"deny\"}],\n",
                "                     \"files\": [{\"path\": \"~/.aws/credentials\", \"mode\": \"deny\"}]}\n",
                "  }\n",
                "}\n"
            ),
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        // Only the four mapped keys are read; the sandbox contributes its mode
        // and nothing from filesystem/credentials.
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(defaults.sandbox_mode.as_deref(), Some("auto_allow"));
        // `bypassPermissions` is a local safety posture, never uploaded.
        assert_eq!(defaults.approval_policy, None);
        assert!(!defaults.selector_context.contains_key("approval_policy"));
        assert_eq!(
            defaults.selector_context.keys().collect::<Vec<_>>(),
            vec!["model", "sandbox_mode"]
        );

        let leaked = defaults
            .selector_context
            .values()
            .chain(defaults.selector_sources.values())
            .find(|value| {
                let lowered = value.to_ascii_lowercase();
                lowered.contains('/')
                    || lowered.contains("sk-")
                    || lowered.contains("bearer")
                    || lowered.contains("token")
                    || lowered.contains("credential")
                    || lowered.contains("bypass")
            });
        assert_eq!(leaked, None, "no path or secret text may ride along");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_settings_defaults_reject_path_shaped_model_values() {
        let root = temp_dir("claude-settings-model-path");
        let claude_dir = root.join(".claude");
        fs::create_dir_all(&claude_dir).expect("create .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\"model\": \"/Users/someone/models/local.gguf\", \"fastMode\": false}\n",
        )
        .expect("write settings");

        let paths = claude_settings_chain(&claude_dir, &root.join("managed-settings.json"));
        let ClaudeConfigDefaultsOutcome::Configured(defaults) = load_claude_defaults(&paths) else {
            panic!("expected configured Claude defaults");
        };
        assert_eq!(defaults.model, None);
        assert_eq!(defaults.fast_mode_enabled, Some(false));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_does_not_backdate_fast_opt_out_to_history() {
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
        assert!(selector.is_empty());
        assert!(item.model_usage[0].selector_sources.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_does_not_backdate_notice_fast_opt_out_to_history() {
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
        assert!(selector.is_empty());
        assert!(item.model_usage[0].selector_sources.is_empty());

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
        // `originator` is Codex-only; Claude Code sessions never carry one.
        assert_eq!(item.originator, None);
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
        for row in &mut items[0].model_usage {
            row.account_identifier_hash = Some("hash-account-exact".to_string());
        }
        for row in &mut items[0].usage_buckets[0].model_usage {
            row.account_identifier_hash = Some("hash-account-exact".to_string());
        }
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
        assert!(items[0]
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.as_deref() == Some("hash-account-exact")));
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
    fn claude_local_otel_account_hash_stamps_unique_and_clears_conflict() {
        let path = temp_file("claude-account-evidence");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-31T10:00:00Z\",\"sessionId\":\"claude-account-1\",\"summary\":\"t\"}\n",
                "{\"timestamp\":\"2026-07-31T10:01:00Z\",\"sessionId\":\"claude-account-1\",\"message\":{\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n"
            ),
        )
        .expect("write fixture");
        let mut items =
            parse_claude_code_jsonl_file(&path, "2026-07-31T10:02:00Z", "fp".to_string())
                .expect("parse");
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);
        let unique = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![crate::claude_effort::ClaudeEffortEvidence {
                session_id: "claude-account-1".to_string(),
                model: "unmatched-model".to_string(),
                effort: "high".to_string(),
                input_tokens: 2,
                output_tokens: 1,
                request_count: 1,
                account_identity_checked: true,
                account_identifier_hash: Some(account_a.clone()),
                ..Default::default()
            }],
        )]);

        apply_claude_effort_evidence(&mut items, &unique);

        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.as_deref() == Some(account_a.as_str())));
        let unique_fingerprint = items[0].snapshot_fingerprint.clone();

        let conflicting = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![
                crate::claude_effort::ClaudeEffortEvidence {
                    account_identity_checked: true,
                    account_identifier_hash: Some(account_a),
                    ..Default::default()
                },
                crate::claude_effort::ClaudeEffortEvidence {
                    account_identity_checked: true,
                    account_identifier_hash: Some(account_b),
                    ..Default::default()
                },
            ],
        )]);
        apply_claude_effort_evidence(&mut items, &conflicting);

        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.is_none()));
        assert_ne!(items[0].snapshot_fingerprint, unique_fingerprint);

        let partially_identified = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![
                crate::claude_effort::ClaudeEffortEvidence {
                    account_identity_checked: true,
                    account_identifier_hash: Some("a".repeat(64)),
                    ..Default::default()
                },
                crate::claude_effort::ClaudeEffortEvidence {
                    account_identity_checked: true,
                    ..Default::default()
                },
            ],
        )]);
        apply_claude_effort_evidence(&mut items, &unique);
        apply_claude_effort_evidence(&mut items, &partially_identified);
        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.is_none()));

        apply_claude_effort_evidence(&mut items, &unique);
        let unidentified = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![crate::claude_effort::ClaudeEffortEvidence {
                account_identity_checked: true,
                ..Default::default()
            }],
        )]);
        apply_claude_effort_evidence(&mut items, &unidentified);
        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.is_none()));

        let mixed_legacy_and_current = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![
                crate::claude_effort::ClaudeEffortEvidence::default(),
                crate::claude_effort::ClaudeEffortEvidence {
                    account_identity_checked: true,
                    account_identifier_hash: Some("a".repeat(64)),
                    ..Default::default()
                },
            ],
        )]);
        apply_claude_effort_evidence(&mut items, &mixed_legacy_and_current);
        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.is_none()));

        let incomplete_current = BTreeMap::from([(
            "claude-account-1".to_string(),
            vec![crate::claude_effort::ClaudeEffortEvidence {
                account_identity_checked: true,
                account_identifier_hash: Some("a".repeat(64)),
                request_count: 1,
                ..Default::default()
            }],
        )]);
        apply_claude_effort_evidence(&mut items, &incomplete_current);
        assert!(items[0]
            .model_usage
            .iter()
            .chain(
                items[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.is_none()));
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
    fn claude_subagent_source_session_id_discriminates_by_subagents_ancestor() {
        // Helper contract (v20): a transcript is a subagent transcript when ANY
        // ancestor directory is `subagents`, and the parent session id comes
        // from the PATH -- the directory whose child is `subagents` -- never
        // from the in-file `sessionId`.

        // Layout 2, Task tool: immediate parent is `subagents`. The v13 id
        // scheme is preserved byte-for-byte so ids already minted for these
        // files keep resolving to the same backend session.
        let task_agent = Path::new("/p/proj/PARENT/subagents/agent-abc123.jsonl");
        assert_eq!(
            claude_subagent_source_session_id(task_agent).as_deref(),
            Some("PARENT_agent-abc123")
        );

        // Layout 3, Workflow tool: two directories deeper. This is the case v19
        // returned None for, which is what let workflow agents overwrite their
        // human parent session.
        let workflow_agent =
            Path::new("/p/proj/PARENT/subagents/workflows/wf_ffe2de5a-c85/agent-abc123.jsonl");
        assert_eq!(
            claude_subagent_source_session_id(workflow_agent).as_deref(),
            Some("PARENT_agent-abc123")
        );
        let identity = claude_subagent_identity(workflow_agent).expect("workflow identity");
        assert_eq!(identity.root_session_id, "PARENT");
        assert_eq!(identity.workflow_ref.as_deref(), Some("wf_ffe2de5a-c85"));
        assert_eq!(identity.agent_ref(), Some("abc123"));

        // Layout 4, the Workflow journal, resolves as a subagent path (so the
        // exclusion below can key off it) but is never emitted.
        let journal = Path::new("/p/proj/PARENT/subagents/workflows/wf_ffe2de5a-c85/journal.jsonl");
        assert_eq!(
            claude_subagent_source_session_id(journal).as_deref(),
            Some("PARENT_journal")
        );
        assert!(claude_transcript_excluded_from_snapshots(journal));

        // Arbitrarily deep nesting still resolves to the session directory that
        // owns the `subagents` tree, not to an intermediate directory.
        let deep = Path::new("/p/proj/PARENT/subagents/workflows/wf_a/inner/deeper/agent-z9.jsonl");
        assert_eq!(
            claude_subagent_source_session_id(deep).as_deref(),
            Some("PARENT_agent-z9")
        );
        assert_eq!(
            claude_subagent_identity(deep)
                .expect("deep identity")
                .workflow_ref
                .as_deref(),
            Some("wf_a")
        );

        // Layout 1, top-level transcript -> None (raw in-file id kept).
        let top = Path::new("/p/proj/PARENT.jsonl");
        assert_eq!(claude_subagent_source_session_id(top), None);
        assert!(!claude_transcript_excluded_from_snapshots(top));

        // A nested but non-`subagents` sibling dir -> None. `workflows/` under
        // the SESSION directory holds wf_*.json manifests, not transcripts.
        let other = Path::new("/p/proj/PARENT/workflows/wf.jsonl");
        assert_eq!(claude_subagent_source_session_id(other), None);
        // A `journal.jsonl` outside any `subagents` tree is an ordinary file and
        // must not be swept up by the exclusion.
        let unrelated_journal = Path::new("/p/proj/PARENT/journal.jsonl");
        assert!(!claude_transcript_excluded_from_snapshots(
            unrelated_journal
        ));

        // `subagents` with no owning session directory above it cannot name a
        // parent, so it is not treated as a subagent transcript.
        let orphan = Path::new("subagents/agent-abc123.jsonl");
        assert_eq!(claude_subagent_source_session_id(orphan), None);
    }

    #[test]
    fn claude_workflow_subagent_rekeys_off_its_parent_and_carries_tree_facts() {
        // The live bug: a Workflow-tool agent transcript nested under
        // `subagents/workflows/<wfId>/` carries the PARENT's sessionId on every
        // line, so before v20 it uploaded a snapshot claiming to BE the parent
        // human session and overwrote it under last-writer-wins promotion.
        let root = temp_dir("claude-workflow-subagent");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let workflow_dir = root
            .join(parent_session)
            .join("subagents")
            .join("workflows")
            .join("wf_ffe2de5a-c85");
        fs::create_dir_all(&workflow_dir).expect("create workflow dir");
        let path = workflow_dir.join("agent-a4d1585d310070d0f.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-24T09:00:00.000Z\",\"type\":\"user\",\"sessionId\":\"1338a80a-f36e-4cbc-a5bb-50fc66430ba5\",\"agentId\":\"a4d1585d310070d0f\",\"isSidechain\":true,\"entrypoint\":\"cli\",\"message\":{\"role\":\"user\",\"content\":\"research\"}}\n",
                "{\"timestamp\":\"2026-07-24T09:00:09.000Z\",\"type\":\"assistant\",\"sessionId\":\"1338a80a-f36e-4cbc-a5bb-50fc66430ba5\",\"agentId\":\"a4d1585d310070d0f\",\"isSidechain\":true,\"requestId\":\"req_W\",\"message\":{\"id\":\"msg_W\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":120,\"output_tokens\":30}}}\n"
            ),
        )
        .expect("write fixture");
        fs::write(
            workflow_dir.join("agent-a4d1585d310070d0f.meta.json"),
            "{\"agentType\":\"workflow-subagent\",\"spawnDepth\":1,\"model\":\"opus\"}",
        )
        .expect("write sidecar");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-24T09:10:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "1338a80a-f36e-4cbc-a5bb-50fc66430ba5_agent-a4d1585d310070d0f"
        );
        assert_ne!(item.source_session_id, parent_session);
        assert!(!item.source_session_id.contains('/'));
        // The subagent's own tokens, counted once under its own session.
        assert_eq!(item.input_tokens, 120);
        assert_eq!(item.output_tokens, 30);

        let fact = |field: &str| {
            item.attribution_facts
                .iter()
                .find(|fact| fact.field == field)
                .map(|fact| fact.value.clone())
        };
        // Depth-1 agent: the direct parent IS the root human session.
        assert_eq!(fact("parent_session_ref").as_deref(), Some(parent_session));
        assert_eq!(fact("root_session_ref").as_deref(), Some(parent_session));
        assert_eq!(fact("agent_kind").as_deref(), Some("workflow-subagent"));
        assert_eq!(fact("agent_ref").as_deref(), Some("a4d1585d310070d0f"));
        assert_eq!(fact("workflow_ref").as_deref(), Some("wf_ffe2de5a-c85"));
        assert_eq!(fact("origin_kind").as_deref(), Some("subagent"));
        // Bounded-payload contract still holds with the full fact set present.
        crate::session_attribution::validate_fact_limits(&item.attribution_facts)
            .expect("subagent facts stay inside the bounded payload budget");
        // The dark parent id must not widen the v6 origin wire object.
        let wire = serde_json::to_value(&item).expect("serialize");
        assert!(wire
            .get("origin")
            .and_then(|origin| origin.get("parent_session_ref"))
            .is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_nested_subagent_parent_ref_points_at_the_spawning_agent() {
        // spawnDepth>1 with a recorded `parentAgentId`: the DIRECT parent is the
        // spawning agent's own re-keyed session, while the root stays the human
        // session so the rollup key is unambiguous.
        let root = temp_dir("claude-nested-subagent");
        let parent_session = "abeeabab-6bc0-4bc3-8a95-e5d967c6e9a1";
        let subagents_dir = root.join(parent_session).join("subagents");
        fs::create_dir_all(&subagents_dir).expect("create subagents dir");
        let path = subagents_dir.join("agent-abadf13e89f0b1c4c.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-24T10:00:00.000Z\",\"type\":\"user\",\"sessionId\":\"abeeabab-6bc0-4bc3-8a95-e5d967c6e9a1\",\"isSidechain\":true,\"entrypoint\":\"cli\",\"message\":{\"role\":\"user\",\"content\":\"trace\"}}\n",
                "{\"timestamp\":\"2026-07-24T10:00:05.000Z\",\"type\":\"assistant\",\"sessionId\":\"abeeabab-6bc0-4bc3-8a95-e5d967c6e9a1\",\"isSidechain\":true,\"requestId\":\"req_N\",\"message\":{\"id\":\"msg_N\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":11,\"output_tokens\":2}}}\n"
            ),
        )
        .expect("write fixture");
        fs::write(
            subagents_dir.join("agent-abadf13e89f0b1c4c.meta.json"),
            "{\"agentType\":\"Explore\",\"spawnDepth\":2,\"parentAgentId\":\"a665ed7d7731771a8\"}",
        )
        .expect("write sidecar");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-24T10:10:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        let fact = |field: &str| {
            item.attribution_facts
                .iter()
                .find(|fact| fact.field == field)
                .map(|fact| fact.value.clone())
        };
        assert_eq!(
            fact("parent_session_ref").as_deref(),
            Some("abeeabab-6bc0-4bc3-8a95-e5d967c6e9a1_agent-a665ed7d7731771a8")
        );
        assert_eq!(fact("root_session_ref").as_deref(), Some(parent_session));
        assert_eq!(fact("agent_kind").as_deref(), Some("Explore"));
        assert_eq!(fact("spawn_depth").as_deref(), Some("2"));
        // Not under `workflows/`, so no workflow edge is claimed.
        assert_eq!(fact("workflow_ref"), None);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_subagent_without_meta_sidecar_degrades_to_path_facts() {
        // A missing or malformed sidecar must leave the derived facts absent and
        // never drop the session.
        let root = temp_dir("claude-subagent-no-meta");
        let parent_session = "52c34dcb-44e4-428f-8def-979dd43b7259";
        let subagents_dir = root.join(parent_session).join("subagents");
        fs::create_dir_all(&subagents_dir).expect("create subagents dir");
        let missing = subagents_dir.join("agent-a35bc3648272bc00c.jsonl");
        let malformed = subagents_dir.join("agent-b11111111111111c.jsonl");
        for (path, agent) in [
            (&missing, "a35bc3648272bc00c"),
            (&malformed, "b11111111111111c"),
        ] {
            fs::write(
                path,
                format!(
                    "{{\"timestamp\":\"2026-07-24T11:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"req_{agent}\",\"message\":{{\"id\":\"msg_{agent}\",\"model\":\"claude-sonnet-4-6\",\"usage\":{{\"input_tokens\":5,\"output_tokens\":1}}}}}}\n"
                ),
            )
            .expect("write fixture");
        }
        fs::write(
            subagents_dir.join("agent-b11111111111111c.meta.json"),
            "{not json at all",
        )
        .expect("write malformed sidecar");

        for (path, agent) in [
            (&missing, "a35bc3648272bc00c"),
            (&malformed, "b11111111111111c"),
        ] {
            let item = parse_claude_code_jsonl_file(path, "2026-07-24T11:10:00Z", "fp".to_string())
                .expect("parse")
                .into_iter()
                .next()
                .expect("snapshot");
            assert_eq!(
                item.source_session_id,
                format!("{parent_session}_agent-{agent}")
            );
            let fact = |field: &str| {
                item.attribution_facts
                    .iter()
                    .find(|fact| fact.field == field)
                    .map(|fact| fact.value.clone())
            };
            // Path-derived facts survive; sidecar-derived ones are simply absent.
            assert_eq!(fact("parent_session_ref").as_deref(), Some(parent_session));
            assert_eq!(fact("root_session_ref").as_deref(), Some(parent_session));
            assert_eq!(fact("agent_ref").as_deref(), Some(agent));
            assert_eq!(fact("agent_kind"), None);
            assert_eq!(fact("spawn_depth"), None);
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_workflow_journal_is_never_collected_or_emitted() {
        // `journal.jsonl` has no usage rows and no `sessionId`, and its stem
        // collides across the workflow directories of one parent session. It
        // must be dropped at collection time and refused by the parser.
        let root = temp_dir("claude-workflow-journal");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let session_dir = root.join(parent_session);
        let first = session_dir
            .join("subagents")
            .join("workflows")
            .join("wf_ffe2de5a-c85");
        let second = session_dir
            .join("subagents")
            .join("workflows")
            .join("wf_73e1a9d2-065");
        fs::create_dir_all(&first).expect("create first workflow dir");
        fs::create_dir_all(&second).expect("create second workflow dir");
        for dir in [&first, &second] {
            fs::write(
                dir.join("journal.jsonl"),
                "{\"type\":\"started\",\"key\":\"v2:abc\",\"agentId\":\"a1\"}\n{\"type\":\"result\"}\n",
            )
            .expect("write journal");
        }
        fs::write(
            first.join("agent-a1f7743a82e5fe4e9.jsonl"),
            format!(
                "{{\"timestamp\":\"2026-07-24T12:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"isSidechain\":true,\"requestId\":\"req_J\",\"message\":{{\"id\":\"msg_J\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":4,\"output_tokens\":2}}}}}}\n"
            ),
        )
        .expect("write agent transcript");

        let mut selection = BoundedCandidateSelection::new(None, None, 10);
        let mut census = ScanCensus::default();
        collect_recent_jsonl_files(
            SnapshotSource::ClaudeCode,
            &root,
            &root,
            &mut selection,
            &mut census,
            u64::MAX,
        );
        let (files, _, _, _) = selection.finish(census.discovered_file_count);
        assert!(
            files.iter().all(|candidate| candidate
                .path
                .file_name()
                .and_then(|value| value.to_str())
                != Some("journal.jsonl")),
            "workflow journals must not become scan candidates"
        );
        assert_eq!(files.len(), 1, "only the agent transcript is a candidate");

        let journal = first.join("journal.jsonl");
        let mut hinted_index = ScanIndex::default();
        let hinted = scan_source_roots_with_limit_and_attribution(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut hinted_index,
            "2026-07-24T12:10:00Z",
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
            None,
            None,
            std::slice::from_ref(&journal),
            false,
        )
        .expect("scan with workflow journal hint");
        assert!(hinted_index
            .files
            .keys()
            .all(|path| !path.ends_with("journal.jsonl")));
        assert_eq!(hinted.scanned_file_count, 1);

        // Even through the public parse entry point the journal yields nothing,
        // so `<parent>_journal` can never exist.
        assert!(parse_claude_code_jsonl_file(
            &first.join("journal.jsonl"),
            "2026-07-24T12:10:00Z",
            "fp".to_string(),
        )
        .expect("parse journal")
        .is_empty());

        let _ = fs::remove_dir_all(root);
    }

    /// READ-ONLY audit of the v20 keying against this machine's real
    /// `~/.claude/projects` tree.
    ///
    /// Ignored by default because it depends on local state that CI does not
    /// have. It opens nothing, writes nothing, uploads nothing, and never
    /// touches the daemon: it walks directory entries and classifies each
    /// transcript path. Run it with:
    ///
    /// ```text
    /// cargo test -p ottto-service --lib claude_real_tree_rekey_audit -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "reads the developer's real ~/.claude/projects tree"]
    fn claude_real_tree_rekey_audit() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            eprintln!("no HOME; skipping");
            return;
        };
        let root = home.join(".claude").join("projects");
        if !root.exists() {
            eprintln!("no {} ; skipping", root.display());
            return;
        }

        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.metadata() {
                    Ok(metadata) if metadata.is_dir() => walk(&path, out),
                    Ok(metadata)
                        if metadata.is_file()
                            && path.extension().and_then(|value| value.to_str())
                                == Some("jsonl") =>
                    {
                        out.push(path)
                    }
                    _ => {}
                }
            }
        }

        let mut files = Vec::new();
        walk(&root, &mut files);

        let (mut layout1, mut layout2, mut layout3, mut layout4) = (0usize, 0usize, 0usize, 0usize);
        let mut excluded = 0usize;
        // re-keyed id -> the paths that produced it, so any collision is visible.
        let mut ids: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        let mut top_level_ids: BTreeSet<String> = BTreeSet::new();
        let mut meta_present = 0usize;
        let mut meta_agent_kind = 0usize;
        let mut nested_parent_refs = 0usize;

        for path in &files {
            if claude_transcript_excluded_from_snapshots(path) {
                excluded += 1;
                layout4 += 1;
                continue;
            }
            match claude_subagent_identity(path) {
                None => {
                    layout1 += 1;
                    if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                        top_level_ids.insert(stem.to_string());
                    }
                }
                Some(identity) => {
                    if identity.workflow_ref.is_some() {
                        layout3 += 1;
                    } else {
                        layout2 += 1;
                    }
                    let meta = read_claude_agent_meta(path);
                    if meta != ClaudeAgentMeta::default() {
                        meta_present += 1;
                    }
                    if meta.agent_kind.is_some() {
                        meta_agent_kind += 1;
                    }
                    if meta.parent_agent_id.is_some() {
                        nested_parent_refs += 1;
                    }
                    ids.entry(identity.source_session_id())
                        .or_default()
                        .push(path.clone());
                }
            }
        }

        // Blast radius of the v19 bug: every layout 3/4 file uploaded a snapshot
        // claiming to BE its parent human session. Count the distinct parents
        // that were therefore overwritable.
        let mut poisoned_parents: BTreeSet<String> = BTreeSet::new();
        let mut previously_miskeyed = 0usize;
        for path in &files {
            if claude_transcript_excluded_from_snapshots(path) {
                // Journals carry no usage rows, so they never overwrote anything
                // even under v19; they are excluded here to keep the blast
                // radius honest.
                continue;
            }
            let Some(identity) = claude_subagent_identity(path) else {
                continue;
            };
            let immediate_parent_is_subagents = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|value| value.to_str())
                == Some("subagents");
            if !immediate_parent_is_subagents {
                previously_miskeyed += 1;
                poisoned_parents.insert(identity.root_session_id.clone());
            }
        }

        let collisions: Vec<_> = ids.iter().filter(|(_, paths)| paths.len() > 1).collect();
        let overlap: Vec<_> = ids
            .keys()
            .filter(|id| top_level_ids.contains(id.as_str()))
            .collect();

        println!("--- v20 re-key audit over {} ---", root.display());
        println!("total .jsonl files:            {}", files.len());
        println!("layout 1 (top-level session):  {layout1}");
        println!("layout 2 (task subagent):      {layout2}");
        println!("layout 3 (workflow subagent):  {layout3}");
        println!("layout 4 (workflow journal):   {layout4} (excluded: {excluded})");
        println!("re-keyed subagent sessions:    {}", ids.len());
        println!("  with a readable meta.json:   {meta_present}");
        println!("  with agentType:              {meta_agent_kind}");
        println!("  with parentAgentId (nested): {nested_parent_refs}");
        println!("v19 mis-keyed onto a parent:   {previously_miskeyed}");
        println!("distinct parents overwritable: {}", poisoned_parents.len());
        println!("re-keyed id collisions:        {}", collisions.len());
        println!("re-key vs top-level id clash:  {}", overlap.len());
        for (id, paths) in &collisions {
            println!("  COLLISION {id}: {paths:?}");
        }

        // The canonical case from the incident.
        let canonical = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let family: Vec<_> = ids
            .keys()
            .filter(|id| id.starts_with(&format!("{canonical}_")))
            .collect();
        if !family.is_empty() {
            println!("canonical parent {canonical}: {} children", family.len());
            for id in &family {
                println!("  {id}");
            }
            assert!(
                top_level_ids.contains(canonical),
                "the canonical parent must still key to itself"
            );
            assert!(
                !ids.contains_key(canonical),
                "no child may re-key onto the parent's own id"
            );
        }

        assert!(
            collisions.is_empty(),
            "two transcripts re-keyed to one session id"
        );
        assert!(
            overlap.is_empty(),
            "a re-keyed subagent id collided with a real top-level session id"
        );
        assert_eq!(
            excluded, layout4,
            "every workflow journal must be excluded from emission"
        );
    }

    #[test]
    fn claude_subagent_fact_names_are_the_agreed_backend_contract() {
        // These names are a FIXED contract with the backend session-attribution
        // reader (`SessionAttributionField` in
        // backend/app/domain/telemetry/session_attribution.py). The backend enum
        // rejects unknown field names, and one rejected fact fails the WHOLE
        // upload batch, so the enum must carry every name below BEFORE a daemon
        // emitting `claude_code_jsonl:v20` reaches users. Renaming anything here
        // is a coordinated cross-repo change, never a local rename.
        let facts = crate::session_attribution::claude_subagent_facts(
            &crate::session_attribution::ClaudeSubagentAttribution {
                root_session_ref: "1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
                agent_kind: Some("workflow-subagent"),
                agent_ref: Some("a4d1585d310070d0f"),
                spawn_depth: Some("1"),
                workflow_ref: Some("wf_ffe2de5a-c85"),
            },
            "1338a80a-f36e-4cbc-a5bb-50fc66430ba5_agent-a4d1585d310070d0f",
            "2026-07-24T09:10:00Z",
            "claude_code_jsonl:v20",
        );
        assert_eq!(
            facts
                .iter()
                .map(|fact| fact.field.as_str())
                .collect::<Vec<_>>(),
            // Ordered most- to least-load-bearing: the caller trims from the
            // tail to stay inside the bounded payload budget.
            vec![
                "root_session_ref",
                "agent_kind",
                "agent_ref",
                "workflow_ref",
                "spawn_depth",
            ]
        );
        // Every value is a bounded provider identifier, never free text.
        assert!(facts
            .iter()
            .all(|fact| fact.evidence.strength == "direct" && fact.display_label.is_none()));
    }

    #[test]
    fn claude_subagent_facts_fit_the_bounded_payload_budget() {
        // The budget is a hard byte ceiling over the serialized fact list and
        // one oversized item 422s the whole batch, so the daemon must trim. At
        // ~269 bytes per fact the retired 2 KiB budget fit only seven and
        // dropped `spawn_depth` -- the field deliberately ordered last -- which
        // is what a production Claude subagent session actually lost. The 8 KiB
        // budget the deployed backend also enforces fits all eight with room to
        // spare, which is the whole point of the raise. Pin the full set for the
        // single layout that carries every fact -- a WORKFLOW agent -- so a
        // future trim cannot silently move back onto one of them.
        let root = temp_dir("claude-subagent-budget");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let workflow_dir = root
            .join(parent_session)
            .join("subagents")
            .join("workflows")
            .join("wf_ffe2de5a-c85");
        fs::create_dir_all(&workflow_dir).expect("create workflow dir");
        let path = workflow_dir.join("agent-a4d1585d310070d0f.jsonl");
        fs::write(
            &path,
            format!(
                "{{\"timestamp\":\"2026-07-24T09:00:09.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"isSidechain\":true,\"entrypoint\":\"cli\",\"requestId\":\"req_B\",\"message\":{{\"id\":\"msg_B\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":9,\"output_tokens\":3}}}}}}\n"
            ),
        )
        .expect("write fixture");
        fs::write(
            workflow_dir.join("agent-a4d1585d310070d0f.meta.json"),
            "{\"agentType\":\"workflow-subagent\",\"spawnDepth\":1}",
        )
        .expect("write sidecar");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-24T09:10:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        assert_eq!(
            item.attribution_facts
                .iter()
                .map(|fact| fact.field.as_str())
                .collect::<Vec<_>>(),
            vec![
                "origin_kind",
                "provider_surface",
                "parent_session_ref",
                "root_session_ref",
                "agent_kind",
                "agent_ref",
                "workflow_ref",
                "spawn_depth",
            ]
        );
        const RETIRED_PAYLOAD_BUDGET_BYTES: usize = 2_048;
        let payload_bytes = serde_json::to_vec(&item.attribution_facts)
            .expect("serialize facts")
            .len();
        assert!(
            payload_bytes <= crate::session_attribution::MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
            "the full workflow-subagent fact set must fit the wire budget"
        );
        assert!(
            payload_bytes > RETIRED_PAYLOAD_BUDGET_BYTES,
            "this set is the one the retired 2 KiB budget trimmed; if it now fits there, the \
             fixture stopped covering the regression"
        );
        // Not merely inside the budget but comfortably inside it: the raise is
        // supposed to leave headroom for the grouping facts appended after these
        // eight, not land one skill fact short of trimming again.
        assert!(
            payload_bytes * 2 <= crate::session_attribution::MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
            "expected the full fact set to use under half the budget, used {payload_bytes}"
        );
        crate::session_attribution::validate_fact_limits(&item.attribution_facts)
            .expect("bounded payload");
        // Re-bounding an already-fitting set must be a no-op; this is the call
        // the upload path makes, and it is where `spawn_depth` used to vanish.
        let mut rebounded = item.attribution_facts.clone();
        crate::session_attribution::enforce_fact_limits(&mut rebounded);
        assert_eq!(
            rebounded, item.attribution_facts,
            "the full workflow-subagent fact set must survive enforce_fact_limits untouched"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_subagent_file_stems_are_unique_within_a_parent_session() {
        // The `<parentSessionId>_<fileStem>` scheme is only collision-free
        // because Claude mints agent ids that are unique across ALL of one
        // parent session's subagent directories. Pin that assumption: the same
        // stem is never expected in two workflow directories, and two DIFFERENT
        // stems in different workflow directories must stay distinct.
        let a = Path::new("/p/proj/S/subagents/agent-a1.jsonl");
        let b = Path::new("/p/proj/S/subagents/workflows/wf_x/agent-a2.jsonl");
        let c = Path::new("/p/proj/S/subagents/workflows/wf_y/agent-a3.jsonl");
        let ids: BTreeSet<String> = [a, b, c]
            .into_iter()
            .map(|path| claude_subagent_source_session_id(path).expect("subagent id"))
            .collect();
        assert_eq!(ids.len(), 3);
        // The workflow directory deliberately does NOT enter the id: an agent id
        // is already unique per parent session, and folding the directory in
        // would have changed every id already minted for layout 2.
        assert_eq!(
            claude_subagent_source_session_id(b).as_deref(),
            Some("S_agent-a2")
        );
    }

    #[test]
    fn claude_agent_meta_sidecar_rejects_unsafe_values() {
        // Provider identifiers only. Anything that could smuggle a local path or
        // free text into an attribution fact is dropped, not sanitized.
        let dir = temp_dir("claude-agent-meta-safety");
        fs::create_dir_all(&dir).expect("create dir");
        let transcript = dir.join("agent-a1.jsonl");
        fs::write(
            dir.join("agent-a1.meta.json"),
            "{\"agentType\":\"/Users/someone/secret agent\",\"spawnDepth\":\"2\",\"description\":\"do not leak me\",\"worktreePath\":\"/Users/someone/wt\"}",
        )
        .expect("write sidecar");
        let meta = read_claude_agent_meta(&transcript);
        assert_eq!(meta.agent_kind, None, "unsafe agentType is dropped");
        // spawnDepth must be an integer; a string is not silently accepted.
        assert_eq!(meta.spawn_depth, None);
        assert_eq!(meta.parent_agent_id, None);
        // `description` IS retained (operator decision 2026-07-27: short agent
        // titles are wanted) — but only through the display-label allowlist.
        assert_eq!(meta.description.as_deref(), Some("do not leak me"));
        // A path-shaped description is dropped, not sanitized: `worktreePath`
        // stays unread and a description cannot smuggle one in either.
        fs::write(
            dir.join("agent-a1.meta.json"),
            "{\"description\":\"review /Users/someone/private notes\"}",
        )
        .expect("rewrite sidecar");
        assert_eq!(read_claude_agent_meta(&transcript).description, None);

        // Fragments the BACKEND fact validator rejects are dropped locally too:
        // one rejected fact fails the whole upload batch.
        for hostile in [".claude", "x.codex", "workspace_path", "transcript_path"] {
            fs::write(
                dir.join("agent-a1.meta.json"),
                format!("{{\"agentType\":\"{hostile}\"}}"),
            )
            .expect("rewrite sidecar");
            assert_eq!(
                read_claude_agent_meta(&transcript).agent_kind,
                None,
                "{hostile} must not reach an attribution fact"
            );
        }

        fs::write(
            dir.join("agent-a1.meta.json"),
            "{\"agentType\":\"pr-review-toolkit:code-reviewer\",\"spawnDepth\":3}",
        )
        .expect("rewrite sidecar");
        let meta = read_claude_agent_meta(&transcript);
        assert_eq!(
            meta.agent_kind.as_deref(),
            Some("pr-review-toolkit:code-reviewer")
        );
        assert_eq!(meta.spawn_depth.as_deref(), Some("3"));
        // The common real values must survive the allowlist unchanged.
        for allowed in [
            "workflow-subagent",
            "Explore",
            "general-purpose",
            "claude",
            "claude-code-guide",
            "wait-poller",
            "feature-dev:code-explorer",
        ] {
            fs::write(
                dir.join("agent-a1.meta.json"),
                format!("{{\"agentType\":\"{allowed}\"}}"),
            )
            .expect("rewrite sidecar");
            assert_eq!(
                read_claude_agent_meta(&transcript).agent_kind.as_deref(),
                Some(allowed)
            );
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn claude_subagent_never_inherits_the_parent_desktop_title() {
        // The desktop title store is keyed by CLI session id. A subagent
        // transcript's file stem is an agent id, so a lookup would either miss
        // or hand the subagent its parent's title. Both layouts must refuse.
        let root = temp_dir("claude-subagent-title");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let task_dir = root.join(parent_session).join("subagents");
        let workflow_dir = task_dir.join("workflows").join("wf_ffe2de5a-c85");
        fs::create_dir_all(&workflow_dir).expect("create dirs");
        let mut metadata = ClaudeTitleMetadata::default();
        metadata.titles.insert(
            parent_session.to_string(),
            ClaudeTitleCandidate {
                title: "Parent orchestrator session".to_string(),
                user_set: true,
            },
        );

        for path in [
            task_dir.join("agent-a1f7743a82e5fe4e9.jsonl"),
            workflow_dir.join("agent-a4d1585d310070d0f.jsonl"),
        ] {
            fs::write(
                &path,
                format!(
                    "{{\"timestamp\":\"2026-07-24T13:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"isSidechain\":true,\"requestId\":\"req_T\",\"message\":{{\"id\":\"msg_T\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":6,\"output_tokens\":2}}}}}}\n"
                ),
            )
            .expect("write fixture");
            let item = parse_claude_code_jsonl_file_with_title_metadata(
                &path,
                "2026-07-24T13:10:00Z",
                "fp".to_string(),
                &metadata,
                true,
            )
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
            assert_ne!(
                item.session_display_name.as_deref(),
                Some("Parent orchestrator session"),
                "{} inherited its parent's desktop title",
                path.display()
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_workflow_label_titles_workflow_subagent_sessions() {
        // The prize path: a Workflow agent is named from the run manifest's
        // `workflowProgress[].label`. Parent provenance remains a separate
        // relationship field rather than being duplicated in the child title.
        let root = temp_dir("claude-wf-agent-label");
        let parent_session = "58e9c6bc-c733-4946-b9e4-aa57c707dbf2";
        let session_dir = root.join(parent_session);
        let workflow_dir = session_dir
            .join("subagents")
            .join("workflows")
            .join("wf_f7ae7a92-02b");
        fs::create_dir_all(&workflow_dir).expect("create dirs");
        fs::create_dir_all(session_dir.join("workflows")).expect("create manifest dir");
        fs::write(
            session_dir.join("workflows").join("wf_f7ae7a92-02b.json"),
            "{\"runId\":\"wf_f7ae7a92-02b\",\"workflowProgress\":[\
             {\"type\":\"workflow_phase\",\"index\":1,\"title\":\"Investigate\"},\
             {\"type\":\"workflow_agent\",\"agentId\":\"a09c3096ec4de4f11\",\"label\":\"probe:data-model\",\"promptPreview\":\"CONTEXT (established facts)\"},\
             {\"type\":\"workflow_agent\",\"agentId\":\"a747add886fd90cd8\",\"label\":\"verify:data-model\"}]}",
        )
        .expect("write manifest");
        let transcript = workflow_dir.join("agent-a09c3096ec4de4f11.jsonl");
        fs::write(
            &transcript,
            format!(
                "{{\"timestamp\":\"2026-07-24T13:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"isSidechain\":true,\"requestId\":\"req_L\",\"message\":{{\"id\":\"msg_L\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":6,\"output_tokens\":2}}}}}}\n"
            ),
        )
        .expect("write transcript");
        // Sidecar exists too, with a lower-precedence description: the
        // workflow label must win over it.
        fs::write(
            workflow_dir.join("agent-a09c3096ec4de4f11.meta.json"),
            "{\"agentType\":\"workflow-subagent\",\"spawnDepth\":1,\"description\":\"should lose to label\"}",
        )
        .expect("write sidecar");
        let mut metadata = ClaudeTitleMetadata::default();
        metadata.titles.insert(
            parent_session.to_string(),
            ClaudeTitleCandidate {
                title: "Two Claude accounts research".to_string(),
                user_set: false,
            },
        );

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript,
            "2026-07-24T13:10:00Z",
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
            Some("probe:data-model")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("agent_label")
        );

        // Without a parent title candidate the label stands alone.
        let bare = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript,
            "2026-07-24T13:10:00Z",
            "fp".to_string(),
            &ClaudeTitleMetadata::default(),
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(
            bare.session_display_name.as_deref(),
            Some("probe:data-model")
        );
        assert_eq!(
            bare.session_display_name_source.as_deref(),
            Some("agent_label")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_task_agent_description_and_agent_type_title_fallbacks() {
        // A Task-tool agent has no workflow manifest; its sidecar
        // `description` (the 3-8 word task summary) names it, and a sidecar
        // with only `agentType` still yields that as the last-resort label.
        let root = temp_dir("claude-task-agent-label");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let task_dir = root.join(parent_session).join("subagents");
        fs::create_dir_all(&task_dir).expect("create dirs");
        let transcript = task_dir.join("agent-abadf13e89f0b1c4c.jsonl");
        fs::write(
            &transcript,
            format!(
                "{{\"timestamp\":\"2026-07-24T13:00:00.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent_session}\",\"isSidechain\":true,\"requestId\":\"req_D\",\"message\":{{\"id\":\"msg_D\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":6,\"output_tokens\":2}}}}}}\n"
            ),
        )
        .expect("write transcript");
        fs::write(
            task_dir.join("agent-abadf13e89f0b1c4c.meta.json"),
            "{\"agentType\":\"Explore\",\"description\":\"Fix 2 failing backend integration tests\",\"spawnDepth\":1}",
        )
        .expect("write sidecar");

        let parse = |metadata: &ClaudeTitleMetadata| {
            parse_claude_code_jsonl_file_with_title_metadata(
                &transcript,
                "2026-07-24T13:10:00Z",
                "fp".to_string(),
                metadata,
                true,
            )
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot")
        };
        let item = parse(&ClaudeTitleMetadata::default());
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Fix 2 failing backend integration tests")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("agent_label")
        );

        // A parent title does not alter the child task title.
        let mut metadata = ClaudeTitleMetadata::default();
        metadata.titles.insert(
            parent_session.to_string(),
            ClaudeTitleCandidate {
                title: "Lightweight data collection and ingestion".to_string(),
                user_set: false,
            },
        );
        assert_eq!(
            parse(&metadata).session_display_name.as_deref(),
            Some("Fix 2 failing backend integration tests")
        );

        // agentType-only sidecar -> the agent kind is still a usable name.
        fs::write(
            task_dir.join("agent-abadf13e89f0b1c4c.meta.json"),
            "{\"agentType\":\"Explore\",\"spawnDepth\":1}",
        )
        .expect("rewrite sidecar");
        let item = parse(&ClaudeTitleMetadata::default());
        assert_eq!(item.session_display_name.as_deref(), Some("Explore"));
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("agent_label")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_subagent_first_prompt_never_becomes_title() {
        // A subagent's "first user prompt" is the injected Task/Workflow prompt
        // BODY. Titles yes, content no: with no label material at all the
        // session stays unnamed rather than falling back to prompt text.
        let root = temp_dir("claude-subagent-no-prompt-title");
        let parent_session = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let task_dir = root.join(parent_session).join("subagents");
        fs::create_dir_all(&task_dir).expect("create dirs");
        let transcript = task_dir.join("agent-a58d4ac79525212cf.jsonl");
        fs::write(
            &transcript,
            format!(
                concat!(
                    "{{\"timestamp\":\"2026-07-24T13:00:00.000Z\",\"type\":\"user\",\"sessionId\":\"{parent}\",\"isSidechain\":true,\"message\":{{\"role\":\"user\",\"content\":\"Survey the quota tools\"}}}}\n",
                    "{{\"timestamp\":\"2026-07-24T13:00:05.000Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"isSidechain\":true,\"requestId\":\"req_P\",\"message\":{{\"id\":\"msg_P\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":6,\"output_tokens\":2}}}}}}\n"
                ),
                parent = parent_session
            ),
        )
        .expect("write transcript");

        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript,
            "2026-07-24T13:10:00Z",
            "fp".to_string(),
            &ClaudeTitleMetadata::default(),
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(item.session_display_name, None);
        assert_eq!(item.session_display_name_source, None);
        // An ordinary top-level transcript with the same shape keeps the
        // first-prompt fallback — the suppression is subagent-scoped.
        let top_level = root.join("aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000.jsonl");
        fs::write(
            &top_level,
            concat!(
                "{\"timestamp\":\"2026-07-24T13:00:00.000Z\",\"type\":\"user\",\"sessionId\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000\",\"message\":{\"role\":\"user\",\"content\":\"Survey the quota tools\"}}\n",
                "{\"timestamp\":\"2026-07-24T13:00:05.000Z\",\"type\":\"assistant\",\"sessionId\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000\",\"requestId\":\"req_P\",\"message\":{\"id\":\"msg_P\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":6,\"output_tokens\":2}}}\n"
            ),
        )
        .expect("write top-level transcript");
        let top_item = parse_claude_code_jsonl_file_with_title_metadata(
            &top_level,
            "2026-07-24T13:10:00Z",
            "fp".to_string(),
            &ClaudeTitleMetadata::default(),
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert_eq!(
            top_item.session_display_name.as_deref(),
            Some("Survey the quota tools")
        );
        assert_eq!(
            top_item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn safe_claude_agent_display_label_allowlist_and_truncation() {
        // Real observed values survive unchanged.
        for value in [
            "probe:data-model",
            "verify:daemon-scan-claim",
            "map:collector-daemon",
            "Fix 2 failing + 1 flaky backend integration tests",
        ] {
            // `+` is allowlisted; everything observed must round-trip.
            assert_eq!(
                safe_claude_agent_display_label(value.to_string()).as_deref(),
                Some(value),
                "{value} must survive"
            );
        }
        // Whitespace collapses like every other title path.
        assert_eq!(
            safe_claude_agent_display_label("  probe:\n desktop-path ".to_string()).as_deref(),
            Some("probe: desktop-path")
        );
        // Truncated at the cap, not rejected.
        let long = "a".repeat(200);
        assert_eq!(
            safe_claude_agent_display_label(long)
                .expect("truncated")
                .chars()
                .count(),
            MAX_CLAUDE_AGENT_LABEL_CHARS
        );
        // Paths, home fragments, non-ASCII, and control smuggling are dropped.
        for hostile in [
            "/Users/someone/secret",
            "see /home/user/notes",
            "read ~/.claude/settings",
            "café découverte",
            "line\u{7}bell",
            "back\\slash",
        ] {
            assert_eq!(
                safe_claude_agent_display_label(hostile.to_string()),
                None,
                "{hostile:?} must be dropped"
            );
        }
    }

    #[test]
    fn claude_subagent_sidecar_fingerprint_tracks_naming_material() {
        let root = temp_dir("claude-subagent-sidecar-fp");
        let parent_session = "58e9c6bc-c733-4946-b9e4-aa57c707dbf2";
        let session_dir = root.join(parent_session);
        let workflow_dir = session_dir
            .join("subagents")
            .join("workflows")
            .join("wf_f7ae7a92-02b");
        fs::create_dir_all(&workflow_dir).expect("create dirs");
        let transcript = workflow_dir.join("agent-a09c3096ec4de4f11.jsonl");
        fs::write(&transcript, "{}\n").expect("write transcript");
        let identity = claude_subagent_identity(&transcript).expect("identity");

        let baseline = claude_subagent_sidecar_fingerprint(&transcript, &identity);
        assert_eq!(
            baseline,
            claude_subagent_sidecar_fingerprint(&transcript, &identity),
            "fingerprint must be deterministic"
        );

        // A workflow manifest appearing later re-selects the transcript.
        fs::create_dir_all(session_dir.join("workflows")).expect("create manifest dir");
        fs::write(
            session_dir.join("workflows").join("wf_f7ae7a92-02b.json"),
            "{\"workflowProgress\":[]}",
        )
        .expect("write manifest");
        let with_manifest = claude_subagent_sidecar_fingerprint(&transcript, &identity);
        assert_ne!(baseline, with_manifest);

        // So does a meta sidecar appearing...
        fs::write(
            workflow_dir.join("agent-a09c3096ec4de4f11.meta.json"),
            "{\"agentType\":\"workflow-subagent\"}",
        )
        .expect("write sidecar");
        let with_meta = claude_subagent_sidecar_fingerprint(&transcript, &identity);
        assert_ne!(with_manifest, with_meta);

        let _ = fs::remove_dir_all(root);
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
    fn claude_code_parser_pairs_current_and_legacy_compaction_records() {
        let path = temp_file("claude-compaction-count");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-07-01T11:00:00Z\",\"sessionId\":\"claude-compact-1\",\"requestId\":\"req_011AAA\",\"message\":{\"id\":\"msg_011AAA\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":50,\"output_tokens\":5}}}\n",
                // Real provider order: boundary first, then its legacy summary
                // with a timestamp three milliseconds earlier.
                "{\"timestamp\":\"2026-07-01T11:01:00.003Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{\"trigger\":\"auto\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:01:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":true,\"isVisibleInTranscriptOnly\":true,\"message\":{\"role\":\"user\",\"content\":\"summary\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:02:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":false,\"message\":{\"role\":\"user\",\"content\":\"regular prompt\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:03:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"user\",\"isCompactSummary\":true,\"isVisibleInTranscriptOnly\":true,\"message\":{\"role\":\"user\",\"content\":\"summary again\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:04:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"assistant\",\"isCompactSummary\":true,\"message\":{\"role\":\"assistant\",\"content\":\"not a compaction event\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:05:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{\"trigger\":\"auto\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:06:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{\"trigger\":\"manual\"}}\n",
                "{\"timestamp\":\"2026-07-01T11:07:00Z\",\"sessionId\":\"claude-compact-1\",\"type\":\"system\",\"subtype\":\"status\"}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-07-01T11:08:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");

        assert_eq!(item.compaction_count, Some(4));
        assert_eq!(
            item.compaction_timestamps,
            vec![
                "2026-07-01T11:01:00.003Z".to_string(),
                "2026-07-01T11:03:00Z".to_string(),
                "2026-07-01T11:05:00Z".to_string(),
                "2026-07-01T11:06:00Z".to_string(),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn compaction_timeline_keeps_newest_64_for_snapshot_upload() {
        let mut timestamps = (0..72)
            .map(|index| {
                let day = index / 24 + 1;
                let hour = index % 24;
                format!("2026-07-{day:02}T{hour:02}:00:00Z")
            })
            .collect::<Vec<_>>();
        timestamps.reverse();
        timestamps.push("2026-07-03T23:00:00Z".to_string());

        let bounded = bounded_compaction_timestamps(timestamps);

        assert_eq!(bounded.len(), MAX_COMPACTION_TIMESTAMPS);
        assert_eq!(
            bounded.first().map(String::as_str),
            Some("2026-07-01T08:00:00Z")
        );
        assert_eq!(
            bounded.last().map(String::as_str),
            Some("2026-07-03T23:00:00Z")
        );
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
        assert_eq!(
            item.compaction_timestamps,
            vec!["2026-07-17T03:04:00Z".to_string()]
        );

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
        without_posture.compaction_timestamps.clear();
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
        assert!(item.compaction_timestamps.is_empty());
        let serialized = serde_json::to_value(&item).expect("serialize");
        assert!(serialized.get("peak_context_fill_tokens").is_none());
        assert!(serialized.get("first_turn_context_tokens").is_none());
        assert!(serialized.get("compaction_count").is_none());
        assert!(serialized.get("compaction_timestamps").is_none());

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
        let expected_hash =
            ottto_core::billing_identity_hash("anthropic", "account", "account-ctx")
                .expect("account hash");
        assert!(item
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str())));
        assert!(item.usage_buckets.iter().all(|bucket| bucket
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str()))));
        let serialized = serde_json::to_string(&item).expect("serialize snapshot");
        assert!(serialized.contains("account_identifier_hash"));
        assert!(!serialized.contains("account-ctx"));
        let mut without_account = item.clone();
        for row in &mut without_account.model_usage {
            row.account_identifier_hash = None;
        }
        for bucket in &mut without_account.usage_buckets {
            for row in &mut bucket.model_usage {
                row.account_identifier_hash = None;
            }
        }
        let with_account_components =
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &item);
        let without_account_components =
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &without_account);
        assert_eq!(
            policy_neutral_component_hashes(&with_account_components),
            policy_neutral_component_hashes(&without_account_components),
            "hash epoch 1 excludes the later account-identity wire field"
        );
        assert_ne!(
            snapshot_fingerprint_from_component_hashes(
                SnapshotSource::ClaudeCode,
                &item.source_session_id,
                &with_account_components,
            ),
            snapshot_fingerprint_from_component_hashes(
                SnapshotSource::ClaudeCode,
                &without_account.source_session_id,
                &without_account_components,
            ),
            "account evidence must escape semantic no-op suppression"
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn late_claude_desktop_account_mapping_escapes_semantic_noop_suppression() {
        let session_id = "33333333-4444-5555-6666-777777777777";
        let home = temp_dir("claude-desktop-account-late-mapping");
        let projects_root = home.join(".claude").join("projects");
        let project_dir = projects_root.join("-Users-dev-repo");
        fs::create_dir_all(&project_dir).expect("create project dir");
        fs::write(
            project_dir.join(format!("{session_id}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-07-31T10:01:00Z\",\"sessionId\":\"{session_id}\",\"message\":{{\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n"
            ),
        )
        .expect("write transcript");

        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_eq!(first.snapshots.len(), 1);
        assert!(first.snapshots[0]
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.is_none()));

        let store_dir = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-late")
            .join("workspace");
        fs::create_dir_all(&store_dir).expect("create Desktop store");
        fs::write(
            store_dir.join("local_desktop-late.json"),
            format!("{{\"cliSessionId\":\"{session_id}\"}}"),
        )
        .expect("write late account mapping");

        let second = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second scan");
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(second.semantic_noop_count, 0);
        assert_eq!(second.snapshots.len(), 1);
        let expected_hash =
            ottto_core::billing_identity_hash("anthropic", "account", "account-late")
                .expect("account hash");
        assert!(second.snapshots[0]
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str())));

        let settled = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert!(settled.snapshots.is_empty());

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn late_claude_otel_account_evidence_reselects_unchanged_transcript() {
        let session_id = "44444444-5555-6666-7777-888888888888";
        let home = temp_dir("claude-otel-account-late-mapping");
        let support_dir = home.join("support");
        let projects_root = home.join(".claude").join("projects");
        let project_dir = projects_root.join("-Users-dev-repo");
        fs::create_dir_all(&project_dir).expect("create project dir");
        fs::write(
            project_dir.join(format!("{session_id}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-07-31T10:01:00Z\",\"sessionId\":\"{session_id}\",\"message\":{{\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n"
            ),
        )
        .expect("write transcript");

        let mut index = ScanIndex::default();
        let mut first = scan_source_roots_with_attribution_and_claude_effort(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
            true,
            None,
            Some(&support_dir),
        )
        .expect("first scan");
        assert_eq!(first.snapshots.len(), 1);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut first, &mut index);

        let body = format!(
            "{{\"resourceLogs\":[{{\"scopeLogs\":[{{\"logRecords\":[{{\"timeUnixNano\":\"1785492120000000000\",\"body\":{{\"stringValue\":\"claude_code.api_request\"}},\"attributes\":[{{\"key\":\"session.id\",\"value\":{{\"stringValue\":\"{session_id}\"}}}},{{\"key\":\"user.account_uuid\",\"value\":{{\"stringValue\":\"123E4567-E89B-12D3-A456-426614174000\"}}}},{{\"key\":\"model\",\"value\":{{\"stringValue\":\"claude-opus-4-8\"}}}},{{\"key\":\"input_tokens\",\"value\":{{\"intValue\":\"35\"}}}},{{\"key\":\"output_tokens\",\"value\":{{\"intValue\":\"8\"}}}}]}}]}}]}}]}}"
        );
        assert_eq!(
            crate::claude_effort::capture_claude_api_request_logs(
                &support_dir,
                body.as_bytes(),
                "application/json",
            )
            .expect("capture account evidence"),
            1
        );

        let mut second = scan_source_roots_with_attribution_and_claude_effort(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
            true,
            None,
            Some(&support_dir),
        )
        .expect("second scan");
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(second.semantic_noop_count, 0);
        assert_eq!(second.snapshots.len(), 1);

        let evidence = crate::claude_effort::load_claude_effort_evidence(
            &support_dir,
            [session_id.to_string()],
        )
        .expect("load account evidence");
        apply_claude_effort_evidence(&mut second.snapshots, &evidence);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut second, &mut index);
        let expected_hash = ottto_core::billing_identity_hash(
            "anthropic",
            "account",
            "123e4567-e89b-12d3-a456-426614174000",
        )
        .expect("account hash");
        assert!(second.snapshots[0]
            .model_usage
            .iter()
            .chain(
                second.snapshots[0]
                    .usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter())
            )
            .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str())));

        let settled = scan_source_roots_with_attribution_and_claude_effort(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-31T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
            true,
            None,
            Some(&support_dir),
        )
        .expect("settled scan");
        assert!(settled.snapshots.is_empty());

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_desktop_account_identity_fails_closed_across_accounts() {
        let session_id = "22222222-3333-4444-5555-666666666666";
        let desktop_json = format!(
            "{{\"cliSessionId\":\"{session_id}\",\"title\":\"Shared session\",\"titleSource\":\"auto\"}}"
        );
        let transcript = format!(
            "{{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"{session_id}\",\"message\":{{\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n"
        );
        let (home, transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-account-ambiguity",
            session_id,
            &desktop_json,
            &transcript,
        );
        let second_store = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-other")
            .join("workspace");
        fs::create_dir_all(&second_store).expect("create second account store");
        fs::write(second_store.join("local_desktop-2.json"), &desktop_json)
            .expect("write second account session");

        let ambiguous = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert!(ambiguous.account_identifier_hash(session_id).is_none());
        let ambiguous_fingerprint = ambiguous.session_sidecar_fingerprint(session_id);
        let item = parse_claude_code_jsonl_file_with_title_metadata(
            &transcript_path,
            "2026-07-10T10:04:00Z",
            "fp".to_string(),
            &ambiguous,
            true,
        )
        .expect("parse")
        .into_iter()
        .next()
        .expect("snapshot");
        assert!(item
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.is_none()));

        // Negative control: removing the conflicting account makes the exact
        // mapping load-bearing and must change both selection fingerprint and
        // emitted attribution. An implementation that always matched would
        // fail the ambiguity assertions above.
        fs::remove_dir_all(
            home.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude-code-sessions")
                .join("account-other"),
        )
        .expect("remove conflicting account");
        let exact = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_ne!(
            ambiguous_fingerprint,
            exact.session_sidecar_fingerprint(session_id)
        );
        let expected_hash =
            ottto_core::billing_identity_hash("anthropic", "account", "account-ctx")
                .expect("account hash");
        assert_eq!(
            exact.account_identifier_hash(session_id),
            Some(expected_hash.as_str())
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
    fn claude_title_metadata_fingerprint_is_content_stable_and_session_scoped() {
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
        let unrelated_before = first.session_sidecar_fingerprint("unrelated-session");

        // Rewriting the file with the SAME title (mtime/size churn from
        // ordinary session activity) must keep the fingerprint stable...
        fs::write(
            &store_file,
            "{\"cliSessionId\":\"s-3\",\"title\":\"First title\",\"titleSource\":\"auto\",\"lastFocusedAt\":\"2026-07-10T11:00:00Z\"}",
        )
        .expect("rewrite store");
        let same = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_eq!(
            first.session_sidecar_fingerprint("s-3"),
            same.session_sidecar_fingerprint("s-3")
        );

        // ...while an actual title change must change it so unchanged
        // transcripts re-parse and pick the new title up.
        fs::write(
            &store_file,
            "{\"cliSessionId\":\"s-3\",\"title\":\"Second title\",\"titleSource\":\"user\"}",
        )
        .expect("rewrite store with new title");
        let changed = ClaudeTitleMetadata::load_from_roots(std::slice::from_ref(&projects_root));
        assert_ne!(
            first.session_sidecar_fingerprint("s-3"),
            changed.session_sidecar_fingerprint("s-3")
        );
        assert_eq!(
            unrelated_before,
            changed.session_sidecar_fingerprint("unrelated-session")
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_desktop_store_pages_past_five_thousand_and_resumes_correction() {
        let session_id = "late-prefix-session";
        let (home, _transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-paged-title",
            session_id,
            "{}",
            "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"late-prefix-session\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":35,\"output_tokens\":8}}}\n",
        );
        let store_dir = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-ctx")
            .join("workspace");
        fs::remove_file(store_dir.join("local_desktop-1.json")).expect("remove base sidecar");
        for value in 0..MAX_CLAUDE_DESKTOP_SESSION_FILES {
            fs::write(store_dir.join(format!("{value:05}.json")), b"{}")
                .expect("write bounded filler sidecar");
        }
        fs::write(
            store_dir.join("zzzzz-late.json"),
            format!(
                "{{\"cliSessionId\":\"{session_id}\",\"title\":\"Recovered late desktop title\",\"titleSource\":\"user\"}}"
            ),
        )
        .expect("write late-prefix title");

        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first bounded sidecar page");
        assert!(!first.sidecar_census_complete);
        assert_eq!(first.snapshots.len(), 1);
        assert_ne!(
            first.snapshots[0].session_display_name.as_deref(),
            Some("Recovered late desktop title")
        );

        let checkpoint = home.join("scanner-index.json");
        index
            .save(&checkpoint)
            .expect("persist sidecar page cursor");
        let mut resumed = ScanIndex::load(&checkpoint).expect("resume sidecar page cursor");
        let second = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut resumed,
            "2026-07-10T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("second bounded sidecar page");
        assert!(second.sidecar_census_complete);
        assert_eq!(second.snapshots.len(), 1);
        assert_eq!(
            second.snapshots[0].session_display_name.as_deref(),
            Some("Recovered late desktop title")
        );

        let third = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut resumed,
            "2026-07-10T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("unchanged correction is a semantic no-op");
        assert!(third.snapshots.is_empty());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn malformed_claude_title_file_preserves_prior_title_and_marks_census_incomplete() {
        let (home, _transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-malformed-retain",
            "retain-session",
            "{\"cliSessionId\":\"retain-session\",\"title\":\"Known durable title\",\"titleSource\":\"user\"}",
            "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"retain-session\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
        );
        let store_file = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-ctx")
            .join("workspace")
            .join("local_desktop-1.json");
        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("seed durable title");
        assert_eq!(
            first.snapshots[0].session_display_name.as_deref(),
            Some("Known durable title")
        );

        fs::write(&store_file, b"{not valid json}").expect("corrupt title sidecar");
        let second = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:05:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("malformed title is isolated");
        assert!(!second.sidecar_census_complete);
        assert!(!second.census_complete);
        assert!(
            second.snapshots.is_empty(),
            "the retained title keeps the transcript a semantic no-op"
        );
        assert_eq!(
            index
                .claude_desktop_title_files
                .values()
                .next()
                .and_then(|entry| entry.title.as_deref()),
            Some("Known durable title")
        );

        fs::write(
            &store_file,
            "{\"cliSessionId\":\"retain-session\",\"title\":\"Recovered durable title\",\"titleSource\":\"user\"}",
        )
        .expect("repair title sidecar");
        let backed_off = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:05:30Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("sidecar retry remains bounded");
        assert!(!backed_off.sidecar_census_complete);
        assert!(backed_off.snapshots.is_empty());

        let recovered = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:06:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("sidecar retry recovers on deadline");
        assert!(recovered.sidecar_census_complete);
        assert!(recovered.census_complete);
        assert_eq!(recovered.snapshots.len(), 1);
        assert_eq!(
            recovered.snapshots[0].session_display_name.as_deref(),
            Some("Recovered durable title")
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn one_sided_claude_title_shapes_preserve_account_only_mapping() {
        let (home, _transcript_path, projects_root) = claude_desktop_fixture(
            "claude-desktop-one-sided",
            "no-title-session",
            "{\"cliSessionId\":\"no-title-session\",\"sessionId\":\"desktop-session\"}",
            "{\"timestamp\":\"2026-07-10T10:01:00Z\",\"sessionId\":\"no-title-session\",\"message\":{\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
        );
        let store_dir = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("account-ctx")
            .join("workspace");
        fs::write(
            store_dir.join("desktop-only.json"),
            "{\"sessionId\":\"desktop-only\",\"title\":\"Desktop only title\"}",
        )
        .expect("write desktop-only title");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects_root),
            &mut index,
            "2026-07-10T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan one-sided optional title shapes");
        assert!(scan.sidecar_census_complete);
        assert!(scan.census_complete);
        assert_eq!(index.claude_desktop_title_files.len(), 1);
        assert_eq!(scan.snapshots.len(), 1);
        assert!(scan.snapshots[0].session_display_name.is_none());
        let expected_hash =
            ottto_core::billing_identity_hash("anthropic", "account", "account-ctx")
                .expect("account hash");
        assert!(scan.snapshots[0]
            .model_usage
            .iter()
            .all(|row| row.account_identifier_hash.as_deref() == Some(expected_hash.as_str())));
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn claude_title_store_entry_budget_fails_red_without_unbounded_walk() {
        let root = temp_dir("claude-title-entry-budget");
        for index in 0..4 {
            fs::write(
                root.join(format!("session-{index}.json")),
                format!("{{\"cliSessionId\":\"session-{index}\",\"title\":\"Title {index}\"}}"),
            )
            .expect("write title budget fixture");
        }
        let mut selection = BoundedPathSelection::new(None, None, 10);
        let mut census = ClaudeDesktopStoreCensus::default();
        let mut remaining_entries = 3;
        collect_claude_desktop_session_files(
            &root,
            0,
            &mut remaining_entries,
            &mut selection,
            &mut census,
        );
        assert_eq!(remaining_entries, 0);
        assert_eq!(census.entry_budget_exceeded_count, 1);
        assert_eq!(census.discovered_file_count, 3);
        assert!(census.has_errors());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_claude_store_directory_marks_sidecar_census_incomplete() {
        let root = temp_dir("claude-desktop-unreadable-directory");
        let not_a_directory = root.join("store-file");
        fs::write(&not_a_directory, b"not a directory").expect("write directory impostor");
        let mut index = ScanIndex::default();
        let metadata = ClaudeTitleMetadata::load_from_store_dirs_with_index(
            &BTreeSet::from([not_a_directory]),
            &mut index,
            "2026-07-31T00:00:00Z",
        );
        assert!(metadata.sidecar_census_incomplete);
        assert!(metadata.titles.is_empty());
        let _ = fs::remove_dir_all(root);
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
    fn claude_transcript_custom_title_beats_first_prompt() {
        let path = temp_file("claude-custom-title");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"user\",\"sessionId\":\"37227cb3-9bd5-41c9-9fbc-85652afe8793\",\"message\":{\"role\":\"user\",\"content\":\"repair this pull request\"}}\n",
                "{\"type\":\"custom-title\",\"customTitle\":\"pr-fixer-3532-37227cb3\"}\n",
                "{\"timestamp\":\"2026-07-29T10:33:00Z\",\"sessionId\":\"37227cb3-9bd5-41c9-9fbc-85652afe8793\",\"message\":{\"model\":\"claude-sonnet-5\",\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n",
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(&path, "2026-07-29T10:34:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.session_display_name.as_deref(), Some("Fix PR #3532"));
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("transcript_title")
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
    fn pi_parser_sums_legacy_message_end_usage_and_extracts_session_meta() {
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
    fn pi_legacy_message_end_prefers_provider_timestamp_over_envelope_time() {
        let path = temp_file("pi-legacy-timestamp-precedence");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"fixture-session\",\"timestamp\":\"2026-07-22T10:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"timestamp\":\"2026-07-22T11:00:01Z\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":\"2026-07-22T10:59:59Z\",\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write legacy timestamp precedence fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T11:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.usage_buckets.len(), 1);
        assert_eq!(item.usage_buckets[0].bucket_start, "2026-07-22T10:00:00Z");
        assert_eq!(
            item.usage_buckets[0].last_activity_at.as_deref(),
            Some("2026-07-22T10:59:59Z")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_reads_current_nested_message_shape() {
        let path = temp_file("pi-current-message");
        fs::write(
            &path,
            include_str!("../../../fixtures/snapshot-audit/pi-session-current.jsonl"),
        )
        .expect("write current Pi fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T08:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "fixture-session-019e2700-1111-7000-9000-111111111111"
        );
        assert_eq!(item.input_tokens, 12);
        assert_eq!(item.output_tokens, 4);
        assert_eq!(item.request_count, 1);
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.model_usage[0].model, "gpt-5.4");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Summarize the fixture change")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );
        assert_eq!(
            item.source_started_at.as_deref(),
            Some("2026-07-22T08:00:00Z")
        );
        assert_eq!(
            item.source_last_activity_at.as_deref(),
            Some("2026-07-22T08:00:01.000Z")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_dedupes_transitional_message_and_message_end_records() {
        let path = temp_file("pi-current-legacy-dedup");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write transitional fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T08:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.input_tokens, 12);
        assert_eq!(item.output_tokens, 4);
        assert_eq!(item.request_count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_transitional_pair_uses_provider_time_across_hour_boundary() {
        let path = temp_file("pi-provider-time-dedup");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T10:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T11:00:01Z\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":\"2026-07-22T10:59:59Z\",\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"timestamp\":\"2026-07-22T11:00:02Z\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":\"2026-07-22T10:59:59.000Z\",\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write provider-time fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T11:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.request_count, 1);
        assert_eq!(item.usage_buckets.len(), 1);
        assert_eq!(item.usage_buckets[0].bucket_start, "2026-07-22T10:00:00Z");
        assert_eq!(
            item.source_last_activity_at.as_deref(),
            Some("2026-07-22T10:59:59Z")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_reused_response_id_reconciles_every_cross_shape_occurrence() {
        let root = temp_dir("pi-reused-response-id-pairs");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"reused-response\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"reused-response\",\"timestamp\":\"2026-07-22T08:00:02Z\",\"usage\":{\"input\":20,\"output\":5}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"reused-response\",\"timestamp\":\"2026-07-22T08:00:01.000Z\",\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"reused-response\",\"timestamp\":\"2026-07-22T08:00:02.000Z\",\"usage\":{\"input\":20,\"output\":5}}}\n",
            ),
        )
        .expect("write reused response-id fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan reused response-id fixture");

        assert!(scan.census_complete);
        assert_eq!(scan.dropped_usage_record_count, 0);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(scan.snapshots[0].input_tokens, 32);
        assert_eq!(scan.snapshots[0].output_tokens, 9);
        assert_eq!(scan.snapshots[0].request_count, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_divergent_cross_shape_response_id_quarantines_the_file() {
        let root = temp_dir("pi-divergent-response-id");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":99,\"output\":4}}}\n",
            ),
        )
        .expect("write divergent response-id fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan divergent response-id fixture");

        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.dropped_usage_record_count, 1);
        assert!(!scan.census_complete);
        assert!(index.files.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_unmatched_divergence_after_exact_pair_quarantines_the_file() {
        let root = temp_dir("pi-divergent-response-id-after-pair");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707202000,\"usage\":{\"input\":99,\"output\":4}}}\n",
            ),
        )
        .expect("write partially paired divergent response-id fixture");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan partially paired divergent response-id fixture");

        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.dropped_usage_record_count, 1);
        assert!(!scan.census_complete);
        assert!(index.files.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_repeated_identical_occurrence_survives_one_compatibility_pair() {
        let path = temp_file("pi-repeated-identical-with-pair");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write repeated identical occurrence fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T08:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");
        assert_eq!(item.input_tokens, 24);
        assert_eq!(item.output_tokens, 8);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_does_not_dedupe_repeated_same_shape_response_ids() {
        let path = temp_file("pi-same-shape-response-id");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:02Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"responseId\":\"response-1\",\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write repeated same-shape fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T08:03:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.input_tokens, 24);
        assert_eq!(item.output_tokens, 8);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_keeps_identical_usage_without_response_ids_distinct() {
        let path = temp_file("pi-no-id-distinct");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write repeated id-less fixture");

        let item = parse_pi_jsonl_file(&path, "2026-07-22T08:02:00Z", "fp".to_string())
            .expect("parse")
            .into_iter()
            .next()
            .expect("snapshot");

        assert_eq!(item.input_tokens, 24);
        assert_eq!(item.output_tokens, 8);
        assert_eq!(item.request_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_timestamp_order_handles_fractional_rfc3339_and_invalid_fallbacks() {
        assert!(pi_timestamp_is_before(
            "2026-07-22T08:00:00Z",
            "2026-07-22T08:00:00.500Z"
        ));
        assert!(pi_timestamp_is_after(
            "2026-07-22T08:00:00.500Z",
            "2026-07-22T08:00:00Z"
        ));
        assert!(pi_timestamp_is_before("invalid-a", "invalid-b"));
        assert!(pi_timestamp_is_after("invalid-b", "invalid-a"));
        assert!(!pi_timestamp_is_before("invalid-a", "2026-07-22T08:00:00Z"));
        assert!(!pi_timestamp_is_after("invalid-b", "2026-07-22T08:00:00Z"));
        assert!(pi_timestamp_is_before("2026-07-22T08:00:00Z", "invalid-a"));
        assert!(pi_timestamp_is_after("2026-07-22T08:00:00Z", "invalid-b"));
    }

    #[test]
    fn pi_current_shape_scan_populates_manifest_and_settles_idempotently() {
        let root = temp_dir("pi-current-manifest");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            include_str!("../../../fixtures/snapshot-audit/pi-session-current.jsonl"),
        )
        .expect("write current Pi fixture");
        let mut index = ScanIndex::default();

        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        let first_manifest = index.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS);
        assert_eq!(first.discovered_file_count, 1);
        assert_eq!(first.scanned_file_count, 1);
        assert_eq!(first.scanned_session_count, 1);
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first_manifest.entity_count, 1);

        let second = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert_eq!(second.discovered_file_count, 1);
        assert_eq!(second.scanned_file_count, 0);
        assert_eq!(second.scanned_session_count, 0);
        assert!(second.snapshots.is_empty());
        assert_eq!(
            index.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS),
            first_manifest
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pi_scan_settles_the_observed_populated_and_genuine_empty_mix() {
        const POPULATED: usize = 426;
        const EMPTY: usize = 30;
        let root = temp_dir("pi-observed-populated-empty-mix");
        for index in 0..POPULATED + EMPTY {
            let session_id = format!("fixture-session-{index:04}");
            let content = if index < POPULATED {
                format!(
                    concat!(
                        "{{\"type\":\"session\",\"id\":\"{session_id}\",",
                        "\"timestamp\":\"2026-07-22T08:00:00Z\"}}\n",
                        "{{\"type\":\"message\",\"timestamp\":\"2026-07-22T08:00:01Z\",",
                        "\"message\":{{\"role\":\"assistant\",\"provider\":\"openai\",",
                        "\"model\":\"gpt-5.4\",\"usage\":{{\"input\":12,\"output\":4}}}}}}\n"
                    ),
                    session_id = session_id,
                )
            } else {
                format!(
                    "{{\"type\":\"session\",\"id\":\"{session_id}\",\"timestamp\":\"2026-07-22T08:00:00Z\"}}\n"
                )
            };
            fs::write(root.join(format!("session-{index:04}.jsonl")), content)
                .expect("write observed-shape fixture");
        }
        let mut index = ScanIndex::default();

        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("first scan");
        assert_eq!(first.discovered_file_count, POPULATED + EMPTY);
        assert_eq!(first.scanned_file_count, POPULATED + EMPTY);
        assert_eq!(first.scanned_session_count, POPULATED);
        assert_eq!(first.snapshots.len(), POPULATED);
        assert_eq!(first.zero_snapshot_usage_evidence_count, 0);
        assert_eq!(index.confirmed_empty_files.len(), EMPTY);
        let manifest = index.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS);
        assert_eq!(manifest.entity_count, POPULATED as u64);

        let settled = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled scan");
        assert_eq!(settled.discovered_file_count, POPULATED + EMPTY);
        assert_eq!(settled.scanned_file_count, 0);
        assert_eq!(settled.scanned_session_count, 0);
        assert!(settled.snapshots.is_empty());
        assert_eq!(settled.zero_snapshot_usage_evidence_count, 0);
        assert_eq!(
            index.manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS),
            manifest
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parser_identity_change_that_yields_zero_clears_the_manifest_contribution() {
        let root = temp_dir("pi-parser-regression-clears-manifest");
        let path = root.join("session.jsonl");
        fs::write(
            &path,
            "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n",
        )
        .expect("write genuine empty transcript");
        let mut index = ScanIndex::default();
        let first = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("establish empty checkpoint");
        assert_eq!(first.scanned_file_count, 1);
        let key = path.to_string_lossy().to_string();
        index.confirmed_empty_files.remove(&key);
        let entry = index.files.get_mut(&key).expect("index entry");
        entry.last_snapshot_fingerprint = Some("previous-server-snapshot".to_string());
        entry.source_file_fingerprint = "previous-parser-identity".to_string();

        let reparsed = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:03:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("reparse after identity change");
        assert_eq!(reparsed.scanned_file_count, 1);
        assert_eq!(reparsed.scanned_session_count, 0);
        let entry = &index.files[&key];
        assert!(entry.last_snapshot_fingerprint.is_none());
        assert!(index.confirmed_empty_files.contains(&key));
        assert_eq!(
            index
                .manifest(SnapshotSource::Pi, BACKFILL_WINDOW_DAYS)
                .entity_count,
            0
        );

        let settled = scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-22T08:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("settled regression scan");
        assert_eq!(settled.scanned_file_count, 0);
        let _ = fs::remove_dir_all(root);
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
    fn pi_ms_timestamp_formats_bounded_rfc3339() {
        // Anchor on epoch 0 and a verifiable mid-2024 date.
        assert_eq!(
            bounded_rfc3339_millis(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        // 2024-01-01T00:00:00.000Z = 1_704_067_200 s = 1_704_067_200_000 ms
        assert_eq!(
            bounded_rfc3339_millis(1_704_067_200_000).as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
        // Sub-second granularity is preserved.
        assert_eq!(
            bounded_rfc3339_millis(1_704_067_200_123).as_deref(),
            Some("2024-01-01T00:00:00.123Z")
        );
        assert_eq!(bounded_rfc3339_millis(i64::MIN), None);
        assert_eq!(bounded_rfc3339_millis(i64::MAX), None);
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
                "{\"type\":\"message_end\",\"timestamp\":1747735200000,\"gatewayProvider\":\"openai\",\"modelProvider\":\"openai\",\"message\":{\"model\":\"gpt-5.5\",\"usage\":{\"input\":8,\"output\":6}}}\n",
                "{\"type\":\"message_end\",\"timestamp\":1747738800000,\"gatewayProvider\":\"google\",\"modelProvider\":\"google\",\"message\":{\"model\":\"gemini-2.5\",\"usage\":{\"input\":3,\"output\":7}}}\n"
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
        assert_eq!(
            item.usage_buckets
                .iter()
                .map(|bucket| bucket.bucket_start.as_str())
                .collect::<Vec<_>>(),
            [
                "2025-05-20T09:00:00Z",
                "2025-05-20T10:00:00Z",
                "2025-05-20T11:00:00Z",
            ]
        );

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
            "semantic_envelope",
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
            "compaction_timestamps",
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
            account_identifier_hash: None,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        let mut item = SnapshotItem {
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
            compaction_timestamps: Vec::new(),
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
            originator: None,
            attribution_facts: Vec::new(),
        };
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::ClaudeCode.api_slug().to_string(),
            machine_id: "machine-contract-0001".to_string(),
            collector_version: Some("local-enriched/1".to_string()),
            snapshots: vec![item],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
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
    fn v6_snapshot_preflight_rejects_oversized_compaction_timeline() {
        let mut request = valid_v6_batch_request();
        request.snapshots[0].compaction_timestamps =
            vec!["2026-07-20T12:00:00Z".to_string(); MAX_COMPACTION_TIMESTAMPS + 1];

        let error = validate_snapshot_batch_request(&request).expect_err("preflight rejects");

        assert!(
            error.contains("more than 64 compaction_timestamps"),
            "{error}"
        );
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
            account_identifier_hash: None,
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
                compaction_timestamps: Vec::new(),
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
                originator: None,
                attribution_facts: Vec::new(),
            }],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        }
    }

    #[test]
    fn snapshot_preflight_enforces_item_and_batch_wire_byte_caps() {
        let source = SnapshotSource::ClaudeCode;
        let mut oversized_item = valid_v6_batch_request();
        oversized_item.snapshots[0].session_display_name =
            Some("x".repeat(MAX_SNAPSHOT_ITEM_WIRE_BYTES));
        oversized_item.snapshots[0].snapshot_fingerprint =
            snapshot_fingerprint(source, &oversized_item.snapshots[0]);
        let item_error = validate_snapshot_batch_request(&oversized_item)
            .expect_err("oversized item fails before network I/O");
        assert!(item_error.contains("wire body"), "{item_error}");

        let mut batch = valid_v6_batch_request();
        let mut items = Vec::new();
        for index in 0..40 {
            let mut item = batch.snapshots[0].clone();
            item.source_session_id = format!("large-session-{index}");
            item.session_display_name = Some("y".repeat(110 * 1024));
            item.snapshot_fingerprint = snapshot_fingerprint(source, &item);
            items.push(item);
        }
        batch.snapshots = items;
        let batch_error = validate_snapshot_batch_request(&batch)
            .expect_err("oversized batch fails before network I/O");
        assert!(batch_error.contains("batch wire body"), "{batch_error}");
    }

    #[test]
    fn semantic_envelope_cross_language_golden_covers_all_valid_policies() {
        let mut base = valid_v6_batch_request()
            .snapshots
            .into_iter()
            .next()
            .expect("fixture snapshot");
        base.source_session_id = "session-שלום-東京-null".to_string();
        base.session_display_name = Some("כותרת 東京".to_string());
        base.session_display_name_source = Some("fixture".to_string());
        base.workspace_display_label = Some("workspace-é".to_string());
        base.workspace_label_source = Some("fixture".to_string());
        base.repository_label = Some("repo-東京".to_string());
        base.repository_label_source = Some("fixture".to_string());
        base.session_artifacts = vec![SessionArtifact {
            kind: "pull_request".to_string(),
            value: "https://github.com/example/repo/pull/7".to_string(),
        }];
        base.origin = Some(SnapshotOrigin {
            thread_source: Some("subagent".to_string()),
            originator: Some("codex_work_desktop".to_string()),
            ..SnapshotOrigin::default()
        });

        let mut cases = Vec::new();
        for source in [
            SnapshotSource::Pi,
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
        ] {
            for policy in crate::snapshot_audit::valid_upload_policies() {
                let mut item = base.clone();
                apply_upload_policy(source, std::slice::from_mut(&mut item), policy);
                let component_hashes = snapshot_semantic_component_hashes(source, &item);
                item.snapshot_fingerprint = snapshot_fingerprint_from_component_hashes(
                    source,
                    &item.source_session_id,
                    &component_hashes,
                );
                let envelope = snapshot_semantic_envelope(source, &item, policy);
                let content_body = snapshot_content_identity_body(
                    source,
                    &item.source_session_id,
                    &envelope.component_hashes,
                );
                let canonical_bytes = crate::canonical_json::canonicalize(&content_body)
                    .expect("canonicalize content identity body");
                let revision_v2_body =
                    snapshot_revision_v2_body(source, &item, policy, &envelope.component_hashes);
                cases.push(json!({
                    "source": source.api_slug(),
                    "source_session_id": item.source_session_id,
                    "upload_policy": policy,
                    "component_hashes": envelope.component_hashes,
                    // The `content_hash` inputs travel with the expected hash so
                    // the other language recomputes the canonicalization from
                    // the same material instead of trusting a copied digest.
                    "policy_neutral_component_hashes":
                        policy_neutral_component_hashes(&envelope.component_hashes),
                    "snapshot_fingerprint": item.snapshot_fingerprint,
                    "revision_hash": envelope.revision_hash,
                    "revision_v2_body": revision_v2_body,
                    "revision_v2_hash": envelope.revision_v2_hash,
                    "content_hash": envelope.content_hash,
                    "hash_epoch": envelope.hash_epoch,
                    "content_canonical_bytes": canonical_bytes.len(),
                    "envelope_bytes": serde_json::to_vec(&envelope).expect("serialize envelope").len(),
                }));
            }
        }
        let actual = json!({
            "schema_version": "semantic_envelope_golden:v3",
            "component_contract_version": SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
            "revision_contract_version": SNAPSHOT_REVISION_CONTRACT_VERSION,
            "revision_v2_contract_version": SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
            "canonicalization": crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
            "content_hash_epoch": SNAPSHOT_CONTENT_HASH_EPOCH,
            "policy_neutral_components": POLICY_NEUTRAL_COMPONENTS,
            "cases": cases,
        });
        if std::env::var_os("UPDATE_SEMANTIC_ENVELOPE_GOLDEN").is_some() {
            fs::write(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/snapshot-audit/semantic-envelope-golden.json"),
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&actual).expect("serialize golden")
                ),
            )
            .expect("write semantic envelope golden");
        }
        let expected: Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/semantic-envelope-golden.json"
        ))
        .expect("parse semantic envelope golden");
        assert_eq!(actual, expected);
        assert_eq!(actual["cases"].as_array().expect("cases").len(), 60);
        assert!(actual["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .all(|case| case["envelope_bytes"].as_u64().expect("size")
                <= MAX_SEMANTIC_ENVELOPE_BYTES as u64));
        // The policy toggles are what the corpus sweeps, so the corpus itself
        // is the strongest available statement that identity survives them: for
        // each source, all twenty policies must agree on `content_hash` while
        // the full component set does not.
        for source in ["pi", "codex", "claude_code"] {
            let per_source = actual["cases"]
                .as_array()
                .expect("cases")
                .iter()
                .filter(|case| case["source"] == source)
                .collect::<Vec<_>>();
            assert_eq!(per_source.len(), 20);
            let content_hashes = per_source
                .iter()
                .map(|case| case["content_hash"].as_str().expect("content hash"))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                content_hashes.len(),
                1,
                "content_hash must not depend on upload policy"
            );
            let fingerprints = per_source
                .iter()
                .map(|case| case["snapshot_fingerprint"].as_str().expect("fingerprint"))
                .collect::<BTreeSet<_>>();
            assert!(
                fingerprints.len() > 1,
                "the policy-scoped fingerprint must still move with policy"
            );
        }
    }

    #[test]
    fn content_hash_ignores_scan_state_parser_provenance_and_display_policy() {
        // The exclusion list from the identity contract, one mutation each. Any
        // of these changing `content_hash` would re-mint every session's
        // identity on a scan, a parser bump, or a privacy toggle.
        let source = SnapshotSource::ClaudeCode;
        let base = valid_v6_batch_request()
            .snapshots
            .into_iter()
            .next()
            .expect("fixture snapshot");
        let content_hash = |item: &SnapshotItem| {
            snapshot_content_hash(
                source,
                &item.source_session_id,
                &snapshot_semantic_component_hashes(source, item),
            )
        };
        let expected = content_hash(&base);

        let mut scan_time = base.clone();
        scan_time.collected_at = "2027-01-01T00:00:00Z".to_string();
        assert_eq!(content_hash(&scan_time), expected, "scan time");

        let mut fingerprint = base.clone();
        fingerprint.source_file_fingerprint = Some("f".repeat(32));
        assert_eq!(content_hash(&fingerprint), expected, "file fingerprint");
        assert_ne!(
            snapshot_revision_hash(
                source,
                &fingerprint,
                &snapshot_semantic_component_hashes(source, &fingerprint)
            ),
            snapshot_revision_hash(
                source,
                &base,
                &snapshot_semantic_component_hashes(source, &base)
            ),
            "the revision hash — the re-upload trigger — must still move"
        );

        let mut collector = base.clone();
        collector.provenance.collector = "some_other_collector".to_string();
        collector.provenance.source_file_count = 41;
        assert_eq!(content_hash(&collector), expected, "collector provenance");

        let mut display = base.clone();
        display.session_display_name = Some("a title".to_string());
        display.session_display_name_source = Some("fixture".to_string());
        display.workspace_display_label = Some("a workspace".to_string());
        display.workspace_label_source = Some("fixture".to_string());
        display.session_artifacts = vec![SessionArtifact {
            kind: "pull_request".to_string(),
            value: "https://github.com/example/repo/pull/7".to_string(),
        }];
        assert_eq!(content_hash(&display), expected, "display identity");
        let mut suppressed = display.clone();
        apply_upload_policy(
            source,
            std::slice::from_mut(&mut suppressed),
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
                session_artifacts_enabled: false,
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
            },
        );
        assert_eq!(content_hash(&suppressed), expected, "policy suppression");

        // Parser and scan-identity versions are compile-time constants, so the
        // statement that they are outside identity is made structurally: the
        // canonical body carries neither, and it carries exactly five keys.
        let body = snapshot_content_identity_body(
            source,
            &base.source_session_id,
            &snapshot_semantic_component_hashes(source, &base),
        );
        assert_eq!(
            body.as_object()
                .expect("body object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "canonicalization",
                "components",
                "hash_epoch",
                "source",
                "source_session_id",
            ])
        );
        let encoded = body.to_string();
        for excluded in [
            source.parser_version(),
            source.scan_identity_version(),
            &base.collected_at,
        ] {
            assert!(
                !encoded.contains(excluded),
                "identity body must not carry {excluded}"
            );
        }
    }

    #[test]
    fn revision_v2_ignores_retry_clock_and_unrelated_inventory_but_binds_entity_witness() {
        let source = SnapshotSource::Codex;
        let policy = SnapshotUploadPolicy::default();
        let mut base = valid_v6_batch_request()
            .snapshots
            .into_iter()
            .next()
            .expect("fixture snapshot");
        let hashes = snapshot_semantic_component_hashes(source, &base);
        let expected = snapshot_revision_v2_hash(source, &base, policy, &hashes);

        base.collected_at = "2030-01-01T00:00:00Z".to_string();
        base.provenance.source_file_count = 9_999;
        assert_eq!(
            snapshot_revision_v2_hash(source, &base, policy, &hashes),
            expected,
            "retry wall clock and unrelated transcript inventory are not revision evidence"
        );

        base.source_file_fingerprint = Some("changed-opened-object-witness".to_string());
        assert_ne!(
            snapshot_revision_v2_hash(source, &base, policy, &hashes),
            expected,
            "the exact opened/source-file witness is revision evidence"
        );
    }

    #[test]
    fn revision_v2_projection_is_explicit_non_recursive_and_version_sensitive() {
        let source = SnapshotSource::Codex;
        let policy = SnapshotUploadPolicy::default();
        let item = valid_v6_batch_request()
            .snapshots
            .into_iter()
            .next()
            .expect("fixture snapshot");
        let hashes = snapshot_semantic_component_hashes(source, &item);
        let body = snapshot_revision_v2_body(source, &item, policy, &hashes);
        let object = body.as_object().expect("revision body object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "canonicalization",
                "component_hashes",
                "contract",
                "lifecycle",
                "parser_version",
                "provenance",
                "scan_identity_version",
                "source",
                "source_file_fingerprint",
                "source_session_id",
                "upload_policy",
            ])
        );
        let encoded = serde_json::to_string(&body).expect("revision body JSON");
        for forbidden in [
            "semantic_envelope",
            "revision_hash",
            "content_hash",
            "snapshot_fingerprint",
            "collected_at",
            "source_file_count",
            "challenge",
        ] {
            assert!(!encoded.contains(forbidden), "forbidden field {forbidden}");
        }

        let mut changed_parser = body;
        changed_parser["parser_version"] = json!("codex_jsonl:future");
        let canonical = crate::canonical_json::canonicalize(&changed_parser)
            .expect("changed parser body canonicalizes");
        let mut digest = Sha256::new();
        digest.update(canonical);
        assert_ne!(
            format!("{:x}", digest.finalize()),
            snapshot_revision_v2_hash(source, &item, policy, &hashes)
        );
    }

    #[test]
    fn content_hash_moves_with_every_policy_neutral_component() {
        let source = SnapshotSource::ClaudeCode;
        let base = valid_v6_batch_request()
            .snapshots
            .into_iter()
            .next()
            .expect("fixture snapshot");
        let content_hash = |item: &SnapshotItem| {
            snapshot_content_hash(
                source,
                &item.source_session_id,
                &snapshot_semantic_component_hashes(source, item),
            )
        };
        let expected = content_hash(&base);

        let mut usage = base.clone();
        usage.input_tokens += 1;
        assert_ne!(content_hash(&usage), expected, "usage_accounting");

        let mut lifecycle = base.clone();
        lifecycle.status = "completed".to_string();
        assert_ne!(content_hash(&lifecycle), expected, "lifecycle_activity");

        let mut latency = base.clone();
        latency.avg_duration_ms = Some(4_321);
        assert_ne!(content_hash(&latency), expected, "latency");

        let mut posture = base.clone();
        posture.peak_context_fill_tokens = Some(123_456);
        assert_ne!(content_hash(&posture), expected, "context_posture");

        let mut session = base.clone();
        session.source_session_id = "another-session".to_string();
        assert_ne!(content_hash(&session), expected, "session scope");
        assert_ne!(
            snapshot_content_hash(
                SnapshotSource::Codex,
                &base.source_session_id,
                &snapshot_semantic_component_hashes(source, &base)
            ),
            expected,
            "source scope"
        );
    }

    fn manifest_index_entry(fingerprint: Option<&str>) -> ScanIndexEntry {
        ScanIndexEntry {
            size_bytes: 1,
            modified_unix_seconds: 2,
            modified_unix_nanos: Some(3),
            source_file_fingerprint: "source".to_string(),
            last_snapshot_fingerprint: fingerprint.map(str::to_string),
            scan_identity_version: Some("semantic_sync:v1".to_string()),
        }
    }

    #[test]
    fn committable_subset_commits_only_what_the_server_holds() {
        let mut committed = ScanIndex::default();
        committed.files.insert(
            "unchanged.jsonl".to_string(),
            manifest_index_entry(Some("aa")),
        );
        committed.files.insert(
            "pending.jsonl".to_string(),
            manifest_index_entry(Some("old")),
        );
        committed.files.insert(
            "became-empty.jsonl".to_string(),
            manifest_index_entry(Some("old-empty-entity")),
        );
        committed.file_snapshot_fingerprints.insert(
            "became-empty.jsonl".to_string(),
            BTreeSet::from(["old-empty-entity".to_string()]),
        );
        committed.codex_state_only_snapshot_fingerprints.insert(
            "removed-state-only".to_string(),
            "old-state-entity".to_string(),
        );
        committed.quarantined_snapshot_fingerprints.insert(
            "old-state-entity".to_string(),
            snapshot_quarantine_record(SnapshotSource::Codex),
        );

        let mut scanned = committed.clone();
        // A semantic no-op: same fingerprint as the committed entry, so the
        // server already holds this content even though nothing was uploaded.
        scanned.files.insert(
            "unchanged.jsonl".to_string(),
            ScanIndexEntry {
                size_bytes: 42,
                ..manifest_index_entry(Some("aa"))
            },
        );
        // Changed and accepted this pass.
        scanned.files.insert(
            "accepted.jsonl".to_string(),
            manifest_index_entry(Some("bb")),
        );
        // Changed and NOT accepted: committing it would drop the entity, because
        // the next scan skips an unchanged transcript.
        scanned.files.insert(
            "pending.jsonl".to_string(),
            manifest_index_entry(Some("cc")),
        );
        // Parsed to nothing at all: there is no entity to lose.
        scanned
            .files
            .insert("empty.jsonl".to_string(), manifest_index_entry(None));
        scanned
            .confirmed_empty_files
            .insert("empty.jsonl".to_string());
        // This file and state-only row previously had server entities. Their
        // absence cannot become authoritative during a shed/partial commit.
        scanned
            .files
            .insert("became-empty.jsonl".to_string(), manifest_index_entry(None));
        scanned
            .confirmed_empty_files
            .insert("became-empty.jsonl".to_string());
        scanned
            .file_snapshot_fingerprints
            .remove("became-empty.jsonl");
        scanned
            .codex_state_only_snapshot_fingerprints
            .remove("removed-state-only");

        let accepted = BTreeSet::from(["bb".to_string()]);
        let committable = scanned.committable_subset(&committed, &accepted, &BTreeMap::new());

        assert_eq!(
            committable.files["unchanged.jsonl"].size_bytes, 42,
            "a semantic no-op advances: the server already has that content"
        );
        assert!(committable.files.contains_key("accepted.jsonl"));
        assert!(committable.files.contains_key("empty.jsonl"));
        assert_eq!(
            committable.files["became-empty.jsonl"]
                .last_snapshot_fingerprint
                .as_deref(),
            Some("old-empty-entity")
        );
        assert!(!committable
            .confirmed_empty_files
            .contains("became-empty.jsonl"));
        assert_eq!(
            committable
                .codex_state_only_snapshot_fingerprints
                .get("removed-state-only")
                .map(String::as_str),
            Some("old-state-entity")
        );
        assert!(committable
            .quarantined_snapshot_fingerprints
            .contains_key("old-state-entity"));
        assert_eq!(
            committable.files["pending.jsonl"]
                .last_snapshot_fingerprint
                .as_deref(),
            Some("old"),
            "an unaccepted entity keeps its committed entry so the next scan retries it"
        );

        // A first-time file that was not accepted has no committed entry to fall
        // back to, so it must not appear at all.
        let mut fresh = ScanIndex::default();
        fresh
            .files
            .insert("new.jsonl".to_string(), manifest_index_entry(Some("dd")));
        let committable =
            fresh.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
        assert!(committable.files.is_empty());
    }

    #[test]
    fn partial_commit_preserves_old_upload_context_and_forces_full_policy_reparse() {
        let mut previous = ScanIndex {
            upload_context_fingerprint: Some("context-a".to_string()),
            ..ScanIndex::default()
        };
        previous.files.insert(
            "/opaque/accepted.jsonl".to_string(),
            manifest_index_entry(Some("old-accepted")),
        );
        previous.files.insert(
            "/opaque/pending.jsonl".to_string(),
            manifest_index_entry(Some("old-pending")),
        );

        let mut scanned = previous.clone();
        scanned.upload_context_fingerprint = Some("context-b".to_string());
        scanned.activate_upload_context("context-b".to_string());
        scanned.files.insert(
            "/opaque/accepted.jsonl".to_string(),
            manifest_index_entry(Some("new-accepted")),
        );
        scanned.files.insert(
            "/opaque/pending.jsonl".to_string(),
            manifest_index_entry(Some("new-pending")),
        );
        let mut committable = scanned.committable_subset(
            &previous,
            &BTreeSet::from(["new-accepted".to_string()]),
            &BTreeMap::new(),
        );
        committable.mark_bounded_sweep_unsettled();
        assert_eq!(
            committable.upload_context_fingerprint.as_deref(),
            Some("context-a"),
            "a shed/partial save cannot advance the global policy epoch"
        );

        committable.activate_upload_context("context-b".to_string());
        let mut candidate = test_candidate(PathBuf::from("/opaque/accepted.jsonl"));
        let entry = committable
            .files
            .get("/opaque/accepted.jsonl")
            .expect("accepted file is safely checkpointed");
        candidate.size_bytes = entry.size_bytes;
        candidate.modified_unix_seconds = entry.modified_unix_seconds;
        candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap_or_default();
        candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
        assert_eq!(
            committable.candidate_decision(&candidate),
            CandidateDecision::Parse,
            "even an accepted page is re-derived because untouched siblings still owe the policy transition"
        );
        assert!(committable.bounded_sweep_had_unsettled_upload);
    }

    #[test]
    fn committable_subset_applies_the_same_rule_to_codex_state_only_entities() {
        let mut committed = ScanIndex::default();
        committed
            .codex_state_only_snapshot_fingerprints
            .insert("session-noop".to_string(), "aa".to_string());
        committed
            .codex_state_only_snapshot_fingerprints
            .insert("session-pending".to_string(), "old".to_string());

        let mut scanned = ScanIndex::default();
        scanned
            .codex_state_only_snapshot_fingerprints
            .insert("session-noop".to_string(), "aa".to_string());
        scanned
            .codex_state_only_snapshot_fingerprints
            .insert("session-pending".to_string(), "cc".to_string());
        scanned
            .codex_state_only_snapshot_fingerprints
            .insert("session-accepted".to_string(), "bb".to_string());
        scanned
            .codex_state_only_snapshot_fingerprints
            .insert("session-new".to_string(), "dd".to_string());

        let committable = scanned.committable_subset(
            &committed,
            &BTreeSet::from(["bb".to_string()]),
            &BTreeMap::new(),
        );

        assert_eq!(
            committable.codex_state_only_snapshot_fingerprints,
            BTreeMap::from([
                ("session-noop".to_string(), "aa".to_string()),
                ("session-pending".to_string(), "old".to_string()),
                ("session-accepted".to_string(), "bb".to_string()),
            ])
        );
    }

    #[test]
    fn committable_subset_uses_exact_multi_entity_set_and_preserves_quarantine() {
        let accepted = "a".repeat(64);
        let quarantined = "b".repeat(64);
        let mut scanned = ScanIndex::default();
        scanned.files.insert(
            "split.jsonl".to_string(),
            manifest_index_entry(Some("set-hash")),
        );
        scanned.file_snapshot_fingerprints.insert(
            "split.jsonl".to_string(),
            BTreeSet::from([accepted.clone(), quarantined.clone()]),
        );

        let committable = scanned.committable_subset(
            &ScanIndex::default(),
            &BTreeSet::from([accepted]),
            &BTreeMap::from([(
                quarantined.clone(),
                snapshot_quarantine_record(SnapshotSource::Codex),
            )]),
        );
        assert!(committable.files.contains_key("split.jsonl"));
        assert_eq!(
            committable.file_snapshot_fingerprints["split.jsonl"].len(),
            2
        );
        assert_eq!(
            committable.quarantined_snapshot_fingerprints,
            BTreeMap::from([(
                quarantined,
                snapshot_quarantine_record(SnapshotSource::Codex),
            )])
        );
        assert_eq!(
            committable
                .manifest(SnapshotSource::Codex, 183)
                .entity_count,
            1,
            "quarantine is checkpointed but never advertised as server-held"
        );
    }

    #[test]
    fn scan_index_manifest_counts_entities_and_folds_their_fingerprints() {
        let mut index = ScanIndex::default();
        index
            .files
            .insert("a.jsonl".to_string(), manifest_index_entry(Some("aa")));
        index
            .files
            .insert("b.jsonl".to_string(), manifest_index_entry(Some("bb")));
        // A scanned file that produced no snapshot is not an entity the server
        // could hold, so it must not inflate the denominator.
        index
            .files
            .insert("c.jsonl".to_string(), manifest_index_entry(None));
        index
            .codex_state_only_snapshot_fingerprints
            .insert("session-1".to_string(), "cc".to_string());

        let manifest = index.manifest(SnapshotSource::Codex, 183);
        assert_eq!(manifest.source, "codex");
        assert_eq!(manifest.entity_count, 3);
        // The scope and window are reported, never folded into the hash: two
        // machines holding the same entity set must agree on the fold even if
        // their authorized windows differ, and the window is what lets a
        // consumer scope its own set before comparing.
        assert_eq!(manifest.scope, SNAPSHOT_MANIFEST_SCOPE);
        assert_eq!(
            manifest.rolling_hash,
            index.manifest(SnapshotSource::Codex, 730).rolling_hash
        );
        assert_eq!(manifest.rolling_hash.len(), 64);
        assert!(manifest
            .rolling_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(manifest, index.manifest(SnapshotSource::Codex, 183));
    }

    #[test]
    fn snapshot_manifest_v2_matches_python_golden_byte_for_byte() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/snapshot-manifest-v2-golden.json"
        ))
        .expect("parse shared manifest golden");
        let mut index = ScanIndex::default();
        index.file_snapshot_fingerprints.insert(
            "late-sidecar.jsonl".to_string(),
            BTreeSet::from(["bb".to_string(), "aa".to_string()]),
        );
        index
            .codex_state_only_snapshot_fingerprints
            .insert("state-only".to_string(), "aa".to_string());
        index.snapshot_activity_at = BTreeMap::from([
            ("aa".to_string(), Some("2026-01-01T00:00:00Z".to_string())),
            ("bb".to_string(), Some("2026-06-30T23:59:59Z".to_string())),
        ]);
        let manifest = index
            .manifest_for_window(
                SnapshotSource::Codex,
                golden["window_start"].as_str().unwrap(),
                golden["window_end"].as_str().unwrap(),
            )
            .expect("golden window");
        assert_eq!(serde_json::to_value(&manifest).unwrap(), golden);
    }

    #[test]
    fn snapshot_manifest_v2_omits_explicit_metadata_only_activity() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/snapshot-manifest-v2-metadata-only-golden.json"
        ))
        .expect("parse shared metadata-only golden");
        let fingerprint = golden["snapshot_fingerprint"].as_str().unwrap().to_string();
        let mut item = sample_session_artifact_item();
        item.source_session_id = golden["source_session_id"].as_str().unwrap().to_string();
        item.snapshot_fingerprint = fingerprint.clone();
        assert_eq!(
            snapshot_semantic_activity_at(&item),
            golden["semantic_activity"].as_str().map(str::to_string)
        );

        let mut index = ScanIndex::default();
        index.file_snapshot_fingerprints.insert(
            "metadata-only.jsonl".to_string(),
            BTreeSet::from([fingerprint.clone()]),
        );
        index
            .snapshot_activity_at
            .insert(fingerprint, snapshot_semantic_activity_at(&item));
        let expected = &golden["manifest"];
        let manifest = index
            .manifest_for_window(
                SnapshotSource::Codex,
                expected["window_start"].as_str().unwrap(),
                expected["window_end"].as_str().unwrap(),
            )
            .expect("metadata-only manifest");
        assert_eq!(serde_json::to_value(manifest).unwrap(), *expected);
    }

    #[test]
    fn snapshot_manifest_v2_uses_semantic_half_open_window_not_file_mtime() {
        let inside_start = "a".repeat(64);
        let inside_late_sidecar = "b".repeat(64);
        let excluded_end = "c".repeat(64);
        let excluded_old_modified_now = "d".repeat(64);
        let mut index = ScanIndex {
            file_snapshot_fingerprints: BTreeMap::from([
                (
                    "old-file-modified-now.jsonl".to_string(),
                    BTreeSet::from([excluded_old_modified_now.clone()]),
                ),
                (
                    "late-sidecar.jsonl".to_string(),
                    BTreeSet::from([inside_late_sidecar.clone(), excluded_end.clone()]),
                ),
            ]),
            ..ScanIndex::default()
        };
        index
            .codex_state_only_snapshot_fingerprints
            .insert("state-only".to_string(), inside_start.clone());
        index.snapshot_activity_at = BTreeMap::from([
            (inside_start, Some("2026-01-01T00:00:00Z".to_string())),
            (
                inside_late_sidecar,
                Some("2026-06-30T23:59:59.999999999Z".to_string()),
            ),
            (excluded_end, Some("2026-07-01T00:00:00Z".to_string())),
            (
                excluded_old_modified_now,
                Some("2025-12-31T23:59:59Z".to_string()),
            ),
        ]);
        // Deliberately future local mtime: it cannot admit an old semantic
        // entity into the server-reconstructible activity window.
        index.files.insert(
            "old-file-modified-now.jsonl".to_string(),
            ScanIndexEntry {
                size_bytes: 1,
                modified_unix_seconds: u64::MAX,
                modified_unix_nanos: Some(u64::MAX),
                source_file_fingerprint: "local-mtime-is-not-membership".to_string(),
                last_snapshot_fingerprint: Some("group".to_string()),
                scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
            },
        );
        let manifest = index
            .manifest_for_window(
                SnapshotSource::Codex,
                "2026-01-01T00:00:00Z",
                "2026-07-01T00:00:00Z",
            )
            .expect("semantic window");
        assert_eq!(manifest.entity_count, 2);
    }

    #[test]
    fn scan_index_manifest_ignores_paths_and_insertion_order() {
        // The fold is over fingerprints only. That is what makes it something
        // the server can recompute — it has the fingerprints and never sees a
        // local path — and it is also why no path can leak through the hash.
        let mut left = ScanIndex::default();
        left.files
            .insert("/one/a.jsonl".to_string(), manifest_index_entry(Some("aa")));
        left.files
            .insert("/one/b.jsonl".to_string(), manifest_index_entry(Some("bb")));
        let mut right = ScanIndex::default();
        right.files.insert(
            "/other/z.jsonl".to_string(),
            manifest_index_entry(Some("bb")),
        );
        right.files.insert(
            "/other/y.jsonl".to_string(),
            manifest_index_entry(Some("aa")),
        );

        assert_eq!(
            left.manifest(SnapshotSource::Codex, 183),
            right.manifest(SnapshotSource::Codex, 183)
        );
    }

    #[test]
    fn scan_index_manifest_is_scoped_to_its_source_and_moves_with_content() {
        let mut index = ScanIndex::default();
        index
            .files
            .insert("a.jsonl".to_string(), manifest_index_entry(Some("aa")));
        let codex = index.manifest(SnapshotSource::Codex, 183);
        assert_ne!(
            codex.rolling_hash,
            index.manifest(SnapshotSource::ClaudeCode, 183).rolling_hash
        );

        index
            .files
            .insert("a.jsonl".to_string(), manifest_index_entry(Some("ab")));
        assert_ne!(
            codex.rolling_hash,
            index.manifest(SnapshotSource::Codex, 183).rolling_hash
        );
        assert_eq!(index.manifest(SnapshotSource::Codex, 183).entity_count, 1);
    }

    #[test]
    fn scan_index_manifest_length_prefixes_defeat_fingerprint_splitting() {
        // Two entities "aa"+"bb" and one entity "aabb" are different sets, so a
        // bare concatenation would be a real collision, not a theoretical one.
        let mut split = ScanIndex::default();
        split
            .files
            .insert("a".to_string(), manifest_index_entry(Some("aa")));
        split
            .files
            .insert("b".to_string(), manifest_index_entry(Some("bb")));
        let mut joined = ScanIndex::default();
        joined
            .files
            .insert("a".to_string(), manifest_index_entry(Some("aabb")));

        assert_ne!(
            split.manifest(SnapshotSource::Codex, 183).rolling_hash,
            joined.manifest(SnapshotSource::Codex, 183).rolling_hash
        );
    }

    #[test]
    fn batch_request_carries_the_client_report_with_its_zeros() {
        let request = valid_v6_batch_request();
        let value = serde_json::to_value(&request).expect("serialize batch");
        let report = &value["client_report"];
        assert_eq!(report["schema_version"], 1);
        let entries = report["entries"].as_array().expect("entries");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["reason"].as_str().expect("reason"))
                .collect::<Vec<_>>(),
            vec![
                "queue_overflow",
                "ratelimit_backoff",
                "network_error",
                "poisoned"
            ]
        );
        assert!(entries
            .iter()
            .all(|entry| entry["quantity"].as_u64() == Some(0)));
    }

    #[test]
    fn wire_envelope_carries_the_content_hash_and_its_epoch() {
        let request = valid_v6_batch_request();
        let value = serde_json::to_value(&request).expect("serialize batch");
        let envelope = &value["snapshots"][0]["semantic_envelope"];
        let content_hash = envelope["content_hash"].as_str().expect("content hash");
        assert_eq!(content_hash.len(), 64);
        assert!(content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(envelope["hash_epoch"], SNAPSHOT_CONTENT_HASH_EPOCH);
    }

    #[test]
    fn content_identity_body_stays_canonicalizable() {
        // Guards the `expect` inside `snapshot_content_hash`: if a future field
        // brings a fractional number into the identity body, this fails here
        // instead of panicking on a customer's machine.
        for source in [
            SnapshotSource::Pi,
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
        ] {
            let item = valid_v6_batch_request()
                .snapshots
                .into_iter()
                .next()
                .expect("fixture snapshot");
            let body = snapshot_content_identity_body(
                source,
                &item.source_session_id,
                &snapshot_semantic_component_hashes(source, &item),
            );
            assert!(crate::canonical_json::is_canonicalizable(&body));
        }
    }
}
