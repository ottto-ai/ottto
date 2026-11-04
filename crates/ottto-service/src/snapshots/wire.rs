//! The snapshot upload wire model: the batch request, the per-session
//! `SnapshotItem` and its nested records, and the batch serializer that adds
//! each item's semantic envelope.
pub(super) mod batch_validation;
pub(super) mod content_hash;

use content_hash::snapshot_semantic_envelope;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{
    claude_history_upgrade, claude_request_identity, claude_request_money, is_false, is_zero_u64,
    snapshot_source_from_api_slug, CacheObservations, ClaudeCompactionObservation, ClaudeFileBirth,
    ClaudeFileBirthVerdict, ClaudeTranscriptUsageOccurrence, LocalContextPoint, OwnedRequest,
    SnapshotCompactionEvent, SnapshotContextCurve, SnapshotSessionStart, SnapshotUploadPolicy,
    CLAUDE_CODE_SCAN_IDENTITY_VERSION, CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
    CODEX_SCAN_IDENTITY_VERSION, CODEX_SNAPSHOT_PARSER_VERSION, MAX_SEMANTIC_ENVELOPE_BYTES,
    PI_SCAN_IDENTITY_VERSION, PI_SNAPSHOT_PARSER_VERSION, SNAPSHOT_ENTITY_ACK_CONTRACT,
    SNAPSHOT_HEAD_CAS_CONTRACT, USAGE_DECREASE_HOLD_ACK_CONTRACT,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    Codex,
    ClaudeCode,
    Pi,
}
crate::durable_tail_codec::durable_enum!(SnapshotSource {
    0 => Codex,
    1 => ClaudeCode,
    2 => Pi,
});

impl SnapshotSource {
    pub fn api_slug(self) -> &'static str {
        match self {
            SnapshotSource::Codex => "codex",
            SnapshotSource::ClaudeCode => "claude_code",
            SnapshotSource::Pi => "pi",
        }
    }

    /// The index of a process-local per-source array.
    pub(crate) fn slot(self) -> usize {
        match self {
            SnapshotSource::Codex => 0,
            SnapshotSource::ClaudeCode => 1,
            SnapshotSource::Pi => 2,
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
    pub(super) fn derives_context_posture(self) -> bool {
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
            SnapshotSource::Pi => vec![crate::agent_status::pi_sessions_dir(home)],
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
    /// Opaque predecessor authorization returned only after the backend proved
    /// these exact bytes own the current head. Legacy reconciliation never
    /// borrows a settled sibling's token: an absent token is an explicit CAS
    /// bootstrap that admits only an exact repeat or a genuinely missing head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_head_etag: Option<String>,
    /// Answer to a head-CAS conflict: the server's opaque challenge plus the
    /// refused revision v2 hash it binds. Never combined with a base token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict_head_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rescan_from_revision_hash: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub forced_full_rescan: bool,
}

#[derive(Serialize)]
pub(super) struct SnapshotItemWire<'a> {
    #[serde(flatten)]
    pub(super) snapshot: &'a SnapshotItem,
    pub(super) semantic_envelope: SnapshotSemanticEnvelope,
}

/// Normal batch wire with optional optimistic-head enforcement. Reconciliation
/// uses the same write endpoint and entity ACKs as every upload; this wrapper
/// only activates the backend's existing CAS discipline for an isolated legacy
/// page.
pub(crate) struct SnapshotBatchWireRequest<'a> {
    request: &'a SnapshotBatchRequest,
    enforce_head_cas: bool,
}

impl SnapshotBatchRequest {
    pub(crate) fn wire_with_head_cas(&self) -> SnapshotBatchWireRequest<'_> {
        SnapshotBatchWireRequest {
            request: self,
            enforce_head_cas: true,
        }
    }
}

/// The batch declares `usage_decrease_hold_ack:v1`: a Claude batch carrying
/// at least one request-owned literal body.
pub(crate) fn declares_usage_decrease_hold_ack(request: &SnapshotBatchRequest) -> bool {
    snapshot_source_from_api_slug(&request.source) == Some(SnapshotSource::ClaudeCode)
        && request
            .snapshots
            .iter()
            .any(claude_history_upgrade::is_request_owned_literal)
}

fn serialize_snapshot_batch<S: Serializer>(
    request: &SnapshotBatchRequest,
    enforce_head_cas: bool,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let source = snapshot_source_from_api_slug(&request.source)
        .ok_or_else(|| serde::ser::Error::custom("unsupported snapshot source"))?;
    let snapshots = request
        .snapshots
        .iter()
        .map(|snapshot| {
            let semantic_envelope =
                snapshot_semantic_envelope(source, snapshot, request.upload_policy);
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
    let mut state = serializer.serialize_struct("SnapshotBatchRequest", 9)?;
    state.serialize_field("schema_version", &request.schema_version)?;
    state.serialize_field("source", &request.source)?;
    state.serialize_field("machine_id", &request.machine_id)?;
    state.serialize_field("collector_version", &request.collector_version)?;
    // Daemon-first capability declaration. Older backends use a
    // forward-tolerant ingest model and ignore it; capable backends echo it
    // and may return a complete per-entity outcome partition.
    state.serialize_field("entity_ack_contract", SNAPSHOT_ENTITY_ACK_CONTRACT)?;
    // Only Claude request-owned literal batches opt into money-decrease
    // holds; every other batch keeps its released envelope bytes.
    if declares_usage_decrease_hold_ack(request) {
        state.serialize_field(
            "usage_decrease_hold_ack_contract",
            USAGE_DECREASE_HOLD_ACK_CONTRACT,
        )?;
    }
    if enforce_head_cas {
        state.serialize_field("head_cas_contract", SNAPSHOT_HEAD_CAS_CONTRACT)?;
    }
    state.serialize_field("snapshots", &snapshots)?;
    state.serialize_field("client_report", &request.client_report)?;
    state.end()
}

impl Serialize for SnapshotBatchRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_snapshot_batch(
            self,
            self.snapshots
                .iter()
                .any(|item| item.cache_observations.is_some()),
            serializer,
        )
    }
}

impl Serialize for SnapshotBatchWireRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_snapshot_batch(self.request, self.enforce_head_cas, serializer)
    }
}

// Hoisted onto each SnapshotModelUsage row in v6: these participate in the
// backend's billing_hash (one of the two row-key dimensions). Names match
// `_usage_row_key` in backend/app/schemas/agent_session_snapshots.py.
pub(super) const ROW_BILLING_FIELDS: &[&str] = &[
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotActivityCount {
    pub name: String,
    pub count: u64,
}

/// One privacy-safe transcript-observed tool-name aggregate. Only the bounded
/// name and count cross the wire; tool ids, arguments, results, and paths stay
/// local to the parser.
pub type SnapshotToolUsage = SnapshotActivityCount;

/// One privacy-safe agent capability count. The identifiers are collector-owned
/// constants; raw tool arguments, results, URLs, browser ids, and screenshots
/// never enter this shape.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotCapabilityCount {
    pub capability_id: String,
    pub raw_origin: String,
    pub count: u64,
}

/// Hourly capability activity used by the backend's bounded GOLD projection.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotCapabilityBucket {
    pub bucket_start: String,
    pub capability_id: String,
    pub raw_origin: String,
    pub call_count: u64,
}

/// Content-free local activity evidence derived from Codex rollout records.
/// Commands, arguments, paths, patches, and tool output never leave the Mac.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotActivitySummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_collection_version: Option<String>,
    pub tool_calls: u64,
    pub shell_commands: u64,
    pub patch_operations: u64,
    pub changed_files: u64,
    pub lines_added: u64,
    pub lines_deleted: u64,
    pub web_searches: u64,
    pub mcp_calls: u64,
    pub subagent_spawns: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_counts: Vec<SnapshotActivityCount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_tool_counts: Vec<SnapshotActivityCount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_counts: Vec<SnapshotCapabilityCount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_buckets: Vec<SnapshotCapabilityBucket>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
}

impl SnapshotOrigin {
    pub(super) fn is_empty(&self) -> bool {
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

/// Original provider creator identity only; this does not prove a paid route.
/// Raw provider identifiers are converted in memory with the same namespace as
/// CodexHomeBinding and never enter the snapshot or billing rows.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionAccountEvidence {
    pub provider: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_workspace_hash: Option<String>,
    pub identity_hash_scheme: &'static str,
    pub evidence_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_disposition: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_account_evidence: Option<SessionAccountEvidence>,
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
    /// Collector proof that all provider-reported usage assigned to this snapshot belongs
    /// exclusively to this source session. Omitted whenever ownership remains unproven,
    /// including ambiguous Codex or Claude legacy fork shapes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_accounting_contract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_request_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_usage: Option<ClaudeRemovedUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry_owned_complete: Option<bool>,
    /// Native resolver conflicts (two incompatible records of one response,
    /// the loser dropped) in this request-owned body. Present only when >0,
    /// so legacy and conflict-free bodies are byte-identical. The session's money
    /// is marked partial from it; the daemon ships no deltas or prices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_conflict_count: Option<u64>,
    /// Capability-gated class-N disclosure; bucket rows, counted once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy_unproven_counts: Option<CopyUnprovenCounts>,
    #[serde(skip)]
    pub(crate) claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    /// Local-only identities of the Claude API responses whose transcript
    /// usage contributed to this snapshot. Claude Code also emits auxiliary
    /// OTLP requests (for example prompt suggestions) under the same session
    /// id; these exact request ids let account attribution prove coverage of
    /// billed transcript usage without treating those auxiliary requests as
    /// missing transcript rows. Never serialized or uploaded.
    #[serde(skip)]
    pub(crate) claude_usage_request_ids: BTreeSet<String>,
    /// Local-only, per-response Claude usage retained until OTLP log and trace
    /// evidence can prove one owner for every reported occurrence in a family.
    /// Raw request ids and response observations never cross the snapshot wire.
    #[serde(skip)]
    pub(crate) claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_observations: Option<CacheObservations>,
    #[serde(skip)]
    pub(crate) cache_observations_state: Option<Value>,
    #[serde(skip)]
    pub(crate) cache_base_head_etag: Option<String>,
    /// Local-only answer to this session's head-CAS conflict: the server's
    /// opaque challenge and the exact revision v2 hash it was minted over.
    /// When set, the envelope replaces the stale base with the existing
    /// rescan handshake. Never part of the snapshot body.
    #[serde(skip)]
    pub(crate) cache_conflict_answer: Option<(String, String)>,
    #[serde(skip)]
    pub(crate) cache_requests: Vec<OwnedRequest>,
    #[serde(skip)]
    pub(crate) cache_requests_complete: bool,
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
    pub last_turn_context_tokens: Option<u64>,
    // Codex only: `model_context_window` from the SAME owned `token_count`
    // record that set the matching watermark above, so watermark / window is
    // exact even when the window changed mid-session. Each is present only
    // when its own watermark is, and is never 0. None = not recorded (that
    // record carried no window, or another source). Wire-only: these stay out
    // of every semantic component, the fingerprint and the body witness, so
    // shipping them re-mints no identity and starts no re-upload wave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_turn_context_window_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_context_fill_window_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_turn_context_window_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compaction_timestamps: Vec<String>,
    /// Context sizes around each compaction, one per `compaction_timestamps`
    /// entry with a byte-identical `at`. Additive evidence: deliberately
    /// outside the `context_posture` component, the content hash and the body
    /// witness. Codex only for now; Claude Code leaves it empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compaction_events: Vec<SnapshotCompactionEvent>,
    /// Local-only context points for the Mac app's Sessions graph (Codex, last
    /// activity within 75 minutes). Never serialized or uploaded.
    #[serde(skip)]
    pub(crate) local_context_points: Vec<LocalContextPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_total_pre_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_total_post_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_total_cumulative_dropped_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_total_duration_ms: Option<u64>,
    /// Versioned, content-free per-owned-request context evidence. The curve is
    /// intentionally excluded from semantic component/content hashes; the
    /// backend accepted-body witness owns correction identity for this additive
    /// evidence contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_curve: Option<SnapshotContextCurve>,
    /// Local-only raw Claude boundaries retained until the complete scan census
    /// suppresses copied-prefix ownership. Never serialized.
    #[serde(skip)]
    pub(crate) claude_context_curve_boundaries: Vec<ClaudeCompactionObservation>,
    /// Missing provider request identities make a Claude curve unavailable even
    /// when aggregate usage can still be conservatively counted.
    #[serde(skip)]
    pub(crate) claude_context_curve_identity_complete: bool,
    #[serde(skip)]
    pub(crate) claude_context_curve_request_index_complete: bool,
    #[serde(skip)]
    pub(crate) claude_context_curve_owned_start_proven: bool,
    /// Local-only birth evidence and own-only context tally of the Claude
    /// transcript this item was parsed from. Never serialized.
    #[serde(skip)]
    pub(crate) claude_file_birth: ClaudeFileBirth,
    /// Local-only result of design E admission; never persisted or uploaded.
    #[serde(skip)]
    pub(crate) claude_file_birth_verdict: Option<ClaudeFileBirthVerdict>,
    /// Claude Code only: when this session's first own request (design E)
    /// ended, RFC 3339 UTC. Set by the ownership fold only when the
    /// transcript's file birth was measured and no copied record precedes
    /// that request; otherwise absent, never a guess and never
    /// `source_started_at`. Display-only additive evidence: outside every
    /// semantic component, the content hash and the body witness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_own_request_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_summary: Option<SnapshotActivitySummary>,
    /// Names of tools actually invoked by counted Claude assistant responses.
    /// This is deliberately a plain additive wire field: it is not part of any
    /// semantic-envelope component and therefore cannot churn content identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_usage: Option<Vec<SnapshotToolUsage>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tool_usage_truncated: bool,
    /// What a fresh session sent in request 1 and read in requests 1-3
    /// (`snapshots/session_start.rs`). A plain additive wire field outside
    /// every semantic component, the content hash and the upload witness, so it
    /// never churns identity; forks and copied prefixes keep `client_version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_start: Option<Box<SnapshotSessionStart>>,
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
    /// Wire contract 5 only: deduplicated (organization, basis) entries the
    /// rows' `evidence_ref`s index, in the contract's total order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub request_evidence: Vec<SnapshotRequestEvidence>,
    /// Wire contract 5 only: bucket rows left untagged for a refused or pending
    /// reason. Omitted when zero; its zero-vs-positive state is hashed.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub request_identity_refusals: u64,
    /// Local-only `credential_org` markers from this file's owned lines, kept
    /// for contract-5 transcript bases. Never serialized or uploaded.
    #[serde(skip)]
    pub(crate) claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    /// Local-only, content-free reason the Claude request-evidence pass left
    /// this snapshot's account unset (`CLAUDE_ACCOUNT_WITHHELD_*`). Explains the
    /// local active-session card only; never serialized, uploaded or used as
    /// account evidence.
    #[serde(skip)]
    pub(crate) claude_account_withheld_reason: Option<&'static str>,
    /// Local-only display evidence of this item's accounts, set only by
    /// contract-5 tagging: the account of its newest own request and its usage
    /// per account triple. Never serialized, uploaded or used as account
    /// evidence; feeds only the local active-session card.
    #[serde(skip)]
    pub(crate) claude_account_display: Option<Box<claude_request_identity::AccountDisplay>>,
}

/// Request evidence for this session's own billed requests names more than one
/// account, so no single account may stand for its cumulative usage.
pub(crate) const CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS: &str = "multiple_accounts";
/// Request evidence names exactly one account, but it does not cover every
/// billed request, so the account stays unproven.
pub(crate) const CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE: &str =
    "incomplete_request_evidence";
/// Request evidence names more accounts than one item may carry
/// (`MAX_AUTHORITY_KEYS` / `MAX_EVIDENCE_ENTRIES`), so the session is held
/// and not uploaded. Local only, like the other reasons.
pub(crate) const CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS: &str = "too_many_accounts";

/// Cumulative usage removed from this entity's evidence, in wire counters.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ClaudeRemovedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub unattributed_total_tokens: u64,
    pub reasoning_output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotUsageBucket {
    pub bucket_start: String,
    pub model_usage: Vec<SnapshotModelUsage>,
    pub first_activity_at: Option<String>,
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct CopyUnprovenCounts {
    pub rows: u64,
    pub requests: u64,
}
crate::heap_layout_bound::fields!(CopyUnprovenCounts; rows, requests);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotModelUsage {
    pub model: String,
    #[serde(skip_serializing_if = "is_false")]
    pub copy_unproven: bool,
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
    /// Wire contract 5 only (`claude_request_identity::COLLECTOR`): this row's
    /// entry in the item's `request_evidence`. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<u16>,
    /// Wire contract 5 only: a row mixing authority keys carries no row-level
    /// identity and these exact shares instead. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_parts: Option<Vec<SnapshotIdentityPart>>,
    /// Wire contract 5, bucket rows only, option (ii): defer this row's
    /// identity to proof the server retained from an ACKed body. Never on a
    /// tagged row; omitted unless the server advertised the capability.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub identity_retained: bool,
    /// Wire contract 5, bucket rows only: the row's
    /// accepted proof was copy-derived and is tombstoned; a retaining receiver
    /// drops that proof for good. Like
    /// `identity_retained`, only sent when the server advertised option (ii)
    /// and hashed in the identity leaf. Omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub copy_invalidated: bool,
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

/// One authority key's exact share of a usage row that mixes keys (contract 5).
/// All eight counts are always present; money appears iff the row carries it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotIdentityPart {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<u16>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub unattributed_total_tokens: u64,
    pub request_count: u64,
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

/// One (organization, basis) entry of an item's `request_evidence` (contract 5).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotRequestEvidence {
    pub identity_basis: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_workspace_hash: Option<String>,
    /// Absent: existing provenance (own evidence or existing fills). Present under the
    /// `session_request_account_source:v1` capability: an account carried
    /// within one transcript to a request with no telemetry row (placement,
    /// never per-request proof).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_source: Option<AccountSource>,
}

/// Exact shared activity-hint capability for carried-account provenance.
/// Missing/null/unknown keeps existing wire bytes for every source.
pub(crate) const ACCOUNT_SOURCE_CONTRACT: &str = "session_request_account_source:v1";

/// How a carried account reached a request (counts only).
/// Shared wire shape for source reducers; unmarked provenance stays absent.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AccountSource {
    /// From the latest earlier request whose own telemetry named the account.
    CarriedForward,
    /// From the transcript's first such request, to the gap before it.
    CarriedBackward,
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
pub(super) const MAX_SESSION_ARTIFACTS: usize = 50;
/// Wire contract, not a cap: the receiver's `SessionArtifact.value` is
/// `Field(min_length=7, max_length=512)`, counted in characters after a strip
/// (extracted values carry no surrounding whitespace). A longer value refuses
/// the whole batch (422), so it is kept locally and never uploaded.
pub(crate) const MAX_SESSION_ARTIFACT_VALUE_CHARS: usize = 512;
