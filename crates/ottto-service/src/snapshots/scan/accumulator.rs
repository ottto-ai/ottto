//! The snapshot accumulator: its methods, the usage row key and selector
//! capture, the row builders, and their layout rows.

use crate::snapshots::*;

mod activity;
mod claude_responses;
mod codex_ownership;
mod construct;
mod items;

pub(in crate::snapshots) fn row_key_from_model_usage(row: &SnapshotModelUsage) -> RowKey {
    row_key_with_selector_hash(row, selector_hash(&row.selector_context))
}

pub(in crate::snapshots) fn selector_hash(selector_context: &BTreeMap<String, String>) -> String {
    if selector_context.is_empty() {
        "base".to_string()
    } else {
        let payload = serde_json::to_string(selector_context).unwrap_or_else(|_| "{}".to_string());
        sha256_hex(&[payload.as_str()])[..16].to_string()
    }
}

/// Call-local memo for one row rebuild: a session's rows share a handful of
/// selector contexts, so each distinct context is serialized and hashed once.
/// Bounded; dropped with the caller.
#[derive(Default)]
pub(in crate::snapshots) struct SelectorHashes(Vec<(BTreeMap<String, String>, String)>);

impl SelectorHashes {
    const CAP: usize = 16;

    pub(in crate::snapshots) fn row_key(&mut self, row: &SnapshotModelUsage) -> RowKey {
        let context = &row.selector_context;
        let hash = match self.0.iter().find(|(known, _)| known == context) {
            Some((_, hash)) => hash.clone(),
            None => {
                let hash = selector_hash(context);
                if self.0.len() < Self::CAP {
                    self.0.push((context.clone(), hash.clone()));
                }
                hash
            }
        };
        row_key_with_selector_hash(row, hash)
    }
}

// Preserve every legacy key when false. The existing opaque local partition
// also distinguishes the new boolean money dimension; no wire selector or
// persisted RowKey codec field is introduced. The prefix cannot collide with
// a native selector hash ("base" or hexadecimal).
const COPY_UNPROVEN_PARTITION: &str = "copy_unproven:";
/// The model a usage row gets when its record and every earlier record
/// named none (Claude Code and Pi `place_usage`, Codex admission).
pub(crate) const IMPLICIT_USAGE_MODEL: &str = "unknown";
fn row_key_with_selector_hash(row: &SnapshotModelUsage, selector_hash: String) -> RowKey {
    let selector_hash = copy_unproven_selector_hash(row.copy_unproven, selector_hash);
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

/// The RowKey selector partition of a `copy_unproven` row. Every RowKey of a
/// usage row, local or rebuilt from its wire form (the #909 accepted ledger,
/// #944 proved rows), must partition through here so a marked row and an
/// unmarked twin never share a key.
pub(crate) fn copy_unproven_selector_hash(copy_unproven: bool, selector_hash: String) -> String {
    if copy_unproven {
        format!("{COPY_UNPROVEN_PARTITION}{selector_hash}")
    } else {
        selector_hash
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) struct SelectorCapture {
    pub(in crate::snapshots) context: BTreeMap<String, String>,
    pub(in crate::snapshots) sources: BTreeMap<String, String>,
}

impl SelectorCapture {
    pub(in crate::snapshots) fn is_empty(&self) -> bool {
        self.context.is_empty()
    }

    pub(in crate::snapshots) fn insert(&mut self, field: &str, value: String, source: &str) {
        self.context.insert(field.to_string(), value);
        self.sources.insert(field.to_string(), source.to_string());
    }

    pub(in crate::snapshots) fn merge(&mut self, other: SelectorCapture) {
        for (field, value) in other.context {
            self.context.insert(field, value);
        }
        for (field, source) in other.sources {
            self.sources.insert(field, source);
        }
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
pub(in crate::snapshots) struct RowKey {
    pub(in crate::snapshots) model: String,
    pub(in crate::snapshots) selector_hash: String,
    pub(in crate::snapshots) reasoning_effort: Option<String>,
    pub(in crate::snapshots) auth_mode: Option<String>,
    pub(in crate::snapshots) billing_channel: Option<String>,
    pub(in crate::snapshots) billing_provider: Option<String>,
    pub(in crate::snapshots) gateway_provider: Option<String>,
    pub(in crate::snapshots) model_provider: Option<String>,
    pub(in crate::snapshots) subscription_product: Option<String>,
}

impl RowKey {
    /// The hoisted billing fields by their selector names.
    pub(in crate::snapshots) fn billing_fields(&self) -> [(&'static str, Option<&str>); 6] {
        [
            ("auth_mode", self.auth_mode.as_deref()),
            ("billing_channel", self.billing_channel.as_deref()),
            ("billing_provider", self.billing_provider.as_deref()),
            ("gateway_provider", self.gateway_provider.as_deref()),
            ("model_provider", self.model_provider.as_deref()),
            ("subscription_product", self.subscription_product.as_deref()),
        ]
    }
}

pub(crate) struct ClaudeRowPlacement {
    pub(in crate::snapshots) bucket: String,
    pub(in crate::snapshots) normalized_timestamp: String,
    pub(in crate::snapshots) row_key: RowKey,
    pub(in crate::snapshots) reduced_context: BTreeMap<String, String>,
    pub(in crate::snapshots) reduced_sources: BTreeMap<String, String>,
}
/// One native usage placement: the resolved model (`fell_back`: from the
/// running model, the response named none) and its row, None when unplaceable.
pub(crate) struct PlacedClaudeUsage {
    pub(in crate::snapshots) model: String,
    pub(in crate::snapshots) fell_back: bool,
    pub(in crate::snapshots) placement: Option<ClaudeRowPlacement>,
}
/// One owner for the native bucket/key and reduced selector, including fallback time.
pub(in crate::snapshots) fn claude_row_placement(
    model: &str,
    base: &SelectorCapture,
    selector: SelectorCapture,
    effort: Option<&str>,
    timestamp: Option<&str>,
    fallback: Option<&str>,
) -> Option<ClaudeRowPlacement> {
    let (bucket, normalized_timestamp) = activity_bucket_from_timestamp(timestamp.or(fallback)?)?;
    let mut merged = base.clone();
    merged.merge(selector);
    let (row_key, reduced_context, reduced_sources) = build_row_identity(model, &merged, effort);
    Some(ClaudeRowPlacement {
        bucket,
        normalized_timestamp,
        row_key,
        reduced_context,
        reduced_sources,
    })
}

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct BucketRowAccumulator {
    pub(in crate::snapshots) selector_context: BTreeMap<String, String>,
    pub(in crate::snapshots) selector_sources: BTreeMap<String, String>,
    pub(in crate::snapshots) usage: UsageTotals,
    // Per-turn reasoning effort tier (Codex transcript or Claude local OTLP).
    // Also present in RowKey so mixed-effort buckets never collapse.
    pub(in crate::snapshots) reasoning_effort: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct UsageBucketState {
    pub(in crate::snapshots) rows: BTreeMap<RowKey, BucketRowAccumulator>,
    pub(in crate::snapshots) first_activity_at: Option<String>,
    pub(in crate::snapshots) last_activity_at: Option<String>,
}

impl UsageBucketState {
    pub(in crate::snapshots) fn note_activity_at(&mut self, timestamp: &str) {
        match self.first_activity_at.as_ref() {
            Some(current) if timestamp_is_before(timestamp, current) => {
                self.first_activity_at = Some(timestamp.to_string())
            }
            None => self.first_activity_at = Some(timestamp.to_string()),
            _ => {}
        }
        match self.last_activity_at.as_ref() {
            Some(current) if timestamp_is_after(timestamp, current) => {
                self.last_activity_at = Some(timestamp.to_string())
            }
            None => self.last_activity_at = Some(timestamp.to_string()),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::snapshots) enum CodexOwnershipBoundary {
    /// No authoritative session header has been observed yet. Records cannot
    /// be admitted until the header proves whether a physical prefix exists.
    #[default]
    Undetermined,
    /// The rollout has no inherited physical prefix, or uses a paginated
    /// history_base whose referenced records are not local child records.
    AllLocal,
    /// Legacy subagent fork: records are inherited until the first provider
    /// trigger-turn marker.
    AwaitingLegacyTrigger,
    /// Decode-only tombstone for a retired ownership boundary; always held.
    AwaitingParentPrefix,
    /// Native Codex boundary: ordinals below `start` are inherited context.
    Ordinal { start: u64 },
    /// Provider-created physical child whose own creation envelope starts at
    /// ordinal zero. Every record remains tentatively local while the complete
    /// native ordinal/timestamp stream and first-turn binding are validated;
    /// any later structural break suppresses the whole file at finalization.
    NativeCreatedThread,
    /// A fork was observed but its inherited prefix cannot be proven locally.
    /// Usage must fail closed rather than publish an inclusive total.
    AmbiguousFork,
}
crate::durable_tail_codec::durable_enum!(CodexOwnershipBoundary {
    0 => Undetermined,
    1 => AllLocal,
    2 => AwaitingLegacyTrigger,
    3 => AwaitingParentPrefix [decode_only],
    4 => Ordinal { N start: u64 },
    5 => NativeCreatedThread,
    6 => AmbiguousFork,
});

/// An open Codex call's provider call id, apart from its tool name, so a
/// durable record's `L` span is the id alone.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) struct ActivityCallId {
    pub(in crate::snapshots) id: String,
}

impl std::borrow::Borrow<str> for ActivityCallId {
    fn borrow(&self) -> &str {
        &self.id
    }
}

/// The tool name an open Codex call was counted under (`U`: the activity
/// tool counts upload it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct ActivityCallTool {
    pub(in crate::snapshots) name: String,
}

#[derive(Clone)]
pub(in crate::snapshots) struct SnapshotAccumulator {
    pub(in crate::snapshots) source: SnapshotSource,
    pub(in crate::snapshots) cache_configuration_witness: Option<String>,
    pub(in crate::snapshots) cache_task_complete_at: Option<String>,
    pub(in crate::snapshots) cache_pending_idle: Option<u64>,
    // Raw turn ids (class L): never uploaded except where the upload contract
    // already carries it; persisted only in the local durable-tail store.
    pub(in crate::snapshots) cache_active_turns: BTreeSet<String>,
    /// Retired with full context-curve upload; always false. Kept, like the
    /// three `codex_context_curve_*` slots, so the pinned durable-tail
    /// allowlist digest and records already on disk stay valid.
    pub(in crate::snapshots) context_curve_enabled: bool,
    pub(in crate::snapshots) source_session_id: Option<String>,
    pub(in crate::snapshots) account_identifier_hash: Option<String>,
    pub(in crate::snapshots) title: Option<String>,
    pub(in crate::snapshots) title_source: Option<String>,
    pub(in crate::snapshots) first_prompt_title: Option<String>,
    // In-memory only: bounded first-user text used to derive opaque template,
    // schedule, and explicit slash-skill facts. The source text is never copied
    // into SnapshotItem; at most a separately sanitized 96-byte prefix is.
    pub(in crate::snapshots) first_prompt_material: Option<String>,
    // Private local state: provider-native skill names. HMACed before facts
    // are produced; an allowlisted short name may also become a private display
    // label, which upload policy strips unless title consent is active.
    pub(in crate::snapshots) provider_skills: BTreeSet<String>,
    pub(in crate::snapshots) started_at: Option<String>,
    pub(in crate::snapshots) ended_at: Option<String>,
    pub(in crate::snapshots) last_activity_at: Option<String>,
    pub(in crate::snapshots) workspace_hash: Option<String>,
    // Local Workspace fact used to derive privacy-safe repository identity.
    // The raw path is never copied into SnapshotItem or uploaded.
    pub(in crate::snapshots) workspace_path: Option<PathBuf>,
    // Session-owned observation, retained independently of the path cache.
    pub(in crate::snapshots) repository_binding:
        Option<crate::context_footprint::RepositoryIdentity>,
    pub(in crate::snapshots) latest_model: Option<String>,
    // Most-recently-observed Codex per-turn reasoning effort tier. Updated as
    // lines stream past so the next usage row picks up the effort co-located
    // with that turn's token_count.
    pub(in crate::snapshots) latest_reasoning_effort: Option<String>,
    // Most-recently-observed Codex turn id (from `turn_context.payload.turn_id`).
    // The token_count event carries no turn id, so the running turn id is what
    // joins each usage row to its `logs_2` fast-mode signal. Raw id (class L):
    // never uploaded except where the upload contract already carries it;
    // persisted only in the local durable-tail store.
    pub(in crate::snapshots) latest_turn_id: Option<String>,
    // Per-turn fast-mode signal read once per scan from `logs_2.sqlite`. Shared
    // read-only across every session file in the cycle via `Arc`.
    pub(in crate::snapshots) codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    // Keyed by raw turn id (class L): never uploaded except where the upload
    // contract already carries it; persisted only in the local durable-tail
    // store.
    pub(in crate::snapshots) codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
    /// A paged cursor job keeps every turn witness, charged by bytes in its
    /// slot; every other reader keeps the cache-only witness caps.
    pub(in crate::snapshots) codex_priority_witnesses_uncapped: bool,
    pub(in crate::snapshots) codex_tier_replay: Option<codex_file_join::TierReplay>,
    // Usage-counting V2 state. `None` (unconfigured) and a Legacy decision
    // keep today's counting byte for byte.
    pub(in crate::snapshots) codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
    pub(in crate::snapshots) current_selector: SelectorCapture,
    pub(in crate::snapshots) session_cumulative_usage: Option<UsageTotals>,
    pub(in crate::snapshots) codex_session_meta_seen: bool,
    pub(in crate::snapshots) codex_record_seen: bool,
    pub(in crate::snapshots) codex_creator_header_id: Option<String>,
    pub(in crate::snapshots) codex_creator_evidence: Option<SessionAccountEvidence>,
    pub(in crate::snapshots) codex_creator_evidence_conflicted: bool,
    pub(in crate::snapshots) claude_desktop_identity: Option<SessionAccountEvidence>,
    /// The session that started this one from the Claude desktop app.
    pub(in crate::snapshots) claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
    pub(in crate::snapshots) claude_owned_session_id_observed: bool,
    pub(in crate::snapshots) claude_owned_session_id_conflicted: bool,
    pub(in crate::snapshots) codex_ownership_boundary: CodexOwnershipBoundary,
    pub(in crate::snapshots) codex_legacy_trigger_seen: bool,
    pub(in crate::snapshots) codex_legacy_bootstrap_valid: bool,
    // Trusted state-row created-thread classification bound to this opened
    // rollout by its provider session id. Generic spawn edges cannot set it.
    pub(in crate::snapshots) codex_sidecar_created_thread: bool,
    // A timestamp-shaped rollout name has two valid provider grammars. Keep
    // both byte-preserving identities until trusted state/census evidence or
    // the first authoritative header selects exactly one.
    pub(in crate::snapshots) codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
    pub(in crate::snapshots) codex_resolved_path_identity: Option<String>,
    // The rollout-path identity is collision-ambiguous, or a required census
    // failed without a key scope. It must never enter a generic ownership arm.
    pub(in crate::snapshots) codex_sidecar_identity_ambiguous: bool,
    // Trusted, content-free child -> parent edge loaded from Codex's local
    // state DB before the rollout is parsed. It is lineage evidence for the
    // native witness, distinct from the classification bit above.
    pub(in crate::snapshots) codex_sidecar_parent: Option<(String, String)>,
    // Provider state-row creation time for the trusted child edge. Fresh-file
    // timestamps must not precede this physical spawn witness.
    pub(in crate::snapshots) codex_sidecar_child_created_at_nanos: Option<i128>,
    /// L-6: the file length the sidecar bind saw (`seed_codex_sidecar_parent`).
    /// A curable hold is memoized only at exactly this length.
    pub(in crate::snapshots) codex_bind_seed_len: Option<u64>,
    // Codex's independently projected EOF ordinal, when thread_history_1 is
    // available. The native stream must end at the same ordinal boundary.
    pub(in crate::snapshots) codex_sidecar_projected_next_ordinal: Option<u64>,
    pub(in crate::snapshots) codex_parent_session_ref: Option<String>,
    // Fresh provider-created rollouts use a native creation envelope and one
    // gap-free ordinal stream. These fields bind the first task/turn to that
    // envelope and reject retrograde timestamps anywhere in the opened file.
    pub(in crate::snapshots) codex_native_created_thread_valid: bool,
    pub(in crate::snapshots) codex_created_thread_native_only: bool,
    pub(in crate::snapshots) codex_native_created_thread_header_nanos: Option<i128>,
    pub(in crate::snapshots) codex_native_created_thread_last_nanos: Option<i128>,
    // Raw turn id (class L): never uploaded except where the upload contract
    // already carries it; persisted only in the local durable-tail store.
    pub(in crate::snapshots) codex_native_created_thread_task_turn_id: Option<String>,
    pub(in crate::snapshots) codex_native_created_thread_first_turn_bound: bool,
    pub(in crate::snapshots) codex_ordinal_expected: Option<u64>,
    pub(in crate::snapshots) codex_ordinal_sequence_valid: bool,
    pub(in crate::snapshots) codex_owned_record_seen: bool,
    pub(in crate::snapshots) codex_is_fork: bool,
    pub(in crate::snapshots) codex_inherited_usage_records_skipped: u64,
    pub(in crate::snapshots) codex_duplicate_usage_records_skipped: u64,
    pub(in crate::snapshots) codex_cumulative_reset_count: u64,
    // Retired durable-tail slots (see `context_curve_enabled`): always empty.
    pub(in crate::snapshots) codex_context_curve_candidates:
        crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    pub(in crate::snapshots) codex_context_curve_boundaries:
        crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    pub(in crate::snapshots) codex_context_curve_exact_supported: bool,
    // Identity of the last provider usage event, used only to collapse an
    // exact repeated physical checkpoint. Cumulative totals alone are not an
    // occurrence key: a restarted epoch can legitimately reach the same total.
    pub(in crate::snapshots) codex_last_usage_event_identity: Option<String>,
    // Legacy child initialization records are written immediately before the
    // trigger marker. Keep only the bounded, usage-free suffix beginning at
    // the last task_started so its turn model/tier/title state can be replayed
    // as child-owned once the marker proves the boundary.
    pub(in crate::snapshots) codex_legacy_bootstrap_buffer: Vec<Value>,
    // Exact sum of every usage record admitted to the wire projection. A
    // provider record that would overflow any u64 wire field is refused before
    // bucket mutation and counted as dropped, keeping the file retryable.
    pub(in crate::snapshots) accepted_usage_totals: UsageTotals,
    pub(in crate::snapshots) usage_buckets: BTreeMap<String, UsageBucketState>,
    pub(in crate::snapshots) origin: SnapshotOrigin,
    pub(in crate::snapshots) codex_root_session_ref: Option<String>,
    pub(in crate::snapshots) codex_spawn_depth: Option<u64>,
    // In-memory only: a sanitized, humanized leaf from Codex's content-free
    // `/root/<task_name>` agent path. The raw path never enters SnapshotItem.
    pub(in crate::snapshots) codex_agent_label: Option<String>,
    pub(in crate::snapshots) activity_tool_counts: BTreeMap<String, u64>,
    // Keyed by raw call id (class L): never uploaded except where the upload
    // contract already carries it; persisted only in the local durable-tail
    // store, apart from the tool name (U).
    pub(in crate::snapshots) activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
    pub(in crate::snapshots) activity_mcp_tool_counts: BTreeMap<String, u64>,
    // Codex MCP calls keyed by the backend's qualified `mcp__<server>__<tool>`
    // spelling. Fed by the same `mcp_tool_call_end` events as the activity map,
    // and by `function_call`s that name their server in `payload.namespace`.
    pub(in crate::snapshots) activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
    // Open call ids already counted as MCP, so a call is counted once whichever
    // of its namespaced `function_call` and `mcp_tool_call_end` comes first.
    // The value records whether the completion event (and its capability) was
    // seen. Like `activity_call_tools`, entries end at `function_call_output`.
    // Raw MCP call ids (class L): never uploaded except where the upload
    // contract already carries it; persisted only in the local durable-tail
    // store.
    pub(in crate::snapshots) activity_mcp_call_ids: BTreeMap<String, bool>,
    pub(in crate::snapshots) activity_capability_buckets: BTreeMap<(String, String, String), u64>,
    // Claude-only summary: the seen-tool-use walk does not grow with history.
    // Raw tool-use ids (class L): never uploaded except where the upload
    // contract already carries it; persisted only in the local durable-tail
    // store.
    pub(in crate::snapshots) seen_claude_capability_tool_uses:
        crate::owned_heap::OwnedMap<String, ()>,
    pub(in crate::snapshots) activity_skills: BTreeSet<String>,
    // A SKILL.md reference whose skill could not be named (`cat SKILL.md`,
    // `skills/*/SKILL.md`). The session then keeps the v1 capability marker:
    // its skill list may be incomplete, so it cannot prove "no skill used".
    pub(in crate::snapshots) skill_detector_incomplete: bool,
    pub(in crate::snapshots) activity_changed_file_hashes: BTreeSet<String>,
    pub(in crate::snapshots) activity_patch_operations: u64,
    pub(in crate::snapshots) activity_lines_added: u64,
    pub(in crate::snapshots) activity_lines_deleted: u64,
    pub(in crate::snapshots) activity_web_searches: u64,
    pub(in crate::snapshots) activity_mcp_calls: u64,
    pub(in crate::snapshots) activity_subagent_spawns: u64,
    pub(in crate::snapshots) artifacts: Vec<SessionArtifact>,
    /// Retired: links are always scraped and filtered only at upload. Kept
    /// because the durable record shape carries this byte.
    pub(in crate::snapshots) artifacts_enabled: bool,
    // Codex per-session latency accumulators, summed from rollout
    // `task_complete` events (`duration_ms` + `time_to_first_token_ms`) and
    // averaged in `into_items`. Zero counts mean no latency was observed.
    pub(in crate::snapshots) latency_duration_ms_sum: u64,
    pub(in crate::snapshots) latency_duration_ms_count: u64,
    pub(in crate::snapshots) latency_ttft_ms_sum: u64,
    pub(in crate::snapshots) latency_ttft_ms_count: u64,
    // Max (slowest single turn) alongside the avg — the tail the average hides.
    pub(in crate::snapshots) latency_duration_ms_max: u64,
    pub(in crate::snapshots) latency_ttft_ms_max: u64,
    // Claude Code persists one assistant record per content block. Sidechain
    // writers update output_tokens progressively across those records, so a
    // response must be resolved in full before any tokens, selectors, latency,
    // posture, or request count enter the session projection. The map is local
    // to one complete transcript parse; its key format also provides the seam
    // for a future scan-level legacy-fork ownership ledger.
    pub(in crate::snapshots) claude_responses: ClaudeResponseBook,
    pub(in crate::snapshots) claude_response_sequence: u64,
    pub(in crate::snapshots) claude_response_record_count: usize,
    // Exact provider response ids for the once-per-response Claude usage rows
    // above. Local-only; copied into SnapshotItem solely for account-evidence
    // coverage and never serialized.
    pub(in crate::snapshots) claude_usage_request_ids: BTreeSet<String>,
    pub(in crate::snapshots) claude_usage_occurrences:
        BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    /// Capture transcript markers: the scan's cycle holds a contract-5 permit.
    pub(in crate::snapshots) claude_request_identity_capture: bool,
    pub(in crate::snapshots) claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    pub(in crate::snapshots) cache_observations: Option<CacheObservations>,
    pub(crate) cache_requests: crate::owned_heap::OwnedVec<OwnedRequest>,
    pub(in crate::snapshots) cache_requests_complete: bool,
    pub(in crate::snapshots) claude_context_curve_identity_complete: bool,
    pub(in crate::snapshots) claude_context_curve_request_index_complete: bool,
    pub(in crate::snapshots) claude_context_curve_owned_start_proven: bool,
    pub(in crate::snapshots) claude_file_birth: ClaudeFileBirth,
    /// The original a `/branch` copy names (`fork-context-ref`); empty when
    /// the file names two or an invalid one. `e2` copy proof only.
    pub(in crate::snapshots) claude_fork_parent: Option<String>,
    pub(in crate::snapshots) claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    pub(in crate::snapshots) tool_usage_counts: BTreeMap<String, u64>,
    pub(in crate::snapshots) tool_usage_truncated: bool,
    // Current Pi transcripts carry usage on `type=message` assistant records;
    // older exporters used `type=message_end`. When both representations are
    // present, their response id is the exact occurrence key that prevents a
    // compatibility parser from charging the same response twice.
    // Each response id retains the unmatched digest multiset for both record
    // shapes. A later opposite-shape exact match consumes one occurrence;
    // repeated same-shape occurrences remain distinct. Keeping the multiset is
    // required because transitional writers may reuse one response id for more
    // than one paired occurrence.
    pub(in crate::snapshots) seen_pi_usage_keys: PiLedger,
    // Positive usage observations deliberately refused because their activity
    // timestamp could not produce a truthful hourly bucket.
    pub(in crate::snapshots) dropped_usage_record_count: u64,
    // Timestamp of the most recent Claude Code `type=user` record (a real user
    // prompt OR a tool_result — both are "model input available" moments). Each
    // assistant API response's first content-block record subtracts this to
    // derive that turn's wall-clock duration, feeding the shared
    // `latency_duration_ms_*` accumulators. Claude Code stamps every record with
    // an ms-precision RFC3339 timestamp but no first-token marker, so only whole
    // turn duration is derivable this way, never TTFT.
    pub(in crate::snapshots) claude_last_user_ts: Option<String>,
    // Desktop-lineage clocks (L04): the earliest and latest top-level
    // `timestamp` over every whole Claude line, copied history included, in
    // unix nanoseconds. Stored in the first head format so the lineage window
    // can come from the head; not read yet.
    pub(in crate::snapshots) claude_line_clocks: Option<(i128, i128)>,
    // Context posture (see the SnapshotItem field docs). Running max /
    // first-seen watermarks over each counted API response's effective input
    // context, plus a count of compaction records. The Claude Code and Codex
    // line parsers each feed these from their own records — the per-source
    // input-scope difference is resolved before it reaches here, so both write
    // the same window-comparable measure. Pi leaves them at their zero values
    // and emits None.
    pub(in crate::snapshots) peak_context_fill_tokens: u64,
    pub(in crate::snapshots) first_turn_context_tokens: Option<u64>,
    pub(in crate::snapshots) last_turn_context_tokens: Option<u64>,
    // Codex only: the `model_context_window` of the record that set each
    // watermark above (see the SnapshotItem field docs). Set in the same
    // owned-record step as the watermarks, so a retained Tail continuation
    // carries them exactly as a full read would.
    pub(in crate::snapshots) first_turn_context_window_tokens: Option<u64>,
    pub(in crate::snapshots) peak_context_fill_window_tokens: Option<u64>,
    pub(in crate::snapshots) last_turn_context_window_tokens: Option<u64>,
    pub(in crate::snapshots) compaction_count: u64,
    pub(in crate::snapshots) compaction_timestamps: crate::owned_heap::OwnedVec<String>,
    // Codex only: sizes index-aligned with `compaction_timestamps`.
    pub(in crate::snapshots) codex_compaction_sizes: CodexCompactionSizes,
    // Codex only: bounded points for the local Sessions graph.
    pub(in crate::snapshots) local_context_points: LocalContextPoints,
    pub(in crate::snapshots) claude_compaction_observations:
        crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    // Pair key of the latest boundary still waiting for its legacy summary and
    // the uuid at the tip of its `attachment` chain. One slot suffices: the
    // provider writes boundary, attachments, then summary as a linear chain.
    pub(in crate::snapshots) claude_compaction_link_tip: Option<(u64, String)>,
    pub(in crate::snapshots) session_start: Box<session_start::SessionStartState>,
    /// Codex: each dictionary key's stable Tail page slot. Never set for
    /// another source, and never stored as a whole (the pages rebuild it).
    pub(in crate::snapshots) codex_dictionary_slots: codex_dictionary_slots::CodexDictionarySlots,
    /// The existing ownership-affecting sidecar dependency, independent of upload scope.
    pub(in crate::snapshots) codex_sidecar_binding: Option<String>,
}

impl SnapshotAccumulator {
    fn note_tool_usage(&mut self, name: String) {
        if let Some(count) = self.tool_usage_counts.get_mut(&name) {
            *count = count.saturating_add(1);
        } else if self.tool_usage_counts.len() < MAX_TOOL_USAGE_NAMES {
            self.tool_usage_counts.insert(name, 1);
        } else {
            self.tool_usage_truncated = true;
        }
    }

    /// Fold one resolved Claude response's wall-clock duration into the session
    /// latency accumulators. The preceding user timestamp is captured when the
    /// response's first content block arrives, before later transcript records
    /// can advance the streaming user cursor.
    fn note_claude_turn_duration_between(
        &mut self,
        user_ts: Option<&str>,
        assistant_ts: Option<&str>,
    ) {
        let Some(Ok(duration_ms)) = user_ts
            .zip(assistant_ts)
            .and_then(|(user, assistant)| cache_observations::elapsed(user, assistant))
            .map(|elapsed| u64::try_from(elapsed.whole_milliseconds()))
        else {
            return;
        };
        self.latency_duration_ms_sum = self.latency_duration_ms_sum.saturating_add(duration_ms);
        self.latency_duration_ms_count += 1;
        self.latency_duration_ms_max = self.latency_duration_ms_max.max(duration_ms);
    }

    pub(in crate::snapshots) fn fallback_bucket_timestamp(
        &self,
        collected_at: Option<&str>,
    ) -> Option<String> {
        self.last_activity_at
            .clone()
            .or_else(|| self.started_at.clone())
            .or_else(|| collected_at.map(|value| value.to_string()))
    }

    pub(in crate::snapshots) fn set_title(&mut self, title: Option<String>, source: &str) {
        // Claude transcript titles come from already validated customTitle records.
        // Preserve that validation policy through this second normalization while
        // retaining the existing emitted source and Codex transcript-title policy.
        let normalization_source =
            if self.source == SnapshotSource::ClaudeCode && source == "transcript_title" {
                "custom_title"
            } else {
                source
            };
        let Some(title) =
            title.and_then(|value| normalize_display_title(value, normalization_source))
        else {
            return;
        };
        self.title = Some(title);
        self.title_source = Some(source.to_string());
    }

    pub(in crate::snapshots) fn set_title_if_absent(
        &mut self,
        title: Option<String>,
        source: &str,
    ) {
        if self.title.is_some() {
            return;
        }
        self.set_title(title, source);
    }

    pub(in crate::snapshots) fn set_first_prompt_title(&mut self, value: Option<String>) {
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

    pub(in crate::snapshots) fn note_provider_skill(&mut self, value: Option<String>) {
        let Some(value) = value else {
            return;
        };
        let normalized = value.trim().to_ascii_lowercase();
        // One past the fact cap is enough to keep invocations ahead of
        // references in `grouping_facts`; more would only grow memory.
        if !normalized.is_empty()
            && normalized.len() <= 128
            && self.provider_skills.len() <= crate::session_attribution::MAX_SKILL_FACTS
        {
            self.provider_skills.insert(normalized);
        }
    }

    pub(in crate::snapshots) fn apply_codex_title_metadata(
        &mut self,
        path: &Path,
        metadata: &CodexTitleMetadata,
    ) {
        let session_id = self
            .source_session_id
            .clone()
            .or_else(|| metadata.identity_from_path_evidence(path));
        let Some(session_id) = session_id else {
            return;
        };
        let session_id = resolve_codex_identity(session_id.as_str());
        if let Some((parent, root, depth)) = metadata.family_position(session_id.as_str()) {
            self.origin.thread_source = Some("subagent".to_string());
            self.origin.source_subagent = Some(true);
            self.origin.parent_session_ref = Some(parent);
            self.codex_root_session_ref = Some(root);
            self.codex_spawn_depth = Some(depth);
        }
        if self.title.is_some() {
            return;
        }
        if let Some(title) = metadata.titles.get(session_id.as_str()) {
            self.set_title_if_absent(Some(title.title.clone()), title.source.as_str());
        }
    }

    pub(in crate::snapshots) fn apply_claude_title_metadata(
        &mut self,
        path: &Path,
        metadata: &ClaudeTitleMetadata,
    ) {
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
        // The exact native transcript id joins Desktop metadata. A copied
        // locator or a child's parent id cannot create an original owner.
        if self.claude_owned_session_id_observed
            && path.file_stem().and_then(|value| value.to_str()) == Some(session_id.as_str())
        {
            let mut evidence = metadata.session_account_evidence(&session_id);
            if self.claude_owned_session_id_conflicted {
                evidence.identity_disposition = Some("conflict");
            }
            self.claude_desktop_identity = Some(evidence);
        }
        // Keyed by the transcript's own file stem: the desktop store names
        // native sessions by `cliSessionId`, never by a copied locator.
        if path.file_stem().and_then(|value| value.to_str()) == Some(session_id.as_str()) {
            self.claude_desktop_spawn_lineage = metadata.spawn_lineage(&session_id).cloned();
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

    pub(in crate::snapshots) fn apply_first_prompt_fallback(&mut self) {
        if self.title.is_some() {
            return;
        }
        self.set_title_if_absent(self.first_prompt_title.clone(), "first_prompt");
    }

    pub(in crate::snapshots) fn set_workspace_hash(&mut self, value: Option<String>) {
        if self.workspace_hash.is_none() {
            if let Some(raw) = value {
                self.workspace_hash = Some(sha256_hex(&[raw.as_str()]));
                self.workspace_path = Some(PathBuf::from(raw));
            }
        }
    }

    pub(in crate::snapshots) fn set_model(&mut self, model: Option<String>) {
        if let Some(model) = model.and_then(normalize_title) {
            self.latest_model = Some(model);
        }
    }

    pub(in crate::snapshots) fn set_selector(&mut self, selector: SelectorCapture) {
        if selector.is_empty() {
            return;
        }
        // Running display context for usage rows. Row keys are derived
        // per-line from the merged selector inside add_usage_with_selector.
        self.current_selector.merge(selector);
    }

    pub(in crate::snapshots) fn note_dropped_usage(&mut self) {
        self.dropped_usage_record_count = self.dropped_usage_record_count.saturating_add(1);
    }

    /// True when the running turn (`latest_turn_id`) paid for Codex fast mode,
    /// per the `logs_2` request tier. Used to stamp `service_tier=priority` onto
    /// that turn's usage row only — never onto `current_selector`, so the signal
    /// does not bleed into later standard turns of the same session.
    pub(in crate::snapshots) fn current_turn_is_priority(&mut self) -> bool {
        let Some(turn_id) = self.latest_turn_id.as_ref() else {
            return false;
        };
        let priority = self
            .codex_turn_traces
            .as_ref()
            .is_some_and(|traces| traces.is_priority_turn(turn_id));
        if let Some(observed) = self.codex_observed_priority_turns.as_mut() {
            if !self.codex_priority_witnesses_uncapped
                && (turn_id.len() > sampled_jsonl::MAX_PRIORITY_WITNESS_ID_BYTES
                    || (observed.len() >= sampled_jsonl::MAX_PRIORITY_WITNESSES
                        && !observed.contains_key(turn_id)))
            {
                // Dropping a dependency witness disables future retention,
                // never the native usage decision or durable audit obligation.
                self.codex_observed_priority_turns = None;
            } else {
                if self.source == SnapshotSource::Codex {
                    self.codex_dictionary_slots.priority_turns.note(turn_id);
                }
                observed.insert(turn_id.clone(), priority);
            }
        }
        priority
    }

    /// Replace the running requested tier from one in-epoch thread-settings
    /// snapshot. Only an explicit non-default tier sets it; anything else
    /// clears it, adds no `service_tier` and prices as standard, so an earlier
    /// Fast never outlives its replacement. Pre-epoch and undated events change
    /// nothing: a record saved before the release holds no tier, so counting
    /// them would make a Full differ from its restored Tail.
    pub(in crate::snapshots) fn note_codex_thread_settings(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
    ) {
        if !string_eq_at(value, &["type"], "event_msg")
            || !string_eq_at(value, &["payload", "type"], "thread_settings_applied")
        {
            return;
        }
        let requested = string_at(value, &["payload", "thread_settings", "service_tier"]);
        let tier = match requested.as_deref() {
            Some("fast" | "priority") => Some("priority"),
            Some("flex") => Some("flex"),
            _ => None,
        };
        if tier.is_some() {
            crate::local_resource_diagnostics::codex_non_default_thread_tier();
        }
        if !in_codex_forward_evidence_epoch(timestamp) {
            return;
        }
        let context = &mut self.current_selector.context;
        match tier {
            Some(tier) => {
                context.insert(CODEX_THREAD_TIER.into(), tier.into());
            }
            None => {
                context.remove(CODEX_THREAD_TIER);
            }
        }
    }

    /// Stamp one in-epoch request with its requested-tier estimate. Runs after
    /// `logs_2` and the protected replay, whose tiers win; the replay never
    /// sees this stamp, so it files no applied-tier receipt.
    pub(in crate::snapshots) fn stamp_codex_thread_tier(
        &self,
        selector: &mut SelectorCapture,
        timestamp: Option<&str>,
    ) {
        let Some(tier) = self.current_selector.context.get(CODEX_THREAD_TIER) else {
            return;
        };
        if in_codex_forward_evidence_epoch(timestamp)
            && !selector.context.contains_key("service_tier")
            && !self.current_selector.context.contains_key("service_tier")
        {
            selector.insert("service_tier", tier.clone(), "derived_from_thread_settings");
        }
    }

    pub(in crate::snapshots) fn add_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        effort: Option<String>,
    ) {
        if let Some(placed) =
            self.place_usage(model, &usage, selector, timestamp, effort.as_deref())
        {
            self.add_placed_usage(placed, usage, effort);
        }
    }

    /// The native model and row placement of one usage; None for zero usage,
    /// which adds no row.
    fn place_usage(
        &mut self,
        model: Option<String>,
        usage: &UsageTotals,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        effort: Option<&str>,
    ) -> Option<PlacedClaudeUsage> {
        if usage.is_zero() {
            return None;
        }
        let fell_back = model.is_none();
        let model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| IMPLICIT_USAGE_MODEL.to_string());
        self.latest_model = Some(model.clone());

        let fallback = timestamp
            .is_none()
            .then(|| self.fallback_bucket_timestamp(None))
            .flatten();
        let placement = claude_row_placement(
            &model,
            &self.current_selector,
            selector,
            effort,
            timestamp,
            fallback.as_deref(),
        );
        Some(PlacedClaudeUsage {
            model,
            fell_back,
            placement,
        })
    }

    fn add_placed_usage(
        &mut self,
        placed: PlacedClaudeUsage,
        usage: UsageTotals,
        effort: Option<String>,
    ) {
        let PlacedClaudeUsage {
            placement:
                Some(ClaudeRowPlacement {
                    bucket: bucket_start,
                    normalized_timestamp,
                    row_key,
                    reduced_context,
                    reduced_sources,
                }),
            ..
        } = placed
        else {
            self.note_dropped_usage();
            return;
        };
        if !self.accepted_usage_totals.add(&usage) {
            self.note_dropped_usage();
            return;
        }

        let bucket = self.usage_buckets.entry(bucket_start).or_default();
        bucket.note_activity_at(&normalized_timestamp);
        match bucket.rows.get_mut(&row_key) {
            Some(row) => {
                for (field, source) in reduced_sources {
                    row.selector_sources.insert(field, source);
                }
                let row_added = row.usage.add(&usage);
                debug_assert!(row_added);
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

    // Usage ownership needs the event identity, selector, activity time, and
    // effort beside both cumulative and last-response counters. Keeping these
    // inputs together makes the one-occurrence accounting invariant explicit.
    #[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
    pub(in crate::snapshots) fn set_cumulative_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
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
        if self.codex_counting_v2() {
            return self.set_codex_v2_cumulative_usage(
                model,
                usage,
                last_usage,
                usage_event_identity,
                selector,
                timestamp,
                implicit_request_count,
                effort,
            );
        }
        let (resolved_model, delta) = self.decide_codex_legacy_usage(
            model,
            usage,
            last_usage,
            usage_event_identity,
            timestamp,
            implicit_request_count,
        )?;
        self.add_usage_with_selector(
            Some(resolved_model),
            delta.clone(),
            selector,
            timestamp,
            effort,
        );
        Some(delta)
    }

    /// Admission steps shared by the legacy and v2 decisions, in their
    /// order: the model carries forward, an exact repeated usage event is
    /// skipped (`None`), a cumulative reset is counted and `usage` becomes
    /// the cumulative total. Returns the resolved model, the previous
    /// cumulative total and whether `usage` reset it.
    pub(in crate::snapshots) fn admit_codex_cumulative_usage(
        &mut self,
        model: Option<String>,
        usage: &UsageTotals,
        usage_event_identity: Option<String>,
    ) -> Option<(String, Option<UsageTotals>, bool)> {
        let resolved_model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| IMPLICIT_USAGE_MODEL.to_string());
        self.latest_model = Some(resolved_model.clone());
        // Only an exact repeated physical usage event is a duplicate. Equal
        // cumulative totals are not an occurrence identity: after a restart,
        // a new response can legitimately bring the new epoch to the same
        // counters while `last_token_usage` proves positive work.
        if usage_event_identity.is_some()
            && usage_event_identity == self.codex_last_usage_event_identity
        {
            self.codex_duplicate_usage_records_skipped =
                self.codex_duplicate_usage_records_skipped.saturating_add(1);
            return None;
        }
        if usage_event_identity.is_some() {
            self.codex_last_usage_event_identity = usage_event_identity;
        }
        let reset = self
            .session_cumulative_usage
            .as_ref()
            .is_some_and(|previous| !usage.is_monotonic_after(previous));
        if reset {
            self.codex_cumulative_reset_count = self.codex_cumulative_reset_count.saturating_add(1);
        }
        let previous = self.session_cumulative_usage.replace(usage.clone());
        Some((resolved_model, previous, reset))
    }

    /// Admission only. The native caller owns publication; bounded replay
    /// uses the same ordered state transition without constructing money rows.
    fn decide_codex_legacy_usage(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
        timestamp: Option<&str>,
        implicit_request_count: Option<u64>,
    ) -> Option<(String, UsageTotals)> {
        let (resolved_model, previous, reset) =
            self.admit_codex_cumulative_usage(model, &usage, usage_event_identity)?;
        // `last_token_usage` is Codex's exact current-response usage and stays
        // correct across compaction/restart resets. Older rollouts lack it; in
        // that case use a cumulative delta, beginning a new additive epoch on
        // a reset. Never erase usage already accepted from the same rollout.
        let mut delta = match &last_usage {
            Some(last) => last.clone(),
            None => match &previous {
                Some(previous) if !reset => usage.delta_from(previous),
                Some(_) | None => usage.clone(),
            },
        };
        if !delta.is_zero() {
            if let Some(count) = implicit_request_count {
                delta.request_count = count;
            }
        }
        if delta.is_zero() {
            return None;
        }
        // The V2 equal-total repeat gate: a re-emitted line with the same
        // `last` and total as the previous counted one is not a new request.
        // Forward only: earlier lines count as they always did, and still
        // set the tuple a later dated repeat is compared with.
        let may_drop = dated_on_or_after(timestamp, CODEX_LEGACY_REPEAT_FROM_UNIX_SECONDS);
        if self.codex_legacy_ui_repeat(last_usage, usage, &delta, may_drop) {
            return None;
        }
        Some((resolved_model, delta))
    }
}

type RepositoryIdentityCache =
    BTreeMap<PathBuf, (SystemTime, crate::context_footprint::RepositoryIdentity)>;

fn repository_identity_cache() -> &'static Mutex<RepositoryIdentityCache> {
    static CACHE: OnceLock<Mutex<RepositoryIdentityCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn fresh_repository_identity(
    cache: &RepositoryIdentityCache,
    workspace: &Path,
    now: SystemTime,
) -> Option<crate::context_footprint::RepositoryIdentity> {
    let (captured_at, identity) = cache.get(workspace)?;
    now.duration_since(*captured_at)
        .map(|age| age.as_secs() <= REPOSITORY_IDENTITY_CACHE_TTL_SECONDS)
        .unwrap_or(false)
        .then(|| identity.clone())
}

pub(in crate::snapshots) fn cached_repository_identity(
    workspace: &Path,
) -> crate::context_footprint::RepositoryIdentity {
    // A cached path observation cannot locate a session whose cwd has gone.
    // The shared resolver classifies this failure without spawning Git.
    if fs::read_dir(workspace).is_err() {
        return crate::context_footprint::resolve_repository_identity(workspace, true);
    }
    let cache = repository_identity_cache();
    let now = SystemTime::now();
    if let Ok(guard) = cache.lock() {
        if let Some(identity) = fresh_repository_identity(&guard, workspace, now) {
            return identity;
        }
    }

    let identity = crate::context_footprint::resolve_repository_identity(workspace, true);
    // Negative observations must not delay a later git init or repaired lookup.
    if identity.is_repository() {
        if let Ok(mut guard) = cache.lock() {
            if guard.len() >= REPOSITORY_IDENTITY_CACHE_MAX_ENTRIES {
                guard.clear();
            }
            guard.insert(workspace.to_path_buf(), (now, identity.clone()));
        }
    }
    identity
}

pub(in crate::snapshots) fn merge_session_row(
    session_rows: &mut BTreeMap<RowKey, BucketRowAccumulator>,
    row_key: RowKey,
    row: BucketRowAccumulator,
) {
    match session_rows.get_mut(&row_key) {
        Some(existing) => {
            for (field, source) in row.selector_sources {
                existing.selector_sources.insert(field, source);
            }
            let row_added = existing.usage.add(&row.usage);
            debug_assert!(row_added);
            debug_assert_eq!(existing.reasoning_effort, row.reasoning_effort);
        }
        None => {
            session_rows.insert(row_key, row);
        }
    }
}

pub(in crate::snapshots) fn model_usage_from_row(
    row_key: &RowKey,
    row: &BucketRowAccumulator,
) -> SnapshotModelUsage {
    SnapshotModelUsage {
        copy_unproven: row_key.selector_hash.starts_with(COPY_UNPROVEN_PARTITION),
        evidence_ref: None,
        identity_parts: None,
        identity_retained: false,
        copy_invalidated: false,
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
pub(in crate::snapshots) fn build_row_identity(
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

/// `current_selector` key of the running Codex requested tier: reducer state
/// that survives Tail and restore in the record. Not in
/// `SELECTOR_CONTEXT_ALLOWED`, so it never reaches a row or the wire.
pub(in crate::snapshots) const CODEX_THREAD_TIER: &str = "codex_thread_tier";

// Mirror of backend SELECTOR_FIELDS (selector_context.py). Daemon-side
// reduction matches the backend's normalize_selector_context so two rows
// that differ only in a key the backend would strip aren't emitted as
// distinct rows here (which would trip "duplicate model selector rows" on
// the backend bucket validator).
pub(in crate::snapshots) const SELECTOR_CONTEXT_ALLOWED: &[&str] = &[
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
    "attribution_mcp_tool",
];

// Closed owned-field inventory for optional scan overlap admission.
crate::heap_layout_bound::fields!(BucketRowAccumulator; selector_context, selector_sources, usage, reasoning_effort);
crate::durable_tail_codec::durable_struct!(BucketRowAccumulator {
    U selector_context: BTreeMap<String, String>,
    U selector_sources: BTreeMap<String, String>,
    N usage: UsageTotals,
    U reasoning_effort: Option<String>,
});
crate::heap_layout_bound::fields!(RowKey; model, selector_hash, reasoning_effort, auth_mode, billing_channel, billing_provider, gateway_provider, model_provider, subscription_product);
crate::durable_tail_codec::durable_struct!(key RowKey {
    U model: String,
    // "base" or a 16-hex prefix of SHA-256 over `selector_context`, which
    // the upload carries (U): not a 32-byte digest, so not H.
    U selector_hash: String,
    U reasoning_effort: Option<String>,
    U auth_mode: Option<String>,
    U billing_channel: Option<String>,
    U billing_provider: Option<String>,
    U gateway_provider: Option<String>,
    U model_provider: Option<String>,
    U subscription_product: Option<String>,
});
crate::heap_layout_bound::fields!(ActivityCallId; id);
crate::durable_tail_codec::durable_struct!(key ActivityCallId { L id: String });
crate::heap_layout_bound::fields!(ActivityCallTool; name);
crate::durable_tail_codec::durable_struct!(ActivityCallTool { U name: String });
crate::heap_layout_bound::fields!(SelectorCapture; context, sources);
// The retired Claude attribution capture put raw skill, plugin,
// MCP and subagent names into `context`; no source emits them now, but the
// shape below is bound into the pinned allowlist digest, so it stays. A context
// holding any attribution key is class `E`: the record is refused (counted as
// `not_persisted{SelectorCapture.context.attribution}`) and the entry reads
// Full after a restart, so raw names never reach the store. Any other
// context is `U`. Hand-written for that one conditional refusal; the shape
// names both rules, so the allowlist binds them.
impl crate::durable_tail_codec::Durable for SelectorCapture {
    fn put(
        &self,
        e: &mut crate::durable_tail_codec::Enc,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        let Self { context, sources } = self;
        if context
            .keys()
            .any(|key| CLAUDE_ATTRIBUTION_SELECTOR_KEYS.contains(&key.as_str()))
        {
            return Err(crate::durable_tail_codec::Refuse::NonEmpty(
                "SelectorCapture.context.attribution",
            ));
        }
        context.put(e)?;
        sources.put(e)
    }
    fn take(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<Self, crate::durable_tail_codec::Corrupt> {
        type Map = BTreeMap<String, String>;
        Ok(Self {
            context: <Map as crate::durable_tail_codec::Durable>::take(d)?,
            sources: <Map as crate::durable_tail_codec::Durable>::take(d)?,
        })
    }
    fn verify(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        type Map = BTreeMap<String, String>;
        <Map as crate::durable_tail_codec::Durable>::verify(d)?;
        <Map as crate::durable_tail_codec::Durable>::verify(d)
    }
    fn shape(s: &mut crate::durable_tail_codec::Shape) {
        type Map = BTreeMap<String, String>;
        if s.enter("SelectorCapture") {
            s.push("U context");
            <Map as crate::durable_tail_codec::Durable>::shape(s);
            s.push("E context.attribution");
            for key in CLAUDE_ATTRIBUTION_SELECTOR_KEYS {
                s.push(key);
            }
            s.push("U sources");
            <Map as crate::durable_tail_codec::Durable>::shape(s);
            s.leave();
        }
    }
}
crate::heap_layout_bound::fields!(SnapshotAccumulator; source, cache_configuration_witness, cache_task_complete_at, cache_pending_idle, cache_active_turns, context_curve_enabled, source_session_id, account_identifier_hash, title, title_source, first_prompt_title, first_prompt_material, provider_skills, started_at, ended_at, last_activity_at, workspace_hash, workspace_path, repository_binding, latest_model, latest_reasoning_effort, latest_turn_id, codex_turn_traces, codex_observed_priority_turns, codex_priority_witnesses_uncapped, codex_tier_replay, codex_counting, current_selector, session_cumulative_usage, codex_session_meta_seen, codex_record_seen, codex_creator_header_id, codex_creator_evidence, codex_creator_evidence_conflicted, claude_desktop_identity, claude_desktop_spawn_lineage, claude_owned_session_id_observed, claude_owned_session_id_conflicted, codex_ownership_boundary, codex_legacy_trigger_seen, codex_legacy_bootstrap_valid, codex_sidecar_created_thread, codex_path_sidecar_candidates, codex_resolved_path_identity, codex_sidecar_identity_ambiguous, codex_sidecar_parent, codex_sidecar_child_created_at_nanos, codex_bind_seed_len, codex_sidecar_projected_next_ordinal, codex_parent_session_ref, codex_native_created_thread_valid, codex_created_thread_native_only, codex_native_created_thread_header_nanos, codex_native_created_thread_last_nanos, codex_native_created_thread_task_turn_id, codex_native_created_thread_first_turn_bound, codex_ordinal_expected, codex_ordinal_sequence_valid, codex_owned_record_seen, codex_is_fork, codex_inherited_usage_records_skipped, codex_duplicate_usage_records_skipped, codex_cumulative_reset_count, codex_context_curve_candidates, codex_context_curve_boundaries, codex_context_curve_exact_supported, codex_last_usage_event_identity, codex_legacy_bootstrap_buffer, accepted_usage_totals, usage_buckets, origin, codex_root_session_ref, codex_spawn_depth, codex_agent_label, activity_tool_counts, activity_call_tools, activity_mcp_tool_counts, activity_mcp_tool_usage_counts, activity_mcp_call_ids, activity_capability_buckets, seen_claude_capability_tool_uses, activity_skills, skill_detector_incomplete, activity_changed_file_hashes, activity_patch_operations, activity_lines_added, activity_lines_deleted, activity_web_searches, activity_mcp_calls, activity_subagent_spawns, artifacts, artifacts_enabled, latency_duration_ms_sum, latency_duration_ms_count, latency_ttft_ms_sum, latency_ttft_ms_count, latency_duration_ms_max, latency_ttft_ms_max, claude_responses, claude_response_sequence, claude_response_record_count, claude_usage_request_ids, claude_usage_occurrences, claude_request_identity_capture, claude_org_markers, cache_observations, cache_requests, cache_requests_complete, claude_context_curve_identity_complete, claude_context_curve_request_index_complete, claude_context_curve_owned_start_proven, claude_file_birth, claude_fork_parent, claude_money, tool_usage_counts, tool_usage_truncated, seen_pi_usage_keys, dropped_usage_record_count, claude_last_user_ts, claude_line_clocks, peak_context_fill_tokens, first_turn_context_tokens, last_turn_context_tokens, first_turn_context_window_tokens, peak_context_fill_window_tokens, last_turn_context_window_tokens, compaction_count, compaction_timestamps, codex_compaction_sizes, local_context_points, claude_compaction_observations, claude_compaction_link_tip, session_start, codex_dictionary_slots, codex_sidecar_binding);
crate::heap_layout_bound::fields!(UsageBucketState; rows, first_activity_at, last_activity_at);
crate::durable_tail_codec::durable_struct!(UsageBucketState {
    D rows: BTreeMap<RowKey, BucketRowAccumulator>,
    N first_activity_at: Option<String>,
    N last_activity_at: Option<String>,
});
