//! The snapshot accumulator: its methods, the usage row key and selector
//! capture, the row builders, and their layout rows.

use crate::snapshots::*;

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
    pub(in crate::snapshots) fn new(source: SnapshotSource) -> Self {
        Self {
            source,
            cache_configuration_witness: None,
            cache_task_complete_at: None,
            cache_pending_idle: None,
            cache_active_turns: BTreeSet::new(),
            context_curve_enabled: false,
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
            repository_binding: None,
            latest_model: None,
            latest_reasoning_effort: None,
            latest_turn_id: None,
            codex_turn_traces: None,
            codex_observed_priority_turns: None,
            codex_priority_witnesses_uncapped: false,
            codex_tier_replay: None,
            codex_counting: None,
            current_selector: SelectorCapture::default(),
            session_cumulative_usage: None,
            codex_session_meta_seen: false,
            codex_record_seen: false,
            codex_creator_header_id: None,
            codex_creator_evidence: None,
            codex_creator_evidence_conflicted: false,
            claude_desktop_identity: None,
            claude_desktop_spawn_lineage: None,
            claude_owned_session_id_observed: false,
            claude_owned_session_id_conflicted: false,
            codex_ownership_boundary: CodexOwnershipBoundary::Undetermined,
            codex_legacy_trigger_seen: false,
            codex_legacy_bootstrap_valid: true,
            codex_sidecar_created_thread: false,
            codex_path_sidecar_candidates: Vec::new(),
            codex_resolved_path_identity: None,
            codex_sidecar_identity_ambiguous: false,
            codex_sidecar_parent: None,
            codex_sidecar_child_created_at_nanos: None,
            codex_bind_seed_len: None,
            codex_sidecar_projected_next_ordinal: None,
            codex_parent_session_ref: None,
            codex_native_created_thread_valid: true,
            codex_created_thread_native_only: false,
            codex_native_created_thread_header_nanos: None,
            codex_native_created_thread_last_nanos: None,
            codex_native_created_thread_task_turn_id: None,
            codex_native_created_thread_first_turn_bound: false,
            codex_ordinal_expected: None,
            codex_ordinal_sequence_valid: true,
            codex_owned_record_seen: false,
            codex_is_fork: false,
            codex_inherited_usage_records_skipped: 0,
            codex_duplicate_usage_records_skipped: 0,
            codex_cumulative_reset_count: 0,
            codex_context_curve_candidates: crate::owned_heap::OwnedVec::new(),
            codex_context_curve_boundaries: crate::owned_heap::OwnedVec::new(),
            codex_context_curve_exact_supported: true,
            codex_last_usage_event_identity: None,
            codex_legacy_bootstrap_buffer: Vec::new(),
            accepted_usage_totals: UsageTotals::default(),
            usage_buckets: BTreeMap::new(),
            origin: SnapshotOrigin::default(),
            codex_root_session_ref: None,
            codex_spawn_depth: None,
            codex_agent_label: None,
            activity_tool_counts: BTreeMap::new(),
            activity_call_tools: BTreeMap::new(),
            activity_mcp_tool_counts: BTreeMap::new(),
            activity_mcp_tool_usage_counts: BTreeMap::new(),
            activity_mcp_call_ids: BTreeMap::new(),
            activity_capability_buckets: BTreeMap::new(),
            seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap::new(),
            activity_skills: BTreeSet::new(),
            skill_detector_incomplete: false,
            activity_changed_file_hashes: BTreeSet::new(),
            activity_patch_operations: 0,
            activity_lines_added: 0,
            activity_lines_deleted: 0,
            activity_web_searches: 0,
            activity_mcp_calls: 0,
            activity_subagent_spawns: 0,
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
            claude_responses: ClaudeResponseBook::default(),
            claude_response_sequence: 0,
            claude_response_record_count: 0,
            claude_usage_request_ids: BTreeSet::new(),
            claude_usage_occurrences: BTreeMap::new(),
            // Preserve parser fixtures' capture default; released scans capture Claude only.
            claude_request_identity_capture: cfg!(test)
                || claude_request_identity::captures(source),
            claude_org_markers: None,
            cache_observations: None,
            cache_requests: crate::owned_heap::OwnedVec::new(),
            cache_requests_complete: true,
            claude_context_curve_identity_complete: true,
            claude_context_curve_request_index_complete: true,
            claude_context_curve_owned_start_proven: false,
            claude_file_birth: ClaudeFileBirth::default(),
            claude_fork_parent: None,
            claude_money: None,
            tool_usage_counts: BTreeMap::new(),
            tool_usage_truncated: false,
            seen_pi_usage_keys: PiLedger::default(),
            dropped_usage_record_count: 0,
            claude_last_user_ts: None,
            claude_line_clocks: None,
            peak_context_fill_tokens: 0,
            first_turn_context_tokens: None,
            last_turn_context_tokens: None,
            first_turn_context_window_tokens: None,
            peak_context_fill_window_tokens: None,
            last_turn_context_window_tokens: None,
            compaction_count: 0,
            compaction_timestamps: crate::owned_heap::OwnedVec::new(),
            codex_compaction_sizes: CodexCompactionSizes::default(),
            local_context_points: LocalContextPoints::default(),
            claude_compaction_observations: crate::owned_heap::OwnedVec::new(),
            claude_compaction_link_tip: None,
            session_start: Box::default(),
            codex_dictionary_slots: Default::default(),
            codex_sidecar_binding: None,
        }
    }

    pub(in crate::snapshots) fn seed_codex_sidecar_parent(
        &mut self,
        path: &Path,
        file_metadata: &fs::Metadata,
        metadata: &CodexTitleMetadata,
    ) {
        self.codex_sidecar_binding =
            Some(metadata.path_reduction_fingerprint(path)).filter(|binding| !binding.is_empty());
        self.codex_bind_seed_len = Some(file_metadata.len());
        let identities = codex_session_id_candidates_from_path(path);
        if identities.is_empty() {
            // A provider rollout whose identity cannot be resolved while the
            // trusted state contains created-thread suspects cannot safely be
            // treated as an ordinary file.
            self.codex_sidecar_identity_ambiguous = !metadata.state_created_threads.is_empty()
                || metadata.created_thread_census_incomplete_for(path);
            return;
        }
        self.codex_path_sidecar_candidates = identities
            .into_iter()
            .map(|identity| {
                let (thread, rollout_extent) =
                    metadata.thread_extent_for_path(identity.as_str(), path);
                let parent = metadata
                    .family_position(identity.as_str())
                    .map(|(parent, _, _)| parent);
                let created_thread = metadata.state_created_threads.contains(identity.as_str());
                // A created thread without a trusted parent can be admitted only
                // from its own file proof. Its creation time is usable solely when
                // no lineage evidence exists at all and the state row positively
                // locates this whole rollout (path plus thread-history extent).
                // Otherwise withhold it, so no native creation witness can start.
                let parentless_creation_bound = created_thread
                    && parent.is_none()
                    && !metadata.spawn_parents.contains_key(identity.as_str())
                    && !metadata.spawn_parent_conflicts.contains(identity.as_str())
                    && rollout_extent.is_some()
                    && thread
                        .and_then(|thread| thread.rollout_path.as_deref())
                        .is_some_and(|path| !path.is_empty());
                CodexPathSidecarCandidate {
                    recorded_evidence: metadata.has_identity_evidence(identity.as_str()),
                    created_thread,
                    identity_conflict: metadata.identity_conflicts.contains(identity.as_str()),
                    detail_incomplete: metadata.state_census_unscoped_incomplete
                        || metadata.sidecar_census_unscoped_incomplete,
                    rollout_file_matches: codex_sidecar_rollout_file_matches(
                        path,
                        file_metadata,
                        thread,
                        rollout_extent,
                        created_thread,
                    ),
                    child_created_at_nanos: (parent.is_some() || parentless_creation_bound)
                        .then_some(thread)
                        .flatten()
                        .and_then(|thread| thread.created_at.as_deref())
                        .and_then(rfc3339_unix_nanos),
                    parent,
                    projected_next_ordinal: rollout_extent.map(|extent| extent.next_ordinal),
                    identity,
                }
            })
            .collect();

        if metadata.created_thread_census_incomplete_for(path) {
            self.codex_sidecar_identity_ambiguous = true;
            return;
        }
        if self.codex_path_sidecar_candidates.len() == 1 {
            self.bind_codex_path_sidecar_candidate(0);
            return;
        }
        let supported = self
            .codex_path_sidecar_candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.recorded_evidence.then_some(index))
            .collect::<Vec<_>>();
        if supported.len() == 1 {
            self.bind_codex_path_sidecar_candidate(supported[0]);
        } else if supported.len() > 1
            && supported.iter().any(|index| {
                let candidate = &self.codex_path_sidecar_candidates[*index];
                candidate.created_thread || candidate.identity_conflict
            })
        {
            self.codex_sidecar_identity_ambiguous = true;
        }
    }

    fn bind_codex_path_sidecar_candidate(&mut self, index: usize) {
        let candidate = self.codex_path_sidecar_candidates[index].clone();
        self.codex_resolved_path_identity = Some(candidate.identity.clone());
        // Retain a successfully loaded classification even when an optional
        // title/detail/projection census is unhealthy. Those incomplete facts
        // make a created candidate ambiguous, but they do not reclassify an
        // unrelated ordinary rollout. Only failure of the classification
        // query itself has genuinely source-wide scope.
        self.codex_sidecar_created_thread = candidate.created_thread;
        self.codex_sidecar_identity_ambiguous = candidate.identity_conflict
            || (candidate.created_thread && candidate.detail_incomplete);
        if self.codex_sidecar_identity_ambiguous {
            return;
        }
        // Bind the state-row declaration before validating the optional
        // lineage/file cross-checks. A state-declared created thread whose
        // sidecar conflicts with the opened rollout is still a created thread
        // for admission purposes and must fail closed, never fall through to
        // an ordinary ownership branch.
        if !candidate.rollout_file_matches {
            return;
        }
        let Some(parent) = candidate.parent else {
            if candidate.created_thread {
                // Parentless candidate: the seed withheld the creation time unless
                // lineage is provably absent and the row locates this whole file.
                self.codex_sidecar_child_created_at_nanos = candidate.child_created_at_nanos;
                self.codex_sidecar_projected_next_ordinal = candidate.projected_next_ordinal;
            }
            return;
        };
        self.codex_sidecar_child_created_at_nanos = candidate.child_created_at_nanos;
        self.codex_sidecar_projected_next_ordinal = candidate.projected_next_ordinal;
        self.codex_sidecar_parent = Some((candidate.identity, parent));
    }

    pub(in crate::snapshots) fn resolve_codex_path_sidecar_from_header(&mut self, meta: &Value) {
        if self.codex_resolved_path_identity.is_some()
            || self.codex_sidecar_identity_ambiguous
            || self.codex_path_sidecar_candidates.len() < 2
        {
            return;
        }
        let header_id = resolve_codex_identity_option(codex_identity_at(meta, &["id"]));
        let header_session_id =
            resolve_codex_identity_option(codex_identity_at(meta, &["session_id"]));
        let header_identity = match (header_id, header_session_id) {
            (Some(id), Some(session_id))
                if id == session_id || codex_session_id_is_native_parent(meta, &session_id) =>
            {
                Some(id)
            }
            (Some(id), None) | (None, Some(id)) => Some(id),
            _ => None,
        };
        let header_match = header_identity.as_deref().and_then(|identity| {
            self.codex_path_sidecar_candidates
                .iter()
                .position(|candidate| candidate.identity == identity)
        });
        let recorded = self
            .codex_path_sidecar_candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.recorded_evidence.then_some(index))
            .collect::<Vec<_>>();
        let created_or_conflicted_evidence = recorded.iter().any(|index| {
            let candidate = &self.codex_path_sidecar_candidates[*index];
            candidate.created_thread || candidate.identity_conflict
        });
        if created_or_conflicted_evidence && recorded.len() != 1 {
            self.codex_sidecar_identity_ambiguous = true;
            return;
        }
        if let Some(index) = header_match.or_else(|| (recorded.len() == 1).then(|| recorded[0])) {
            self.bind_codex_path_sidecar_candidate(index);
        } else if created_or_conflicted_evidence {
            self.codex_sidecar_identity_ambiguous = true;
        }
    }

    pub(in crate::snapshots) fn configure_codex_ownership(&mut self, value: &Value) {
        let Some(meta) = codex_session_meta_payload(value) else {
            return;
        };
        if self.codex_ownership_boundary != CodexOwnershipBoundary::Undetermined {
            return;
        }
        self.resolve_codex_path_sidecar_from_header(meta);

        let thread_source = string_at(meta, &["thread_source"]);
        let source_subagent = meta
            .get("source")
            .and_then(Value::as_object)
            .is_some_and(|source| source.contains_key("subagent"));
        let is_subagent = thread_source.as_deref() == Some("subagent") || source_subagent;
        // Capability negotiation controls only whether a context-curve payload
        // is emitted. Ownership attribution is an integrity boundary and must
        // never become weaker when that optional payload is unavailable.
        let rollout_declares_created_thread =
            thread_source.as_deref() == Some("agent_created_thread");
        let state_declares_created_thread = self.codex_sidecar_created_thread;
        let is_created_thread = rollout_declares_created_thread || state_declares_created_thread;
        let forked_from_id =
            resolve_codex_identity_option(codex_identity_at(meta, &["forked_from_id"]));
        self.codex_parent_session_ref = forked_from_id.clone();
        let has_history_base = meta.get("history_base").is_some_and(|base| !base.is_null());
        let exact_start = u64_at(meta, &["subagent_history_start_ordinal"]);
        self.codex_is_fork = is_created_thread
            || forked_from_id.is_some()
            || has_history_base
            || exact_start.is_some();

        if self.codex_sidecar_identity_ambiguous {
            self.codex_is_fork = true;
            self.codex_created_thread_native_only = true;
            self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
            return;
        }

        if is_created_thread {
            // Every provider-created thread has exactly one admission path:
            // the complete native creation witness below. In particular,
            // file-controlled pagination markers can never authorize this shape.
            self.codex_created_thread_native_only = true;
            let source_session_id = resolve_codex_identity_option(
                codex_identity_at(meta, &["id"])
                    .or_else(|| codex_identity_at(meta, &["session_id"])),
            );
            let trusted_parent = self
                .codex_sidecar_parent
                .as_ref()
                .filter(|(child, _)| {
                    source_session_id
                        .as_deref()
                        .is_some_and(|session_id| session_id == child)
                })
                .map(|(_, parent)| parent.clone());
            self.codex_parent_session_ref = trusted_parent.clone();
            // The state row is an independent trusted classification source.
            // If the rollout omits or contradicts that declaration, the
            // disagreement is itself damage/tampering evidence. Do not let a
            // file-controlled marker select an ordinary compatibility branch.
            if state_declares_created_thread && !rollout_declares_created_thread {
                self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
                return;
            }
            if trusted_parent
                .as_ref()
                .zip(forked_from_id.as_ref())
                .is_some_and(|(sidecar_parent, transcript_parent)| {
                    sidecar_parent != transcript_parent
                })
            {
                self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
                return;
            }
            // Without a trusted parent, a created thread is admitted only from its
            // own file proof: a state-declared row bound to this file, no lineage
            // in the header, and the UUID identity of the path, the first physical
            // record and the header all agreeing. A `history_base` can name another
            // session's file, so it is lineage evidence too. The stream conjuncts
            // follow in `validate_parentless_created_thread_record`.
            let parentless = trusted_parent.is_none()
                && self.codex_sidecar_parent.is_none()
                && state_declares_created_thread
                && forked_from_id.is_none()
                && !has_history_base
                && codex_header_declares_no_parent(meta)
                && source_session_id
                    .as_deref()
                    .is_some_and(codex_identity_is_uuid_shaped)
                && self.codex_creator_header_id == source_session_id
                && self.codex_resolved_path_identity == source_session_id;
            if let Some(header_nanos) = (trusted_parent.is_some() || parentless)
                .then(|| {
                    codex_native_created_thread_header(
                        value,
                        source_session_id.as_deref(),
                        self.codex_sidecar_child_created_at_nanos,
                    )
                })
                .flatten()
            {
                self.codex_ordinal_expected = Some(0);
                self.codex_native_created_thread_header_nanos = Some(header_nanos);
                self.codex_native_created_thread_last_nanos = Some(header_nanos);
                self.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
                return;
            }
            // Missing or malformed native evidence fails closed.
            self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
            return;
        }

        self.codex_ownership_boundary = if let Some(start) = exact_start {
            self.codex_ordinal_expected = Some(0);
            CodexOwnershipBoundary::Ordinal { start }
        } else if has_history_base {
            // Paginated forks keep inherited history behind an external
            // history_base reference. Physical records in this file are local.
            // Only a first physical own header may start the optional creator
            // sequence. Other AllLocal arms leave this cursor unset.
            if self.codex_creator_header_id.is_some()
                && codex_paginated_fork_creation_header(value, meta)
            {
                self.codex_ordinal_expected = u64_at(value, &["ordinal"]);
            }
            CodexOwnershipBoundary::AllLocal
        } else if is_subagent && forked_from_id.is_some() {
            CodexOwnershipBoundary::AwaitingLegacyTrigger
        } else {
            CodexOwnershipBoundary::AllLocal
        };
    }

    pub(in crate::snapshots) fn codex_record_is_owned(&mut self, value: &Value) -> bool {
        match self.codex_ownership_boundary {
            CodexOwnershipBoundary::Undetermined => {
                // A reordered or partially-written file may expose usage
                // before its authoritative session header. Treating that
                // prefix as local would defeat fork isolation.
                false
            }
            CodexOwnershipBoundary::AllLocal => {
                // Validate only the optional creation witness. Usage retains its
                // existing AllLocal semantics even if this sequence is broken.
                if self.codex_ordinal_expected.is_some() {
                    let ordinal = u64_at(value, &["ordinal"]);
                    if ordinal.is_none() || ordinal != self.codex_ordinal_expected {
                        self.codex_ordinal_sequence_valid = false;
                    }
                    self.codex_ordinal_expected = ordinal.and_then(|at| at.checked_add(1));
                }
                self.codex_owned_record_seen = true;
                true
            }
            CodexOwnershipBoundary::AwaitingLegacyTrigger => {
                if codex_legacy_trigger_turn(value) {
                    self.codex_legacy_trigger_seen = true;
                    self.codex_ownership_boundary = CodexOwnershipBoundary::AllLocal;
                    self.codex_owned_record_seen = true;
                    true
                } else {
                    self.note_legacy_bootstrap_candidate(value);
                    self.note_inherited_codex_record(value);
                    false
                }
            }
            CodexOwnershipBoundary::AwaitingParentPrefix => false,
            CodexOwnershipBoundary::NativeCreatedThread => {
                self.validate_native_created_thread_record(value);
                self.codex_owned_record_seen = true;
                true
            }
            CodexOwnershipBoundary::Ordinal { start } => {
                let Some(ordinal) = u64_at(value, &["ordinal"]) else {
                    self.codex_ordinal_sequence_valid = false;
                    return false;
                };
                if self.codex_ordinal_expected != Some(ordinal) {
                    self.codex_ordinal_sequence_valid = false;
                }
                self.codex_ordinal_expected = ordinal.checked_add(1);
                if ordinal < start {
                    self.note_inherited_codex_record(value);
                    false
                } else {
                    self.codex_owned_record_seen = true;
                    true
                }
            }
            CodexOwnershipBoundary::AmbiguousFork => {
                self.note_inherited_codex_record(value);
                false
            }
        }
    }

    fn validate_native_created_thread_record(&mut self, value: &Value) {
        let expected_ordinal = self.codex_ordinal_expected;
        let ordinal = u64_at(value, &["ordinal"]);
        if ordinal != expected_ordinal {
            self.codex_ordinal_sequence_valid = false;
        }
        self.codex_ordinal_expected = ordinal.and_then(|value| value.checked_add(1));

        let timestamp_nanos = string_at(value, &["timestamp"])
            .as_deref()
            .and_then(rfc3339_unix_nanos);
        match (
            timestamp_nanos,
            self.codex_native_created_thread_header_nanos,
            self.codex_native_created_thread_last_nanos,
        ) {
            (Some(timestamp), Some(header), Some(previous))
                if timestamp >= header && timestamp >= previous =>
            {
                self.codex_native_created_thread_last_nanos = Some(timestamp);
            }
            _ => self.codex_native_created_thread_valid = false,
        }

        match ordinal {
            Some(0) => {}
            Some(1) => {
                let turn_id = string_at(value, &["payload", "turn_id"]);
                let trace_id = string_at(value, &["payload", "trace_id"]);
                let hex32 = |value: &str| {
                    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                };
                // Codex omits `trace_id` on most parentless created threads. Their
                // anti-copy proof is the start bound, the UUID turn binding and the
                // first-request equality, so only that path accepts a missing key.
                // Any present value, including null, empty or non-string, must be
                // well formed.
                let trace_id_valid = if self.codex_parentless_created_thread() {
                    match value
                        .get("payload")
                        .and_then(|payload| payload.get("trace_id"))
                    {
                        None => true,
                        Some(raw) => raw.as_str().is_some_and(hex32),
                    }
                } else {
                    trace_id.as_deref().is_some_and(hex32)
                };
                let valid = codex_is_task_started(value)
                    && turn_id
                        .as_deref()
                        .is_some_and(codex_identity_is_uuid_shaped)
                    && trace_id_valid
                    && self.codex_task_started_after_creation(value, timestamp_nanos);
                if valid {
                    self.codex_native_created_thread_task_turn_id = turn_id;
                } else {
                    self.codex_native_created_thread_valid = false;
                }
            }
            Some(_) if string_eq_at(value, &["type"], "turn_context") => {
                if !self.codex_native_created_thread_first_turn_bound {
                    self.codex_native_created_thread_first_turn_bound =
                        string_at(value, &["payload", "turn_id"])
                            == self.codex_native_created_thread_task_turn_id;
                    if !self.codex_native_created_thread_first_turn_bound {
                        self.codex_native_created_thread_valid = false;
                    }
                }
            }
            Some(_) if codex_total_usage(value).is_some() => {
                if !self.codex_native_created_thread_first_turn_bound {
                    self.codex_native_created_thread_valid = false;
                }
            }
            Some(_) | None => {}
        }
        if self.codex_parentless_created_thread() {
            self.validate_parentless_created_thread_record(value, ordinal, timestamp_nanos);
        }
    }

    /// A provider task's own `started_at` second lies between the state row's
    /// creation second and the second the record was written. Copies carry
    /// their original payload time, so this binds a task to this thread.
    fn codex_task_started_after_creation(
        &self,
        value: &Value,
        timestamp_nanos: Option<i128>,
    ) -> bool {
        let started_at = u64_at(value, &["payload", "started_at"]);
        let sidecar_second = self
            .codex_sidecar_child_created_at_nanos
            .and_then(|value| u64::try_from(value.div_euclid(1_000_000_000)).ok());
        let record_second =
            timestamp_nanos.and_then(|value| u64::try_from(value.div_euclid(1_000_000_000)).ok());
        started_at
            .zip(sidecar_second.zip(record_second))
            .is_some_and(|(started, (spawned, recorded))| started >= spawned && started <= recorded)
    }

    /// Created thread admitted without a trusted parent. The parented path
    /// always records its trusted parent here while configuring the header.
    pub(in crate::snapshots) fn codex_parentless_created_thread(&self) -> bool {
        self.codex_ownership_boundary == CodexOwnershipBoundary::NativeCreatedThread
            && self.codex_parent_session_ref.is_none()
    }

    /// Extra stream conjuncts for a parentless created thread, which has no
    /// parent ledger to exclude copied history. Any failure holds the file.
    fn validate_parentless_created_thread_record(
        &mut self,
        value: &Value,
        ordinal: Option<u64>,
        timestamp_nanos: Option<i128>,
    ) {
        // Only the line-0 header may describe the session. A later header is a
        // copy or a re-emission and cannot be attributed safely.
        if codex_session_meta_payload(value).is_some() && self.codex_owned_record_seen {
            self.codex_native_created_thread_valid = false;
        }
        // Every later task must start after this thread was created, and only
        // once the first task has bound its turn. The cache tracker opens a turn
        // for any `task_started` payload, so every envelope is checked here.
        if string_eq_at(value, &["payload", "type"], "task_started") && ordinal != Some(1) {
            let turn_id = string_at(value, &["payload", "turn_id"]);
            if codex_is_task_started(value)
                && self.codex_native_created_thread_first_turn_bound
                && turn_id.is_some()
                && self.codex_task_started_after_creation(value, timestamp_nanos)
            {
                self.codex_native_created_thread_task_turn_id = turn_id;
            } else {
                self.codex_native_created_thread_valid = false;
            }
        }
        // Turn contexts and usage must belong to a turn this file opened.
        if string_eq_at(value, &["type"], "turn_context") {
            let turn_id = string_at(value, &["payload", "turn_id"]);
            if !self.codex_parentless_turn_opened(turn_id.as_deref()) {
                self.codex_native_created_thread_valid = false;
            }
        }
        let Some(total) = codex_total_usage(value) else {
            return;
        };
        // Same precedence as `apply_codex_owned_line`, which runs after this
        // check: a turn named by the record wins over the running turn.
        let usage_turn_id = string_at(value, &["turn_context", "payload", "turn_id"])
            .or_else(|| string_at(value, &["payload", "turn_id"]))
            .or_else(|| self.latest_turn_id.clone());
        if !self.codex_parentless_turn_opened(usage_turn_id.as_deref()) {
            self.codex_native_created_thread_valid = false;
        }
        // Before any usage is counted, the first request's cumulative total must
        // equal that request: nothing was accumulated before it in this thread.
        // All-zero pairs are context estimates; `request_count` is a parser
        // default, not provider data, so only token fields are compared.
        if codex_usage_token_fields(&self.accepted_usage_totals) == [0; 5] {
            let total = codex_usage_token_fields(&total);
            let last = codex_last_usage(value).map(|last| codex_usage_token_fields(&last));
            if (total != [0; 5] || last.is_some_and(|last| last != [0; 5])) && last != Some(total) {
                self.codex_native_created_thread_valid = false;
            }
        }
    }

    /// Finalization conjuncts for a parentless created thread: the thread-history
    /// projection proved this file is the whole thread, every physical record was
    /// read under one header, a first request was actually checked, and no record
    /// supplied lineage the sidecar never trusted.
    fn codex_parentless_proof_complete(&self) -> bool {
        self.codex_sidecar_projected_next_ordinal.is_some()
            && !self.codex_creator_evidence_conflicted
            && self.origin.parent_session_ref.is_none()
            && self.origin.source_subagent != Some(true)
            && codex_usage_token_fields(&self.accepted_usage_totals) != [0; 5]
    }

    fn codex_parentless_turn_opened(&self, turn_id: Option<&str>) -> bool {
        turn_id.is_some_and(|turn_id| {
            self.codex_native_created_thread_task_turn_id.as_deref() == Some(turn_id)
                || self.cache_active_turns.contains(turn_id)
        })
    }

    fn note_inherited_codex_record(&mut self, value: &Value) {
        if let Some(usage) = codex_total_usage(value) {
            if !usage.is_zero() {
                self.codex_inherited_usage_records_skipped =
                    self.codex_inherited_usage_records_skipped.saturating_add(1);
            }
            // The last inherited cumulative is the baseline for legacy records
            // that predate `last_token_usage`. It never enters a usage bucket.
            self.session_cumulative_usage = Some(usage);
        }
    }

    fn note_legacy_bootstrap_candidate(&mut self, value: &Value) {
        const MAX_BOOTSTRAP_RECORDS: usize = 64;
        if codex_total_usage(value).is_some() {
            // A completed response proves this was still a copied parent task.
            self.codex_legacy_bootstrap_buffer.clear();
            self.codex_legacy_bootstrap_valid = true;
            return;
        }
        let task_started = string_eq_at(value, &["payload", "type"], "task_started");
        if task_started {
            self.codex_legacy_bootstrap_buffer.clear();
            self.codex_legacy_bootstrap_valid = true;
        }
        if task_started || !self.codex_legacy_bootstrap_buffer.is_empty() {
            if self.codex_legacy_bootstrap_buffer.len() == MAX_BOOTSTRAP_RECORDS {
                CapCounts::record(self.source.api_slug(), 1, 1);
                self.codex_legacy_bootstrap_buffer.clear();
                self.codex_legacy_bootstrap_valid = false;
                return;
            }
            self.codex_legacy_bootstrap_buffer.push(value.clone());
        }
    }

    pub(in crate::snapshots) fn codex_usage_accounting_complete(&self) -> bool {
        match self.codex_ownership_boundary {
            CodexOwnershipBoundary::Undetermined => false,
            CodexOwnershipBoundary::AllLocal => {
                !self.codex_legacy_trigger_seen || self.codex_legacy_bootstrap_valid
            }
            CodexOwnershipBoundary::Ordinal { start } => {
                self.codex_ordinal_sequence_valid
                    && self.codex_owned_record_seen
                    && self.codex_ordinal_expected.is_some_and(|next| next > start)
            }
            CodexOwnershipBoundary::NativeCreatedThread => {
                self.codex_native_created_thread_valid
                    && self.codex_ordinal_sequence_valid
                    && self.codex_owned_record_seen
                    && self.codex_ordinal_expected.is_some_and(|next| next > 1)
                    && self
                        .codex_sidecar_projected_next_ordinal
                        .map(|expected| self.codex_ordinal_expected == Some(expected))
                        .unwrap_or(true)
                    && self.codex_native_created_thread_task_turn_id.is_some()
                    && self.codex_native_created_thread_first_turn_bound
                    && (self.codex_parent_session_ref.is_some()
                        || self.codex_parentless_proof_complete())
            }
            CodexOwnershipBoundary::AwaitingLegacyTrigger
            | CodexOwnershipBoundary::AwaitingParentPrefix
            | CodexOwnershipBoundary::AmbiguousFork => false,
        }
    }

    /// Merge newly scraped artifacts, deduping and capping at
    /// ``MAX_SESSION_ARTIFACTS``. Encounter order is preserved; ``into_items``
    /// sorts for a deterministic fingerprint.
    pub(in crate::snapshots) fn add_artifacts(&mut self, artifacts: Vec<SessionArtifact>) {
        for artifact in artifacts {
            if self.artifacts.len() >= MAX_SESSION_ARTIFACTS {
                break;
            }
            if !self.artifacts.iter().any(|existing| existing == &artifact) {
                self.artifacts.push(artifact);
            }
        }
    }

    /// Move independently observed session features into the next member before
    /// projection. Keep transient call matching and all usage state per member.
    pub(in crate::snapshots) fn merge_session_features(&mut self, other: &mut Self) -> Option<()> {
        macro_rules! maps {
            ($($field:ident),+ $(,)?) => {$({
                for (key, count) in std::mem::take(&mut other.$field) {
                    let into = self.$field.entry(key).or_default();
                    *into = into.checked_add(count)?;
                }
            })+};
        }
        maps!(
            activity_tool_counts,
            activity_mcp_tool_counts,
            activity_mcp_tool_usage_counts,
            activity_capability_buckets,
            tool_usage_counts
        );
        macro_rules! counts {
            ($($field:ident),+ $(,)?) => {$({
                self.$field = self.$field.checked_add(std::mem::take(&mut other.$field))?;
            })+};
        }
        counts!(
            activity_patch_operations,
            activity_lines_added,
            activity_lines_deleted,
            activity_web_searches,
            activity_mcp_calls,
            activity_subagent_spawns
        );
        self.activity_changed_file_hashes
            .extend(std::mem::take(&mut other.activity_changed_file_hashes));
        self.activity_skills
            .extend(std::mem::take(&mut other.activity_skills));
        self.provider_skills
            .extend(std::mem::take(&mut other.provider_skills));
        self.skill_detector_incomplete |= other.skill_detector_incomplete;
        self.tool_usage_truncated |= other.tool_usage_truncated;
        self.add_artifacts(std::mem::take(&mut other.artifacts));
        Some(())
    }

    pub(in crate::snapshots) fn note_activity_tool(&mut self, name: &str) {
        let Some(name) = bounded_activity_label(name) else {
            return;
        };
        // `exec` is Codex Desktop's transport wrapper. Its nested `tools.*`
        // calls are counted separately so the UI reports actions, not protocol.
        if name == "exec" {
            return;
        }
        self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::Tool, &name);
        *self.activity_tool_counts.entry(name).or_default() += 1;
    }

    pub(in crate::snapshots) fn reclassify_activity_call_as_mcp(&mut self, call_id: &str) {
        let Some(ActivityCallTool { name }) = self.activity_call_tools.remove(call_id) else {
            return;
        };
        let Some(count) = self.activity_tool_counts.get_mut(&name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.activity_tool_counts.remove(&name);
        }
    }

    pub(in crate::snapshots) fn note_activity_mcp_tool(&mut self, server: &str, tool: &str) {
        if let Some(name) = bounded_activity_label(&format!("{server}.{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpActivity, &name);
            *self.activity_mcp_tool_counts.entry(name).or_default() += 1;
        }
        if let Some(name) = bounded_tool_usage_name(&format!("mcp__{server}__{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpUsage, &name);
            *self.activity_mcp_tool_usage_counts.entry(name).or_default() += 1;
        }
    }

    /// A Codex name count's stable Tail slot, first seen here.
    fn note_codex_name_slot(&mut self, map: codex_dictionary_slots::CodexCountMap, name: &str) {
        if self.source == SnapshotSource::Codex {
            self.codex_dictionary_slots
                .name_counts
                .note(&(map, name.to_owned()));
        }
    }

    pub(in crate::snapshots) fn note_activity_tools(&mut self, material: &str) {
        for name in nested_unified_exec_tools(material) {
            self.note_activity_tool(&name);
        }
    }

    /// SKILL.md references in tool input (Codex arguments, Claude Read/Bash).
    /// Keeps one name past the wire cap so the backend still sees truncation.
    /// The first spelling wins: `Foo/SKILL.md` and `foo/SKILL.md` are one
    /// skill, and the backend keys uploaded names by their exact bytes.
    pub(in crate::snapshots) fn note_activity_skills(&mut self, material: &str) {
        let skills = &mut self.activity_skills;
        let named_all = for_each_skill_md_reference(material, |name| {
            if skills.len() <= MAX_ACTIVITY_SKILLS
                && !skills.iter().any(|seen| seen.eq_ignore_ascii_case(&name))
            {
                skills.insert(name);
            }
        });
        self.skill_detector_incomplete |= !named_all;
    }

    pub(in crate::snapshots) fn note_capability_call(
        &mut self,
        timestamp: Option<&str>,
        capability_id: &str,
        raw_origin: &str,
    ) {
        let Some((bucket_start, _)) = timestamp.and_then(activity_bucket_from_timestamp) else {
            return;
        };
        *self
            .activity_capability_buckets
            .entry((
                bucket_start,
                capability_id.to_string(),
                raw_origin.to_string(),
            ))
            .or_default() += 1;
    }

    pub(in crate::snapshots) fn activity_summary(&self) -> Option<SnapshotActivitySummary> {
        let capability_buckets = self
            .activity_capability_buckets
            .iter()
            .map(|((bucket_start, capability_id, raw_origin), call_count)| {
                SnapshotCapabilityBucket {
                    bucket_start: bucket_start.clone(),
                    capability_id: capability_id.clone(),
                    raw_origin: raw_origin.clone(),
                    call_count: *call_count,
                }
            })
            .collect::<Vec<_>>();
        let mut capability_totals: BTreeMap<(String, String), u64> = BTreeMap::new();
        for bucket in &capability_buckets {
            *capability_totals
                .entry((bucket.capability_id.clone(), bucket.raw_origin.clone()))
                .or_default() += bucket.call_count;
        }
        let capability_counts = capability_totals
            .into_iter()
            .map(
                |((capability_id, raw_origin), count)| SnapshotCapabilityCount {
                    capability_id,
                    raw_origin,
                    count,
                },
            )
            .collect::<Vec<_>>();
        let codex_tool_calls = self
            .activity_tool_counts
            .values()
            .copied()
            .sum::<u64>()
            .saturating_add(self.activity_mcp_calls);
        // Codex already has a complete local tool-action classifier. Claude's
        // new capability classifier is intentionally narrower, so do not
        // present its allowlisted subset as the session's total tool/MCP use.
        let tool_calls = if self.source == SnapshotSource::Codex {
            codex_tool_calls
        } else {
            0
        };
        // v2: v1's capability counts plus a skill detector that named every
        // SKILL.md reference it saw. Only v2 may later back "no skill used".
        let capability_collection_version = matches!(
            self.source,
            SnapshotSource::Codex | SnapshotSource::ClaudeCode
        )
        .then(|| {
            if self.skill_detector_incomplete {
                "agent_capability_usage:v1"
            } else {
                "agent_capability_usage:v2"
            }
            .to_string()
        });
        let has_activity = capability_collection_version.is_some()
            || tool_calls > 0
            || self.activity_patch_operations > 0
            || self.activity_web_searches > 0
            || self.activity_subagent_spawns > 0
            || !self.activity_skills.is_empty();
        has_activity.then(|| SnapshotActivitySummary {
            capability_collection_version,
            tool_calls,
            shell_commands: self
                .activity_tool_counts
                .get("exec_command")
                .copied()
                .unwrap_or_default(),
            patch_operations: self.activity_patch_operations,
            changed_files: self.activity_changed_file_hashes.len() as u64,
            lines_added: self.activity_lines_added,
            lines_deleted: self.activity_lines_deleted,
            web_searches: self.activity_web_searches,
            mcp_calls: self.activity_mcp_calls,
            subagent_spawns: self.activity_subagent_spawns,
            tool_counts: bounded_activity_counts(&self.activity_tool_counts, 64),
            mcp_tool_counts: bounded_activity_counts(&self.activity_mcp_tool_counts, 32),
            capability_counts,
            capability_buckets,
            // A reference to an invoked skill uploads the invocation's
            // (lowercased) spelling, the one its `skill_id` fact hashes, so
            // backend promotion of these names finds that fact.
            skills: self
                .activity_skills
                .iter()
                .take(MAX_ACTIVITY_SKILLS)
                .map(|skill| {
                    self.provider_skills
                        .get(&skill.to_ascii_lowercase())
                        .unwrap_or(skill)
                        .clone()
                })
                .collect(),
        })
    }

    pub(in crate::snapshots) fn note_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| timestamp_is_before(&timestamp, current))
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| timestamp_is_after(&timestamp, current))
        {
            self.last_activity_at = Some(timestamp);
        }
    }

    /// Retain one Claude usage-bearing record for response-level resolution.
    /// No session-exclusive metric is mutated here; `finalize_claude_responses`
    /// admits exactly one terminal observation after the full file is read.
    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(in crate::snapshots) fn observe_claude_response(
        &mut self,
        value: &Value,
        usage: UsageTotals,
        model: Option<String>,
        selector: SelectorCapture,
        timestamp: Option<String>,
        reasoning_effort: Option<String>,
        computed_effective_input_context: Option<u64>,
    ) {
        let tool_uses = claude_response_tool_uses(value);
        let cache_slot = claude_cache_request_slot(
            value,
            model.clone(),
            reasoning_effort.clone(),
            timestamp.clone(),
        );
        let request_id =
            string_at(value, &["requestId"]).or_else(|| string_at(value, &["request_id"]));
        let key = claude_response_key(value, self.claude_response_sequence);
        self.claude_response_record_count = self.claude_response_record_count.saturating_add(1);
        let selector = self.claude_responses.selectors.intern(selector);
        // The request's own usage records carry entrypoint. Missing or mixed
        // records fail closed; session-first origin is deliberately irrelevant.
        let desktop_request =
            value.get("entrypoint").and_then(Value::as_str) == Some("claude-desktop");
        if let Some(mut existing) = self.claude_responses.get_mut(&key) {
            existing.desktop_request &= desktop_request;
            existing.push(
                usage,
                model,
                selector,
                reasoning_effort,
                request_id,
                timestamp,
                computed_effective_input_context,
                tool_uses,
                cache_slot,
            );
            return;
        }
        let sequence = self.claude_response_sequence;
        self.claude_response_sequence = self.claude_response_sequence.saturating_add(1);
        let mut response = ClaudeResponseObservation::new(
            sequence,
            usage,
            model,
            selector,
            reasoning_effort,
            request_id,
            timestamp,
            self.claude_last_user_ts.clone(),
            computed_effective_input_context,
            tool_uses,
            cache_slot,
        );
        response.desktop_request = desktop_request;
        let inserted = self.claude_responses.insert(key, response);
        if !inserted {
            self.note_dropped_usage();
        }
    }

    /// Resolve every Claude response in transcript order, then admit its final
    /// cumulative usage exactly once. Conflicting provider records are dropped
    /// and make the enclosing file retryable through the existing diagnostics.
    #[cfg(test)]
    pub(in crate::snapshots) fn finalize_claude_responses(&mut self) {
        self.finalize_claude_responses_e2(None);
    }

    pub(in crate::snapshots) fn finalize_claude_responses_e2(
        &mut self,
        money_context: Option<claude_request_money::e2::ReadContext<'_>>,
    ) {
        let (mut responses, selectors) = std::mem::take(&mut self.claude_responses).into_parts();
        responses.sort_by_key(|response| response.sequence);
        // Gate off, the fold keys by hour only: it never reads the selector.
        let base_selector = self.current_selector.clone();
        // Gate on, a family revision 3 keeps on ordinary money gets no fold:
        // its file is read exactly as gate off publishes it (fold-absent).
        let mut money = (money_context
            .as_ref()
            .map_or(true, claude_request_money::e2::file_applies))
        .then(|| {
            claude_request_money::e2::FileFold::new(
                self.claude_file_birth,
                money_context.as_ref(),
                base_selector,
                self.fallback_bucket_timestamp(None),
            )
        });
        crate::local_resource_diagnostics::claude_record_counts(
            self.claude_response_record_count,
            responses
                .iter()
                .map(|response| response.records.len())
                .max()
                .unwrap_or(0),
            CLAUDE_RECORDS_PER_FILE_ALARM,
        );
        let first_sequence = responses.first().map(|response| response.sequence);
        // Resolve the sorted book first: org lines govern from the first
        // response whose provider time is from `ACCOUNT_RULE_FROM`.
        let responses = responses
            .into_iter()
            .map(|response| response.resolve_classified(&selectors))
            .collect::<Vec<_>>();
        if let Some(money) = money.as_mut() {
            let trust_from = responses
                .iter()
                .flatten()
                .find(|response| {
                    claude_request_identity::from_account_rule(
                        response
                            .terminal_timestamp
                            .as_deref()
                            .and_then(rfc3339_unix_seconds),
                    )
                })
                .map(|response| response.sequence);
            money.set_identity(
                self.claude_org_markers.as_deref(),
                self.account_identifier_hash.as_deref(),
                self.source_session_id.as_deref(),
                money_context.as_ref(),
                first_sequence,
                trust_from,
            );
        }
        let mut shared_selectors = BTreeSet::<Arc<SelectorCapture>>::new();
        // The previous resolved response's end when it ended a turn (no tool
        // use); `None` after a tool use or an unresolved response. A response
        // whose prompt follows it starts a turn: the time between is idle.
        let mut turn_end: Option<String> = None;
        for response in responses {
            let mut response = match response {
                Ok(response) => response,
                // With the `e2` gate on, a resolver conflict is counted
                // and disclosed on the body (resolver_conflict_count) and the
                // root publishes; it is not drop residue held for retry. Gate
                // off (dark): unchanged drop residue, still counted.
                Err(ClaudeResolveFailure::Conflict) => {
                    turn_end = None;
                    if let Some(money) = money.as_mut() {
                        money.note_resolver_conflict();
                    }
                    if money.is_none() {
                        self.note_dropped_usage();
                    }
                    continue;
                }
                // An undecodable compact record is loss held for retry, never
                // a resolver conflict.
                Err(ClaudeResolveFailure::Decode) => {
                    turn_end = None;
                    self.note_dropped_usage();
                    continue;
                }
            };
            let at = response
                .terminal_timestamp
                .as_deref()
                .and_then(rfc3339_unix_nanos);
            if !response.cache_slot.request_ref.is_empty() {
                self.cache_requests.push(OwnedRequest {
                    slot: response.cache_slot.clone(),
                    ordering: "sequential".into(),
                    compaction_before: self
                        .claude_compaction_observations
                        .iter()
                        .any(|b| b.response_count_before == response.sequence),
                    configuration_changed: false,
                    configuration_witness: None,
                    idle_seconds: turn_end
                        .as_deref()
                        .zip(response.preceding_user_timestamp.as_deref())
                        .and_then(|(end, prompt)| cache_observations::elapsed_seconds(end, prompt)),
                });
            }
            turn_end = response
                .tool_uses
                .is_empty()
                .then(|| response.terminal_timestamp.clone())
                .flatten();
            let effective_input_context = response
                .computed_effective_input_context
                .unwrap_or_else(|| response.usage.effective_input_context());
            self.claude_file_birth.observe_response_at(
                response.sequence,
                at,
                effective_input_context,
            );
            if !response.selector.context.contains_key("context_bucket") {
                // Stamped only against the model's catalog line: Haiku 5.5's
                // 100K price line or the 200K analysis line of flat 1M-window
                // models. Models without a catalog line carry no bucket.
                if let Some(context_bucket) = response.model.as_deref().and_then(|model| {
                    provider_context_bucket(
                        model,
                        effective_input_context,
                        response.terminal_timestamp.as_deref(),
                    )
                }) {
                    response.selector.insert(
                        "context_bucket",
                        context_bucket.to_string(),
                        "derived_from_effective_input_volume",
                    );
                }
            }
            let has_request_id = response.request_id.is_some();
            if let Some(request_id) = response.request_id.take() {
                let selector = match shared_selectors.get(&response.selector) {
                    Some(shared) => Arc::clone(shared),
                    None => {
                        let shared = Arc::new(response.selector.clone());
                        shared_selectors.insert(Arc::clone(&shared));
                        shared
                    }
                };
                let prior_occurrence = self.claude_usage_occurrences.insert(
                    request_id.clone(),
                    ClaudeTranscriptUsageOccurrence {
                        sequence: response.sequence,
                        telemetry_attached: false,
                        usage: response.usage.clone(),
                        model: response.model.clone(),
                        selector,
                        reasoning_effort: response.reasoning_effort.clone(),
                        timestamp: response.terminal_timestamp.clone(),
                        event_clock_complete: response.event_clock_complete,
                        desktop_request: response.desktop_request,
                        effective_input_context,
                    },
                );
                if self.claude_usage_request_ids.contains(&request_id) || prior_occurrence.is_some()
                {
                    if let Some(money) = money.as_mut() {
                        money.note_ambiguous(&request_id);
                    }
                }
                let request_id_was_new = self.claude_usage_request_ids.insert(request_id);
                // Identity completeness depends on this file's bytes alone (a
                // repeated id here, an id-less response below).
                // Progressive rows for one response were merged by response
                // key above. Reaching this point twice for one provider request
                // id therefore means two distinct responses claim the same
                // request identity; their request index is not trustworthy.
                if !request_id_was_new || prior_occurrence.is_some() {
                    self.claude_context_curve_identity_complete = false;
                }
            } else {
                self.claude_context_curve_identity_complete = false;
                // An id-less response is never a compaction size. Mark the
                // compaction it sits just before or just after for the fold's
                // local counters; the sizes themselves are unchanged.
                // Parse order makes response_count_before non-decreasing,
                // even when marker timestamps repeat or arrive out of order.
                let first = self
                    .claude_compaction_observations
                    .partition_point(|observation| {
                        observation.response_count_before < response.sequence
                    });
                let next = response.sequence.saturating_add(1);
                let end = self
                    .claude_compaction_observations
                    .partition_point(|observation| observation.response_count_before <= next);
                for index in first..end {
                    if let Some(observation) = self
                        .claude_compaction_observations
                        .get_mut(index)
                        .as_deref_mut()
                    {
                        if observation.response_count_before == response.sequence {
                            observation.id_less_after = true;
                        } else {
                            observation.id_less_before = true;
                        }
                    }
                }
            }
            self.note_claude_turn_duration_between(
                response.preceding_user_timestamp.as_deref(),
                response.first_timestamp.as_deref(),
            );
            if effective_input_context > 0 {
                if self.first_turn_context_tokens.is_none() {
                    self.first_turn_context_tokens = Some(effective_input_context);
                }
                self.peak_context_fill_tokens =
                    self.peak_context_fill_tokens.max(effective_input_context);
                self.last_turn_context_tokens = Some(effective_input_context);
            }
            self.session_start.note_claude_response(
                response.sequence,
                &response.usage,
                effective_input_context,
                response.tool_uses.len(),
            );
            for name in response.tool_uses.into_values() {
                self.note_tool_usage(name);
            }
            // One native placement per response; the money fold reuses it.
            let placed = claude_request_money::e2::timed("native.place", || {
                self.place_usage(
                    response.model,
                    &response.usage,
                    response.selector,
                    response.terminal_timestamp.as_deref(),
                    response.reasoning_effort.as_deref(),
                )
            });
            if let Some(money) = money.as_mut() {
                claude_request_money::e2::timed("e2.observe", || {
                    money.observe(
                        response.sequence,
                        has_request_id,
                        &response.usage,
                        at,
                        placed.as_ref(),
                        response.reasoning_effort.as_deref(),
                    )
                });
            }
            if let Some(placed) = placed {
                claude_request_money::e2::timed("native.add", || {
                    self.add_placed_usage(placed, response.usage, response.reasoning_effort)
                });
            }
        }
        if let Some(mut money) = money {
            claude_request_money::e2::timed("e2.finish_native", || {
                money.finish_native(
                    money_context.as_ref(),
                    self.claude_org_markers.as_deref(),
                    self.claude_fork_parent.as_deref(),
                )
            });
            self.claude_money = Some(Box::new(money));
        }
    }

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

    // Production finishes through `into_items_with_repository_identity`.
    #[cfg(test)]
    pub(in crate::snapshots) fn into_items(
        self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Vec<SnapshotItem> {
        self.into_items_with_repository_identity(
            path,
            collected_at,
            source_file_fingerprint,
            attribution_context,
            None,
            false,
        )
    }

    /// The file's first in-file session id, before the wire rule: the parsed
    /// id, else (Codex) the identity bound for this exact file, else the
    /// file stem.
    fn raw_source_session_id(&self, path: &Path) -> Option<String> {
        self.source_session_id
            .clone()
            .or_else(|| {
                (self.source == SnapshotSource::Codex)
                    .then(|| {
                        // Prefer the identity the seeding/header evidence already
                        // bound for this exact file. `codex_session_id_from_path`
                        // is deliberately evidence-free and returns `None` for a
                        // timestamp-shaped name, so without this the ambiguous
                        // grammar would degrade to the raw `rollout-` file stem.
                        self.codex_resolved_path_identity
                            .clone()
                            .or_else(|| codex_session_id_from_path(path))
                    })
                    .flatten()
            })
            .or_else(|| {
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_string())
            })
    }

    /// The `source_session_id` this state's items carry on the wire.
    pub(in crate::snapshots) fn wire_source_session_id(&self, path: &Path) -> Option<String> {
        self.raw_source_session_id(path)
            .map(|id| snapshot_source_session_id(self.source, path, id))
    }

    pub(in crate::snapshots) fn into_items_with_repository_identity(
        mut self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
        measured_repository_identity: Option<crate::context_footprint::RepositoryIdentity>,
        emit_empty_pi_fork: bool,
    ) -> Vec<SnapshotItem> {
        // Defence in depth: the scan already refuses to collect the Workflow
        // journal, but the parse entry points are public, so nothing downstream
        // may mint a `<parentSessionId>_journal` session either.
        if self.source == SnapshotSource::ClaudeCode
            && claude_transcript_excluded_from_snapshots(path)
        {
            return Vec::new();
        }
        // The same session key the head-CAS ledger answers under
        // (`tail_source::load::conflict_owed`).
        let Some(source_session_id) = self.wire_source_session_id(path) else {
            return Vec::new();
        };
        if self.source == SnapshotSource::Codex && !self.codex_usage_accounting_complete() {
            return Vec::new();
        }
        let codex_usage_accounting_proven =
            self.source == SnapshotSource::Codex && self.codex_session_meta_seen;
        let expected_path_id = self
            .codex_resolved_path_identity
            .as_deref()
            .map(str::to_string)
            .or_else(|| codex_session_id_from_path(path));
        let mut session_account_evidence = (self.source == SnapshotSource::Codex
            && !self.codex_creator_evidence_conflicted
            && self.codex_creator_header_id.as_deref() == Some(source_session_id.as_str())
            && expected_path_id.as_deref() == Some(source_session_id.as_str())
            // Native ordinal forks have their own creation-time creator pair.
            // The first physical header/file/time gates prove its origin;
            // the independently validated boundary still owns usage, not identity.
            // AllLocal has a cursor only for the exact external paginated own
            // header; its local sequence and complete acquisition must survive.
            && (!self.codex_is_fork
                || matches!(
                    self.codex_ownership_boundary,
                    CodexOwnershipBoundary::NativeCreatedThread
                        | CodexOwnershipBoundary::Ordinal { .. }
                )
                || (self.codex_ownership_boundary == CodexOwnershipBoundary::AllLocal
                    && self.codex_ordinal_sequence_valid
                    && self.codex_ordinal_expected.is_some())))
        .then(|| self.codex_creator_evidence.clone())
        .flatten()
        .filter(|evidence| {
            creator_time_precedes_start(
                evidence.source_created_at.as_deref(),
                self.started_at.as_deref(),
            )
        });
        if self.source == SnapshotSource::ClaudeCode {
            let mut evidence = self.claude_desktop_identity.clone().unwrap_or_else(|| {
                ClaudeTitleMetadata::default().session_account_evidence(&source_session_id)
            });
            evidence.source_created_at = evidence.source_created_at.take().filter(|created| {
                creator_time_precedes_start(Some(created), self.started_at.as_deref())
            });
            if evidence.source_created_at.is_none()
                && evidence.identity_disposition == Some("complete")
            {
                evidence.identity_disposition = Some("missing");
            }
            // Explicit evaluation is never replaced by omission: otherwise a
            // later missing/conflicting census could inherit an old complete pair.
            session_account_evidence = Some(evidence);
        }
        // A Claude Code subagent transcript (Task tool or Workflow tool) shares
        // its parent's `sessionId`; the wire rule above re-keys it from its PATH
        // to a distinct id so it ingests as its own `isSidechain=true`
        // (ai_agent) session instead of collapsing into -- and overwriting --
        // the human parent. Top-level transcripts are unchanged.
        let claude_subagent = (self.source == SnapshotSource::ClaudeCode)
            .then(|| claude_subagent_identity(path))
            .flatten();
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
        if self.source == SnapshotSource::ClaudeCode {
            let workflows_dir = path.with_extension("").join("workflows");
            self.origin.used_workflow_orchestration =
                Some(claude_workflows_dir_has_manifest(&workflows_dir));
        }
        let repository_identity = self.workspace_path.as_deref().map(|workspace| {
            measured_repository_identity.unwrap_or_else(|| cached_repository_identity(workspace))
        });
        let workspace_display_label = repository_identity
            .as_ref()
            .filter(|identity| {
                matches!(
                    identity.workspace_kind.as_deref(),
                    Some("non_git" | "unknown")
                )
            })
            .and(self.workspace_path.as_deref())
            .and_then(crate::context_footprint::workspace_label);
        let mut attribution_facts = crate::session_attribution::direct_provider_facts(
            self.source,
            Some(&self.origin),
            &source_session_id,
            collected_at,
            self.source.parser_version(),
        );
        let codex_subagent = self.source == SnapshotSource::Codex
            && (self.origin.thread_source.as_deref() == Some("subagent")
                || self.origin.source_subagent == Some(true));
        if codex_subagent {
            attribution_facts.extend(crate::session_attribution::codex_subagent_facts(
                self.codex_root_session_ref.as_deref(),
                &source_session_id,
                self.codex_spawn_depth,
                self.codex_agent_label.as_deref(),
                collected_at,
                self.source.parser_version(),
            ));
        }
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
        // The starting session the Claude desktop app recorded for a session
        // another agent opened with its `start_session` tool. Provider-owned
        // lineage, so it sits ahead of launcher facts and never overwrites a
        // field provider-native evidence already filled.
        if let Some(lineage) = self.claude_desktop_spawn_lineage.as_ref() {
            let mut spawn_facts = crate::session_attribution::claude_desktop_spawn_facts(
                &lineage.parent_session_id,
                &source_session_id,
                collected_at,
            );
            spawn_facts.retain(|spawn_fact| {
                !attribution_facts
                    .iter()
                    .any(|fact| fact.field == spawn_fact.field)
            });
            attribution_facts.extend(spawn_facts);
        }
        // The controller edge an instrumented launcher stated at spawn time.
        // Same position and same reason as the subagent identity above: it is
        // exact lineage, so it has to outrank the derived grouping ids when the
        // payload budget trims from the tail.
        //
        // Provider-native evidence wins every field it already filled. A worker
        // the launcher started is a root session in its own provider tree, so in
        // practice nothing collides; when something does, the provider owns the
        // session and the launcher is the one that must be wrong.
        if let Some(context) = attribution_context {
            let mut launch_facts = context.launch_event_facts(&source_session_id, collected_at);
            launch_facts.retain(|launch_fact| {
                !attribution_facts
                    .iter()
                    .any(|fact| fact.field == launch_fact.field)
            });
            attribution_facts.extend(launch_facts);
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
                        activity_skills: &self.activity_skills,
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
        let activity_summary = self.activity_summary();
        // Emit an explicit empty list for a counted Claude/Codex transcript so
        // a newer cumulative scan can clear a previously observed aggregate.
        // Codex reuses the activity-summary counts (MCP-reclassified calls are
        // already removed from the plain map). Pi's parser does not see tool
        // names, so the field stays omitted there.
        let (tool_usage, tool_usage_truncated) = match self.source {
            SnapshotSource::ClaudeCode => (
                Some(bounded_tool_usage_counts(&self.tool_usage_counts)),
                self.tool_usage_truncated,
            ),
            SnapshotSource::Codex => {
                let (rows, truncated) = codex_tool_usage_rows(
                    &self.activity_tool_counts,
                    &self.activity_mcp_tool_usage_counts,
                );
                (Some(rows), truncated)
            }
            SnapshotSource::Pi => (None, false),
        };
        // Per-row session-wide aggregation (sum across all buckets keyed by
        // RowKey). Drives the top-level model_usage list and the snapshot
        // totals so the backend validator sees the two reconcile exactly.
        let totals = self.accepted_usage_totals.clone();
        let mut session_rows: BTreeMap<RowKey, BucketRowAccumulator> = BTreeMap::new();
        let mut usage_buckets: Vec<SnapshotUsageBucket> = Vec::new();
        // `e2` (gate on): the fold's grains are this body's one per-hour store
        // until `e2::finish_page` emits them; native per-hour rows would only
        // duplicate them on the page. A withheld body never uploads.
        let request_owned_hours =
            self.source == SnapshotSource::ClaudeCode && self.claude_money.is_some();
        for (bucket_start, bucket) in self.usage_buckets {
            if bucket.rows.is_empty() {
                continue;
            }
            if request_owned_hours {
                for (row_key, row) in bucket.rows {
                    merge_session_row(&mut session_rows, row_key, row);
                }
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
        // `e2` (gate on): a file whose every response is a resolver conflict
        // keeps a zero-usage carrier, so its conflict disclosure publishes
        // through the literal emitter like any request-owned body. No tokens
        // are invented; gate off, nothing changes.
        let conflict_carrier = self.source == SnapshotSource::ClaudeCode
            && self
                .claude_money
                .as_deref()
                .is_some_and(|money| money.entity.resolver_conflicts > 0);
        if session_rows.is_empty() && !conflict_carrier && !emit_empty_pi_fork {
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
        // Claude Code events are built by the ownership fold, never here.
        let (compaction_count, compaction_timestamps, compaction_events, compaction_metrics) =
            if self.source == SnapshotSource::ClaudeCode {
                let (count, timestamps, metrics) =
                    claude_compaction_summary(&self.claude_compaction_observations);
                (count, timestamps, Vec::new(), metrics)
            } else {
                let timestamps = self.compaction_timestamps.into_vec();
                let events = if self.source == SnapshotSource::Codex {
                    self.codex_compaction_sizes.into_events()
                } else {
                    Vec::new()
                };
                (
                    self.compaction_count,
                    bounded_compaction_timestamps(timestamps),
                    events,
                    CompactionMetrics::default(),
                )
            };
        let local_context_points = if self.source == SnapshotSource::Codex {
            self.local_context_points
                .into_recent(self.last_activity_at.as_deref(), collected_at)
        } else {
            Vec::new()
        };
        if self.source == SnapshotSource::Codex && codex_usage_accounting_proven {
            // An incomplete physical read report cannot certify an exact
            // omitted count.
            self.cache_observations = Some(cache_wire(
                &source_session_id,
                self.cache_requests.iter(),
                self.cache_requests_complete,
            ));
        }
        let session_start = match self.source {
            SnapshotSource::ClaudeCode => std::mem::take(&mut *self.session_start).finish(
                true,
                self.first_turn_context_tokens,
                session_start::CLAUDE_PARTS_METHOD,
                attribution_context,
                crate::context_file_counts::device_salt().as_ref(),
            ),
            SnapshotSource::Codex => std::mem::take(&mut *self.session_start).finish(
                !self.codex_is_fork,
                self.first_turn_context_tokens,
                session_start::CODEX_PARTS_METHOD,
                attribution_context,
                crate::context_file_counts::device_salt().as_ref(),
            ),
            _ => None,
        }
        .map(Box::new);
        let mut item = SnapshotItem {
            request_evidence: Vec::new(),
            request_identity_refusals: 0,
            claude_org_markers: self.claude_org_markers,
            claude_account_withheld_reason: None,
            claude_account_display: None,
            session_account_evidence,
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
            usage_accounting_contract: codex_usage_accounting_proven
                .then(|| "session_exclusive_reported_usage:v1".to_string()),
            removed_request_count: None,
            removed_usage: None,
            telemetry_owned_complete: None,
            resolver_conflict_count: None,
            copy_unproven_counts: None,
            claude_money: self.claude_money,
            claude_usage_request_ids: self.claude_usage_request_ids,
            claude_usage_occurrences: self.claude_usage_occurrences,
            cache_observations: self.cache_observations,
            cache_observations_state: None,
            cache_base_head_etag: None,
            cache_conflict_answer: None,
            cache_requests: self.cache_requests.into_vec(),
            cache_requests_complete: self.cache_requests_complete,
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
            last_turn_context_tokens: if self.source.derives_context_posture() {
                self.last_turn_context_tokens
            } else {
                None
            },
            // Codex only, and each only beside its own emitted watermark.
            first_turn_context_window_tokens: self.first_turn_context_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.first_turn_context_tokens.is_some()
            }),
            peak_context_fill_window_tokens: self.peak_context_fill_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.peak_context_fill_tokens > 0
            }),
            last_turn_context_window_tokens: self.last_turn_context_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.last_turn_context_tokens.is_some()
            }),
            compaction_count: self
                .source
                .derives_context_posture()
                .then_some(compaction_count),
            compaction_timestamps: if self.source.derives_context_posture() {
                compaction_timestamps
            } else {
                Vec::new()
            },
            compaction_events: if self.source.derives_context_posture() {
                compaction_events
            } else {
                Vec::new()
            },
            // Set by the ownership fold only (design E), never here.
            first_own_request_at: None,
            local_context_points,
            compaction_total_pre_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_pre_tokens)
            } else {
                None
            },
            compaction_total_post_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_post_tokens)
            } else {
                None
            },
            compaction_total_cumulative_dropped_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_cumulative_dropped_tokens)
            } else {
                None
            },
            compaction_total_duration_ms: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_duration_ms)
            } else {
                None
            },
            context_curve: None,
            claude_context_curve_boundaries: self.claude_compaction_observations.into_vec(),
            claude_context_curve_identity_complete: self.claude_context_curve_identity_complete,
            claude_context_curve_request_index_complete: self
                .claude_context_curve_request_index_complete,
            claude_context_curve_owned_start_proven: self.claude_context_curve_owned_start_proven,
            claude_file_birth: self.claude_file_birth,
            claude_file_birth_verdict: None,
            activity_summary,
            tool_usage,
            tool_usage_truncated,
            session_start,
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
            workspace_label_source: workspace_display_label
                .as_ref()
                .map(|_| "directory_name".into()),
            workspace_display_label,
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
