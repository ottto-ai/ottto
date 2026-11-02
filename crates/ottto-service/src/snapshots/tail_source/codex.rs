//! The Codex Tail codec.
//!
//! Head: the identity, the checkpoint certificate, the read report and the
//! three reduction scalars, whether priority decisions exist, every accumulator
//! field stored by its class, and the digests of the re-derived fields. Pages:
//! the three dictionaries in stable slots with tombstones, the priority
//! decisions, the physical signatures, the cache requests, the compaction
//! timestamps, the usage and capability hours and the changed-file hashes.
//! Parse-time totals are head state on Codex, not finish output. Live fields
//! come from this cycle's owners through `install_live`, and foreign or
//! finish-only fields stay empty at the seam.
#![cfg_attr(not(test), allow(dead_code))] // Reached through the shared dispatch's Codex arm.

use super::{
    capability_hour_entry, capability_hour_pages, encode, fixed_pages, hour_page, page_bytes,
    read_page, slot_start, CollectionSpec, DecodedHead, HeadIdentity, LiveInputs, LiveLoadError,
    ReconstructCause, TailSource,
};
use crate::durable_tail_codec::{
    durable_enum, durable_field, durable_struct, Corrupt, Dec, Durable, DurableEmpty, Enc, HDigest,
    Refuse,
};
use crate::snapshots::codex_dictionary_slots::{CodexCountMap, StableSlots};
use crate::snapshots::sampled_jsonl::durable::{rederive_digests, Rederive};
use crate::snapshots::sampled_scan::codex_cursor::{priority_decisions, PriorityDecisions};
use crate::snapshots::state_v2::{Collection, Shape as PageShape};
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const DICTIONARY_G: u32 = 64;
const PRIORITY_G: u32 = 256;
const SIGNATURES_G: u32 = 256;
const REQUESTS_G: u32 = 64;
const COMPACTIONS_G: u32 = 64;
const LOG_G: u32 = 256;

const fn slot(collection: Collection, g: u32) -> CollectionSpec {
    CollectionSpec {
        collection,
        shape: PageShape::Slot,
        g,
        required: true,
    }
}
const fn hour(collection: Collection) -> CollectionSpec {
    CollectionSpec {
        collection,
        shape: PageShape::Hour,
        g: 0,
        required: true,
    }
}

const COLLECTIONS: [CollectionSpec; 10] = [
    slot(Collection::CodexActiveTurns, DICTIONARY_G),
    slot(Collection::CodexOpenCalls, DICTIONARY_G),
    slot(Collection::CodexNameCounts, DICTIONARY_G),
    slot(Collection::PriorityTurns, PRIORITY_G),
    slot(Collection::Signatures, SIGNATURES_G),
    slot(Collection::Requests, REQUESTS_G),
    slot(Collection::Compactions, COMPACTIONS_G),
    hour(Collection::UsageHours),
    hour(Collection::CapabilityHours),
    CollectionSpec {
        collection: Collection::ChangedFiles,
        shape: PageShape::Log,
        g: LOG_G,
        required: true,
    },
];

/// A turn's slot; `active: false` is a tombstone.
struct CodexActiveTurn {
    turn_id: String,
    active: bool,
}
durable_struct!(CodexActiveTurn {
    L turn_id: String,
    N active: bool,
});

/// A call's slot; both `None` is a tombstone. `Some(false)` is a pending MCP
/// call, not a deletion.
struct CodexOpenCall {
    call_id: String,
    tool: Option<String>,
    mcp_completion: Option<bool>,
}
durable_struct!(CodexOpenCall {
    L call_id: String,
    U tool: Option<String>,
    N mcp_completion: Option<bool>,
});

/// A name's slot; `None` is a tombstone and `Some(0)` a real zero.
struct CodexNameCount {
    map: CodexCountMap,
    name: String,
    count: Option<u64>,
}
durable_struct!(CodexNameCount {
    N map: CodexCountMap,
    U name: String,
    N count: Option<u64>,
});

/// One priority decision; the map's sorted order is its page order.
struct CodexPriorityTurn {
    turn_id: String,
    priority: bool,
}
durable_struct!(CodexPriorityTurn {
    L turn_id: String,
    N priority: bool,
});

/// A compaction element. Every append and duplicate has its own slot. Sizes
/// live in the head and are never zipped to these slots. A Codex head reads
/// only the timestamp variant; the tag keeps one element kind for both sources.
#[allow(clippy::large_enum_variant)] // Elements are built and written one at a time.
enum TaggedCompaction {
    CodexTimestamp { at: String },
    ClaudeObservation(ClaudeCompactionObservation),
}
durable_enum!(TaggedCompaction {
    0 => CodexTimestamp { N at: String },
    1 => ClaudeObservation(D observation: ClaudeCompactionObservation),
});

// Every accumulator field, by its Codex Tail home. `I` marks a field kept
// elsewhere: pages, the live inputs `install_live` supplies (traces, ledgers,
// projected ordinal, parent signatures and proof, tier replay), the bootstrap
// buffer that sets a file aside, and fields that stay empty on Codex (foreign
// sources, finish scratch). `D` totals are parse-time Codex state, kept in full
// with presence apart from zero. `X` fields are this pin's re-derivation shim.
head_fields! {
    N source: SnapshotSource,
    H cache_configuration_witness: Option<String>,
    N cache_task_complete_at: Option<String>,
    N cache_pending_idle: Option<u64>,
    I cache_active_turns: BTreeSet<String>,
    N context_curve_enabled: bool,
    U source_session_id: Option<String>,
    U account_identifier_hash: Option<String>,
    X title: Option<String>,
    N title_source: Option<String>,
    X first_prompt_title: Option<String>,
    X first_prompt_material: Option<String>,
    N provider_skills: BTreeSet<String>,
    N started_at: Option<String>,
    N ended_at: Option<String>,
    N last_activity_at: Option<String>,
    U workspace_hash: Option<String>,
    X workspace_path: Option<PathBuf>,
    U latest_model: Option<String>,
    U latest_reasoning_effort: Option<String>,
    L latest_turn_id: Option<String>,
    I codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    I codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
    N codex_priority_witnesses_uncapped: bool,
    I codex_tier_replay: Option<codex_file_join::TierReplay>,
    D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
    D current_selector: SelectorCapture,
    D session_cumulative_usage: Option<UsageTotals>,
    N codex_session_meta_seen: bool,
    N codex_record_seen: bool,
    U codex_creator_header_id: Option<String>,
    D codex_creator_evidence: Option<SessionAccountEvidence>,
    N codex_creator_evidence_conflicted: bool,
    I claude_desktop_identity: Option<SessionAccountEvidence>,
    I claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
    N claude_owned_session_id_observed: bool,
    N claude_owned_session_id_conflicted: bool,
    D codex_ownership_boundary: CodexOwnershipBoundary,
    N codex_legacy_trigger_seen: bool,
    N codex_legacy_bootstrap_valid: bool,
    I codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    N codex_sidecar_created_thread: bool,
    D codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
    U codex_resolved_path_identity: Option<String>,
    N codex_sidecar_identity_ambiguous: bool,
    U codex_sidecar_parent: Option<(String, String)>,
    N codex_sidecar_child_created_at_nanos: Option<i128>,
    N codex_bind_seed_len: Option<u64>,
    I codex_sidecar_projected_next_ordinal: Option<u64>,
    U codex_parent_session_ref: Option<String>,
    I codex_parent_signatures: Option<CodexParentPrefix>,
    H codex_parent_prefix_digest: PrefixDigest,
    D codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
    I codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
    D codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    N codex_parent_proof_mismatch: bool,
    D codex_parent_proof_refusal: Option<ProofRefusal>,
    N codex_proof_decision_only: bool,
    N codex_boundary_buffer_count: u8,
    H codex_proof_ledger_row: Option<String>,
    H codex_parent_ledger_identity_used: Option<String>,
    D codex_parent_unresolvable: Option<CodexParentUnresolvable>,
    N codex_parent_ledger_consulted: bool,
    N codex_parent_signature_index: usize,
    N codex_native_created_thread_valid: bool,
    N codex_created_thread_native_only: bool,
    N codex_native_created_thread_header_nanos: Option<i128>,
    N codex_native_created_thread_last_nanos: Option<i128>,
    L codex_native_created_thread_task_turn_id: Option<String>,
    N codex_native_created_thread_first_turn_bound: bool,
    I codex_physical_signatures: crate::owned_heap::OwnedVec<String>,
    N codex_physical_signatures_complete: bool,
    N codex_ordinal_expected: Option<u64>,
    N codex_ordinal_sequence_valid: bool,
    N codex_owned_record_seen: bool,
    N codex_is_fork: bool,
    N codex_inherited_usage_records_skipped: u64,
    N codex_duplicate_usage_records_skipped: u64,
    N codex_cumulative_reset_count: u64,
    I codex_context_curve_candidates: crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    I codex_context_curve_boundaries: crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    N codex_context_curve_exact_supported: bool,
    H codex_last_usage_event_identity: Option<String>,
    I codex_legacy_bootstrap_buffer: Vec<Value>,
    D accepted_usage_totals: UsageTotals,
    I usage_buckets: BTreeMap<String, UsageBucketState>,
    D origin: SnapshotOrigin,
    U codex_root_session_ref: Option<String>,
    N codex_spawn_depth: Option<u64>,
    X codex_agent_label: Option<String>,
    I activity_tool_counts: BTreeMap<String, u64>,
    I activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
    I activity_mcp_tool_counts: BTreeMap<String, u64>,
    I activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
    I activity_mcp_call_ids: BTreeMap<String, bool>,
    I activity_capability_buckets: BTreeMap<(String, String, String), u64>,
    I seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap<String, ()>,
    N activity_skills: BTreeSet<String>,
    N skill_detector_incomplete: bool,
    I activity_changed_file_hashes: BTreeSet<String>,
    N activity_patch_operations: u64,
    N activity_lines_added: u64,
    N activity_lines_deleted: u64,
    N activity_web_searches: u64,
    N activity_mcp_calls: u64,
    N activity_subagent_spawns: u64,
    U artifacts: Vec<SessionArtifact>,
    N artifacts_enabled: bool,
    N latency_duration_ms_sum: u64,
    N latency_duration_ms_count: u64,
    N latency_ttft_ms_sum: u64,
    N latency_ttft_ms_count: u64,
    N latency_duration_ms_max: u64,
    N latency_ttft_ms_max: u64,
    I claude_responses: ClaudeResponseBook,
    N claude_response_sequence: u64,
    N claude_response_record_count: usize,
    I claude_usage_request_ids: BTreeSet<String>,
    I claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    N claude_request_identity_capture: bool,
    I claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    I cache_observations: Option<CacheObservations>,
    I cache_requests: crate::owned_heap::OwnedVec<OwnedRequest>,
    N cache_requests_complete: bool,
    N claude_context_curve_identity_complete: bool,
    N claude_context_curve_request_index_complete: bool,
    N claude_context_curve_owned_start_proven: bool,
    D claude_file_birth: ClaudeFileBirth,
    I claude_fork_parent: Option<String>,
    I claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    U tool_usage_counts: BTreeMap<String, u64>,
    N tool_usage_truncated: bool,
    I seen_pi_usage_keys: PiLedger,
    N dropped_usage_record_count: u64,
    I claude_last_user_ts: Option<String>,
    N peak_context_fill_tokens: u64,
    N first_turn_context_tokens: Option<u64>,
    N last_turn_context_tokens: Option<u64>,
    N first_turn_context_window_tokens: Option<u64>,
    N peak_context_fill_window_tokens: Option<u64>,
    N last_turn_context_window_tokens: Option<u64>,
    N compaction_count: u64,
    I compaction_timestamps: crate::owned_heap::OwnedVec<String>,
    D codex_compaction_sizes: CodexCompactionSizes,
    D local_context_points: LocalContextPoints,
    I claude_compaction_observations: crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    I claude_compaction_link_tip: Option<(u64, String)>,
    D session_start: Box<session_start::SessionStartState>,
    D durable_marks: crate::durable_tail_codec::DurableMarks,
    I codex_dictionary_slots: crate::snapshots::codex_dictionary_slots::CodexDictionarySlots,
}

/// The Codex source: a marker type, never a value.
pub(in crate::snapshots) enum Codex {}

fn count_map(acc: &SnapshotAccumulator, map: CodexCountMap) -> &BTreeMap<String, u64> {
    match map {
        CodexCountMap::Tool => &acc.activity_tool_counts,
        CodexCountMap::McpActivity => &acc.activity_mcp_tool_counts,
        CodexCountMap::McpUsage => &acc.activity_mcp_tool_usage_counts,
    }
}

/// Every key the native maps hold has its slot. A native insert that missed
/// its slot note would lose the key on load, so it refuses this file's stage
/// (set aside, predecessor kept) rather than store a short dictionary.
fn slots_cover_live_maps(acc: &SnapshotAccumulator) -> bool {
    let slots = &acc.codex_dictionary_slots;
    acc.cache_active_turns
        .iter()
        .all(|turn| slots.active_turns.contains(turn))
        && acc
            .activity_call_tools
            .keys()
            .all(|call| slots.open_calls.contains(&call.id))
        && acc
            .activity_mcp_call_ids
            .keys()
            .all(|call| slots.open_calls.contains(call))
        && [
            CodexCountMap::Tool,
            CodexCountMap::McpActivity,
            CodexCountMap::McpUsage,
        ]
        .into_iter()
        .all(|map| {
            count_map(acc, map)
                .keys()
                .all(|name| slots.name_counts.contains(&(map, name.clone())))
        })
}

fn adopt<K: Ord + crate::heap_layout_bound::HeapLayoutBound>(
    slots: &mut StableSlots<K>,
    key: K,
) -> Result<(), ReconstructCause> {
    if slots.adopt(key) {
        Ok(())
    } else {
        Err(ReconstructCause::Corrupt)
    }
}

impl TailSource for Codex {
    const SOURCE: SnapshotSource = SnapshotSource::Codex;
    const REDUCTION_REVISION: u32 = 1;

    fn collections() -> &'static [CollectionSpec] {
        &COLLECTIONS
    }

    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64 {
        let slots = &acc.codex_dictionary_slots;
        (match collection {
            Collection::CodexActiveTurns => slots.active_turns.len(),
            Collection::CodexOpenCalls => slots.open_calls.len(),
            Collection::CodexNameCounts => slots.name_counts.len(),
            Collection::PriorityTurns => acc
                .codex_observed_priority_turns
                .as_ref()
                .map_or(0, BTreeMap::len),
            Collection::Signatures => acc.codex_physical_signatures.len(),
            Collection::Requests => acc.cache_requests.len(),
            Collection::Compactions => acc.compaction_timestamps.len(),
            Collection::UsageHours => acc.usage_buckets.len(),
            Collection::CapabilityHours => acc.activity_capability_buckets.len(),
            Collection::ChangedFiles => acc.activity_changed_file_hashes.len(),
            _ => 0,
        }) as u64
    }

    /// The bootstrap buffer holds raw lines and sets the file aside while it
    /// holds any. The rest are foreign or finish-only here. Parse-time totals,
    /// usage buckets and cache requests are ordinary Codex state, not on this
    /// list.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str> {
        [
            (
                "codex_legacy_bootstrap_buffer",
                !acc.codex_legacy_bootstrap_buffer.is_empty(),
            ),
            (
                "codex_context_curve_candidates",
                !acc.codex_context_curve_candidates.is_empty(),
            ),
            (
                "codex_context_curve_boundaries",
                !acc.codex_context_curve_boundaries.is_empty(),
            ),
            (
                "claude_responses",
                acc.claude_responses.values().next().is_some(),
            ),
            (
                "claude_desktop_identity",
                acc.claude_desktop_identity.is_some(),
            ),
            (
                "claude_desktop_spawn_lineage",
                acc.claude_desktop_spawn_lineage.is_some(),
            ),
            (
                "seen_claude_capability_tool_uses",
                !acc.seen_claude_capability_tool_uses.is_empty(),
            ),
            (
                "claude_usage_request_ids",
                !acc.claude_usage_request_ids.is_empty(),
            ),
            (
                "claude_usage_occurrences",
                !acc.claude_usage_occurrences.is_empty(),
            ),
            ("claude_org_markers", acc.claude_org_markers.is_some()),
            ("claude_money", acc.claude_money.is_some()),
            ("cache_observations", acc.cache_observations.is_some()),
            (
                "seen_pi_usage_keys",
                !acc.seen_pi_usage_keys.durable_empty(),
            ),
            (
                "claude_compaction_observations",
                !acc.claude_compaction_observations.is_empty(),
            ),
            (
                "claude_compaction_link_tip",
                acc.claude_compaction_link_tip.is_some(),
            ),
            ("claude_last_user_ts", acc.claude_last_user_ts.is_some()),
            ("claude_fork_parent", acc.claude_fork_parent.is_some()),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    fn log_keys(acc: &SnapshotAccumulator, collection: Collection) -> Vec<&String> {
        match collection {
            Collection::ChangedFiles => acc.activity_changed_file_hashes.iter().collect(),
            _ => Vec::new(),
        }
    }

    fn log_page(_: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        page_bytes(keys.iter(), |hash, e| {
            hash.put_h(e, "SnapshotAccumulator.activity_changed_file_hashes")
        })
    }

    fn log_page_keys(_: Collection, bytes: &[u8]) -> Result<Vec<String>, ReconstructCause> {
        let mut keys = Vec::new();
        read_page(bytes, LOG_G, |d| {
            keys.push(String::take_h(d)?);
            Ok(())
        })?;
        Ok(keys)
    }

    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse> {
        let acc = view.accumulator;
        if !slots_cover_live_maps(acc) {
            return Err(Refuse::NonEmpty(
                "SnapshotAccumulator.codex_dictionary_slots",
            ));
        }
        let rederive = rederive_digests(acc, u64::MAX, u64::MAX)?;
        let scalars = (
            view.recognized_usage_drop_count,
            view.positive_recognized_usage_count,
            view.positive_usage_evidence,
        );
        let priority_present = acc.codex_observed_priority_turns.is_some();
        encode(|e| {
            e.with_moved_field("OpeningCall.files", |e| {
                id.put(e)?;
                certificate.put(e)?;
                view.report.put(e)?;
                scalars.put(e)?;
                priority_present.put(e)?;
                put_fields(acc, e)?;
                rederive.put(e)
            })
        })
    }

    fn encode_pages(
        acc: &SnapshotAccumulator,
        collection: Collection,
    ) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
        let slots = &acc.codex_dictionary_slots;
        match collection {
            Collection::CodexActiveTurns => {
                let turns: Vec<_> = slots
                    .active_turns
                    .ordered()
                    .into_iter()
                    .map(|turn| CodexActiveTurn {
                        turn_id: turn.clone(),
                        active: acc.cache_active_turns.contains(turn),
                    })
                    .collect();
                fixed_pages(&turns, DICTIONARY_G, |turn, e| turn.put(e))
            }
            Collection::CodexOpenCalls => {
                let calls: Vec<_> = slots
                    .open_calls
                    .ordered()
                    .into_iter()
                    .map(|call| CodexOpenCall {
                        call_id: call.clone(),
                        tool: acc
                            .activity_call_tools
                            .get(call.as_str())
                            .map(|tool| tool.name.clone()),
                        mcp_completion: acc.activity_mcp_call_ids.get(call).copied(),
                    })
                    .collect();
                fixed_pages(&calls, DICTIONARY_G, |call, e| call.put(e))
            }
            Collection::CodexNameCounts => {
                let counts: Vec<_> = slots
                    .name_counts
                    .ordered()
                    .into_iter()
                    .map(|(map, name)| CodexNameCount {
                        map: *map,
                        name: name.clone(),
                        count: count_map(acc, *map).get(name).copied(),
                    })
                    .collect();
                fixed_pages(&counts, DICTIONARY_G, |count, e| count.put(e))
            }
            Collection::PriorityTurns => {
                let turns: Vec<_> = acc
                    .codex_observed_priority_turns
                    .iter()
                    .flatten()
                    .map(|(turn, priority)| CodexPriorityTurn {
                        turn_id: turn.clone(),
                        priority: *priority,
                    })
                    .collect();
                fixed_pages(&turns, PRIORITY_G, |turn, e| turn.put(e))
            }
            Collection::Signatures => fixed_pages(
                &acc.codex_physical_signatures,
                SIGNATURES_G,
                |signature, e| signature.put_h(e, "SnapshotAccumulator.codex_physical_signatures"),
            ),
            Collection::Requests => {
                fixed_pages(&acc.cache_requests, REQUESTS_G, |request, e| request.put(e))
            }
            Collection::Compactions => {
                let compactions: Vec<_> = acc
                    .compaction_timestamps
                    .iter()
                    .map(|at| TaggedCompaction::CodexTimestamp { at: at.clone() })
                    .collect();
                fixed_pages(&compactions, COMPACTIONS_G, |compaction, e| {
                    compaction.put(e)
                })
            }
            Collection::UsageHours => {
                let mut hours: BTreeMap<u64, Vec<_>> = BTreeMap::new();
                for entry in &acc.usage_buckets {
                    hours.entry(hour_page(entry.0)).or_default().push(entry);
                }
                hours
                    .into_iter()
                    .map(|(hour, entries)| {
                        let bytes = page_bytes(entries.iter(), |(key, bucket), e| {
                            key.put(e)?;
                            bucket.put(e)
                        })?;
                        Ok((hour, bytes))
                    })
                    .collect()
            }
            Collection::CapabilityHours => capability_hour_pages(acc),
            Collection::ChangedFiles => Self::log_keys(acc, collection)
                .chunks(LOG_G as usize)
                .enumerate()
                .map(|(page, keys)| Ok((page as u64, Self::log_page(collection, keys)?)))
                .collect(),
            _ => Ok(Vec::new()),
        }
    }

    fn decode_head(
        revision: u32,
        head: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<DecodedHead, ReconstructCause> {
        if revision != Self::REDUCTION_REVISION {
            return Err(ReconstructCause::Revision);
        }
        let mut d = Dec::new(head);
        HeadIdentity::take(&mut d)?;
        let certificate = DurableCertificate::take(&mut d)?;
        let report = JsonlReadReport::take(&mut d)?;
        let scalars = <(usize, usize, bool)>::take(&mut d)?;
        let priority_present = bool::take(&mut d)?;
        let mut acc = take_fields(&mut d)?;
        let rederive = Rederive::take(&mut d)?;
        d.finish()?;
        if acc.source != Self::SOURCE {
            return Err(ReconstructCause::Corrupt);
        }
        acc.codex_observed_priority_turns = priority_present.then(BTreeMap::new);
        *into = acc;
        Ok(DecodedHead {
            certificate,
            report,
            scalars,
            rederive,
        })
    }

    fn decode_page(
        collection: Collection,
        page: u64,
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause> {
        match collection {
            Collection::CodexActiveTurns => {
                slot_start(
                    page,
                    DICTIONARY_G,
                    into.codex_dictionary_slots.active_turns.len(),
                )?;
                read_page(bytes, DICTIONARY_G, |d| {
                    let CodexActiveTurn { turn_id, active } = CodexActiveTurn::take(d)?;
                    adopt(
                        &mut into.codex_dictionary_slots.active_turns,
                        turn_id.clone(),
                    )?;
                    if active {
                        into.cache_active_turns.insert(turn_id);
                    }
                    Ok(())
                })
            }
            Collection::CodexOpenCalls => {
                slot_start(
                    page,
                    DICTIONARY_G,
                    into.codex_dictionary_slots.open_calls.len(),
                )?;
                read_page(bytes, DICTIONARY_G, |d| {
                    let CodexOpenCall {
                        call_id,
                        tool,
                        mcp_completion,
                    } = CodexOpenCall::take(d)?;
                    adopt(&mut into.codex_dictionary_slots.open_calls, call_id.clone())?;
                    if let Some(completed) = mcp_completion {
                        into.activity_mcp_call_ids
                            .insert(call_id.clone(), completed);
                    }
                    if let Some(name) = tool {
                        into.activity_call_tools
                            .insert(ActivityCallId { id: call_id }, ActivityCallTool { name });
                    }
                    Ok(())
                })
            }
            Collection::CodexNameCounts => {
                slot_start(
                    page,
                    DICTIONARY_G,
                    into.codex_dictionary_slots.name_counts.len(),
                )?;
                read_page(bytes, DICTIONARY_G, |d| {
                    let CodexNameCount { map, name, count } = CodexNameCount::take(d)?;
                    adopt(
                        &mut into.codex_dictionary_slots.name_counts,
                        (map, name.clone()),
                    )?;
                    if let Some(count) = count {
                        let counts = match map {
                            CodexCountMap::Tool => &mut into.activity_tool_counts,
                            CodexCountMap::McpActivity => &mut into.activity_mcp_tool_counts,
                            CodexCountMap::McpUsage => &mut into.activity_mcp_tool_usage_counts,
                        };
                        counts.insert(name, count);
                    }
                    Ok(())
                })
            }
            Collection::PriorityTurns => {
                // Pages under a head that recorded no decisions contradict it.
                let Some(turns) = into.codex_observed_priority_turns.as_mut() else {
                    return Err(ReconstructCause::Corrupt);
                };
                slot_start(page, PRIORITY_G, turns.len())?;
                read_page(bytes, PRIORITY_G, |d| {
                    let CodexPriorityTurn { turn_id, priority } = CodexPriorityTurn::take(d)?;
                    match turns.insert(turn_id, priority) {
                        None => Ok(()),
                        Some(_) => Err(ReconstructCause::Corrupt),
                    }
                })
            }
            Collection::Signatures => {
                let signatures = &mut into.codex_physical_signatures;
                slot_start(page, SIGNATURES_G, signatures.len())?;
                read_page(bytes, SIGNATURES_G, |d| {
                    signatures.push(String::take_h(d)?);
                    Ok(())
                })
            }
            Collection::Requests => {
                let requests = &mut into.cache_requests;
                slot_start(page, REQUESTS_G, requests.len())?;
                read_page(bytes, REQUESTS_G, |d| {
                    requests.push(OwnedRequest::take(d)?);
                    Ok(())
                })
            }
            Collection::Compactions => {
                let timestamps = &mut into.compaction_timestamps;
                slot_start(page, COMPACTIONS_G, timestamps.len())?;
                read_page(bytes, COMPACTIONS_G, |d| match TaggedCompaction::take(d)? {
                    TaggedCompaction::CodexTimestamp { at } => {
                        timestamps.push(at);
                        Ok(())
                    }
                    TaggedCompaction::ClaudeObservation(_) => Err(ReconstructCause::Corrupt),
                })
            }
            Collection::UsageHours => read_page(bytes, 0, |d| {
                let key = String::take(d)?;
                let bucket = UsageBucketState::take(d)?;
                if hour_page(&key) != page || into.usage_buckets.insert(key, bucket).is_some() {
                    return Err(ReconstructCause::Corrupt);
                }
                Ok(())
            }),
            Collection::CapabilityHours => {
                read_page(bytes, 0, |d| capability_hour_entry(d, page, into))
            }
            Collection::ChangedFiles => read_page(bytes, LOG_G, |d| {
                if into.activity_changed_file_hashes.insert(String::take_h(d)?) {
                    Ok(())
                } else {
                    Err(ReconstructCause::Corrupt)
                }
            }),
            _ => Err(ReconstructCause::Corrupt),
        }
    }

    fn facts(acc: &SnapshotAccumulator) -> Result<(), ReconstructCause> {
        if acc.source == Self::SOURCE {
            Ok(())
        } else {
            Err(ReconstructCause::Corrupt)
        }
    }

    /// The reuse decision, then this cycle's inputs. A real group or a
    /// protected receipt has no stored continuation (D168: a counted replay).
    /// Otherwise the stored state continues only under the counting rule this
    /// cycle selects and with every prior priority decision still holding.
    /// Absent or incomplete evidence waits; evidence that disagrees rebuilds.
    /// The fresh accumulator keeps its own inputs: preparing the read still
    /// compares against them.
    fn install_live(
        stored: &mut SnapshotAccumulator,
        fresh: &LiveInputs<'_>,
    ) -> Result<(), LiveLoadError> {
        let live = fresh.accumulator;
        if fresh.group_members > 1 {
            return Err(LiveLoadError::Reconstruct(ReconstructCause::GroupReplay));
        }
        if live
            .codex_tier_replay
            .as_ref()
            .is_some_and(codex_file_join::TierReplay::needs_prior_prefix)
        {
            return Err(LiveLoadError::Reconstruct(
                ReconstructCause::TierPrefixReplay,
            ));
        }
        if !codex_counting_version::reusable(
            stored.codex_counting.as_deref(),
            live.codex_counting.as_deref(),
        ) {
            return Err(LiveLoadError::Reconstruct(ReconstructCause::Incompatible));
        }
        let Some(observed) = stored.codex_observed_priority_turns.as_ref() else {
            return Err(LiveLoadError::Reconstruct(ReconstructCause::Incompatible));
        };
        match priority_decisions(observed, live.codex_turn_traces.as_ref()) {
            PriorityDecisions::Hold => {}
            PriorityDecisions::Unavailable => return Err(LiveLoadError::Unavailable),
            PriorityDecisions::Changed => {
                return Err(LiveLoadError::Reconstruct(ReconstructCause::Incompatible))
            }
        }
        // A child still waiting on its parent cannot continue before the parent
        // evidence exists. Once it does, the parent's prefix has to be consumed
        // from the file start by a read that sees it.
        if stored.codex_parent_resolution_pending() {
            return Err(
                if live.codex_parent_signatures.is_none()
                    && live.codex_parent_prefix_proof.is_none()
                {
                    LiveLoadError::Unavailable
                } else {
                    LiveLoadError::Reconstruct(ReconstructCause::Incompatible)
                },
            );
        }
        stored
            .claude_file_birth
            .refresh_opened(&live.claude_file_birth);
        stored.codex_turn_traces = live.codex_turn_traces.clone();
        stored.codex_parent_ownership_ledgers = live.codex_parent_ownership_ledgers.clone();
        stored.codex_sidecar_projected_next_ordinal = live.codex_sidecar_projected_next_ordinal;
        stored.codex_parent_signatures = live.codex_parent_signatures.clone();
        stored.codex_parent_prefix_proof = live.codex_parent_prefix_proof.clone();
        stored.codex_tier_replay = live.codex_tier_replay.clone();
        Ok(())
    }
}
