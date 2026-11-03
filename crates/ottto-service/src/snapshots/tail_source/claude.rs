//! The Claude Code Tail codec.
//!
//! Head: the identity, the checkpoint certificate, the read report and the
//! three reduction scalars, the response selectors and every accumulator
//! field stored by its class. Pages: the responses (each beside its key, so
//! the index re-derives), the capability tool uses, the changed-file hashes,
//! the hourly capability buckets, the compaction observations and the session
//! facts. Finish-only and live fields are never stored. Content (`X`: title,
//! first prompt, workspace, opening settings with each opening call's file
//! paths by call id) is a session fact, never read back from the file. Skill
//! labels are stored as they are.
use super::{
    encode, fixed_pages, page_bytes, read_page, slot_start, CollectionSpec, DecodedHead,
    HeadIdentity, ReconstructCause, TailSource,
};
use crate::durable_tail_codec::{durable_field, Corrupt, Dec, Durable, Enc, HDigest, Refuse};
use crate::snapshots::state_v2::{Collection, Shape as PageShape};
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const RESPONSES_G: u32 = 256;
const LOG_G: u32 = 256;
const COMPACTIONS_G: u32 = 64;
/// One fact per page, at its kind's position.
const FACTS_G: u32 = 1;

const COLLECTIONS: [CollectionSpec; 6] = [
    CollectionSpec {
        collection: Collection::Responses,
        shape: PageShape::Slot,
        g: RESPONSES_G,
        required: true,
        private: false,
    },
    CollectionSpec {
        collection: Collection::ToolUses,
        shape: PageShape::Log,
        g: LOG_G,
        required: true,
        private: false,
    },
    CollectionSpec {
        collection: Collection::ChangedFiles,
        shape: PageShape::Log,
        g: LOG_G,
        required: true,
        private: false,
    },
    CollectionSpec {
        collection: Collection::CapabilityHours,
        shape: PageShape::Hour,
        g: 0,
        required: true,
        private: false,
    },
    CollectionSpec {
        collection: Collection::Compactions,
        shape: PageShape::Slot,
        g: COMPACTIONS_G,
        required: true,
        private: false,
    },
    CollectionSpec {
        collection: Collection::SessionFacts,
        shape: PageShape::Slot,
        g: FACTS_G,
        required: true,
        private: true,
    },
];

/// The session facts (D168-1): content the head never carries, one element
/// per page at the kind's position, `[kind][version][value]`. A slot is
/// rewritten when its fact changes. A kind or version this build does not
/// know is incompatible: new ones come with a reduction revision.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fact {
    Title = 0,
    FirstPrompt = 1,
    Workspace = 2,
    OpeningSettings = 3,
}
const FACTS: [Fact; 4] = [
    Fact::Title,
    Fact::FirstPrompt,
    Fact::Workspace,
    Fact::OpeningSettings,
];
const FACT_VERSION: u64 = 1;

impl Fact {
    fn present(self, acc: &SnapshotAccumulator) -> bool {
        match self {
            Self::Title => acc.title.is_some(),
            Self::FirstPrompt => {
                acc.first_prompt_material.is_some() || acc.first_prompt_title.is_some()
            }
            Self::Workspace => acc.workspace_path.is_some(),
            Self::OpeningSettings => acc.session_start.has_opening_fact(),
        }
    }

    fn put(self, acc: &SnapshotAccumulator, e: &mut Enc<'_>) -> Result<(), Refuse> {
        e.varint(self as u64)?;
        e.varint(FACT_VERSION)?;
        match self {
            Self::Title => acc.title.put(e),
            Self::FirstPrompt => {
                acc.first_prompt_material.put(e)?;
                acc.first_prompt_title.put(e)
            }
            Self::Workspace => acc.workspace_path.put(e),
            Self::OpeningSettings => acc.session_start.put_opening_fact(e),
        }
    }

    /// One fact page into a decoded head's state.
    fn take(
        page: u64,
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause> {
        let fact = usize::try_from(page)
            .ok()
            .and_then(|at| FACTS.get(at).copied())
            .ok_or(ReconstructCause::Incompatible)?;
        let mut d = Dec::new(bytes);
        if d.varint()? != page {
            return Err(ReconstructCause::Corrupt);
        }
        if d.varint()? != FACT_VERSION {
            return Err(ReconstructCause::Incompatible);
        }
        match fact {
            Self::Title => into.title = <Option<String> as Durable>::take(&mut d)?,
            Self::FirstPrompt => {
                into.first_prompt_material = <Option<String> as Durable>::take(&mut d)?;
                into.first_prompt_title = <Option<String> as Durable>::take(&mut d)?;
            }
            Self::Workspace => into.workspace_path = <Option<PathBuf> as Durable>::take(&mut d)?,
            Self::OpeningSettings => into.session_start.take_opening_fact(&mut d)?,
        }
        d.finish()?;
        // A stored slot holds its fact: an empty one is corrupt.
        if fact.present(into) {
            Ok(())
        } else {
            Err(ReconstructCause::Corrupt)
        }
    }
}

// Artifacts are head data: collected whatever the upload toggle says, and
// filtered only when an item is built.
crate::durable_tail_codec::durable_struct!(SessionArtifact {
    U kind: String,
    U value: String,
});

macro_rules! head_fields {
    ($($c:ident $f:ident : $ty:ty),* $(,)?) => {
        fn put_fields(acc: &SnapshotAccumulator, e: &mut Enc<'_>) -> Result<(), Refuse> {
            let SnapshotAccumulator { $($f),* } = acc;
            $(durable_field!(put $c, e, $f, $ty, concat!("SnapshotAccumulator.", stringify!($f)));)*
            Ok(())
        }
        fn take_fields(d: &mut Dec<'_>) -> Result<SnapshotAccumulator, Corrupt> {
            Ok(SnapshotAccumulator { $($f: durable_field!(take $c, d, $ty)),* })
        }
    };
}
// Every accumulator field, by its Tail home. Stored fields keep their record
// class, except that skill labels are plain data and the fork parent and
// artifacts are stored. `I` marks a field kept elsewhere: pages (responses,
// tool uses, changed files, capability buckets, compactions), finish-only
// fields (usage ids and occurrences, money, cache observations and requests,
// usage buckets and totals), live fields (Desktop identity and spawn lineage,
// account hash) and the Pi ledger. `X` fields are session facts, except the
// Codex agent label, which a Claude parse never sets.
head_fields! {
    N source: SnapshotSource,
    H cache_configuration_witness: Option<String>,
    N cache_task_complete_at: Option<String>,
    N cache_pending_idle: Option<u64>,
    L cache_active_turns: BTreeSet<String>,
    N context_curve_enabled: bool,
    U source_session_id: Option<String>,
    I account_identifier_hash: Option<String>,
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
    L codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
    N codex_priority_witnesses_uncapped: bool,
    E codex_tier_replay: Option<codex_file_join::TierReplay>,
    D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
    D current_selector: SelectorCapture,
    I session_cumulative_usage: Option<UsageTotals>,
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
    E codex_parent_signatures: Option<CodexParentPrefix>,
    H codex_parent_prefix_digest: PrefixDigest,
    D codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
    E codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
    E codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    N codex_parent_proof_mismatch: bool,
    E codex_parent_proof_refusal: Option<ProofRefusal>,
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
    H codex_physical_signatures: crate::owned_heap::OwnedVec<String>,
    N codex_physical_signatures_complete: bool,
    N codex_ordinal_expected: Option<u64>,
    N codex_ordinal_sequence_valid: bool,
    N codex_owned_record_seen: bool,
    N codex_is_fork: bool,
    N codex_inherited_usage_records_skipped: u64,
    N codex_duplicate_usage_records_skipped: u64,
    N codex_cumulative_reset_count: u64,
    D codex_context_curve_candidates: crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    D codex_context_curve_boundaries: crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    N codex_context_curve_exact_supported: bool,
    H codex_last_usage_event_identity: Option<String>,
    E codex_legacy_bootstrap_buffer: Vec<Value>,
    I accepted_usage_totals: UsageTotals,
    I usage_buckets: BTreeMap<String, UsageBucketState>,
    D origin: SnapshotOrigin,
    U codex_root_session_ref: Option<String>,
    N codex_spawn_depth: Option<u64>,
    X codex_agent_label: Option<String>,
    U activity_tool_counts: BTreeMap<String, u64>,
    D activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
    U activity_mcp_tool_counts: BTreeMap<String, u64>,
    U activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
    L activity_mcp_call_ids: BTreeMap<String, bool>,
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
    D claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    I cache_observations: Option<CacheObservations>,
    I cache_requests: crate::owned_heap::OwnedVec<OwnedRequest>,
    N cache_requests_complete: bool,
    N claude_context_curve_identity_complete: bool,
    N claude_context_curve_request_index_complete: bool,
    N claude_context_curve_owned_start_proven: bool,
    D claude_file_birth: ClaudeFileBirth,
    L claude_fork_parent: Option<String>,
    I claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    U tool_usage_counts: BTreeMap<String, u64>,
    N tool_usage_truncated: bool,
    I seen_pi_usage_keys: PiLedger,
    N dropped_usage_record_count: u64,
    N claude_last_user_ts: Option<String>,
    N peak_context_fill_tokens: u64,
    N first_turn_context_tokens: Option<u64>,
    N last_turn_context_tokens: Option<u64>,
    N first_turn_context_window_tokens: Option<u64>,
    N peak_context_fill_window_tokens: Option<u64>,
    N last_turn_context_window_tokens: Option<u64>,
    N compaction_count: u64,
    N compaction_timestamps: crate::owned_heap::OwnedVec<String>,
    D codex_compaction_sizes: CodexCompactionSizes,
    D local_context_points: LocalContextPoints,
    I claude_compaction_observations: crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    L claude_compaction_link_tip: Option<(u64, String)>,
    D session_start: Box<session_start::SessionStartState>,
}

/// The Claude Code source: a marker type, never a value.
pub(in crate::snapshots) enum Claude {}

impl TailSource for Claude {
    const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;
    const REDUCTION_REVISION: u32 = 1;

    fn collections() -> &'static [CollectionSpec] {
        &COLLECTIONS
    }

    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64 {
        (match collection {
            Collection::Responses => acc.claude_responses.values().len(),
            Collection::ToolUses => acc.seen_claude_capability_tool_uses.len(),
            Collection::ChangedFiles => acc.activity_changed_file_hashes.len(),
            Collection::CapabilityHours => acc.activity_capability_buckets.len(),
            Collection::Compactions => acc.claude_compaction_observations.len(),
            Collection::SessionFacts => FACTS.iter().filter(|fact| fact.present(acc)).count(),
            _ => 0,
        }) as u64
    }

    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str> {
        [
            (
                "claude_usage_request_ids",
                !acc.claude_usage_request_ids.is_empty(),
            ),
            (
                "claude_usage_occurrences",
                !acc.claude_usage_occurrences.is_empty(),
            ),
            ("claude_money", acc.claude_money.is_some()),
            ("cache_observations", acc.cache_observations.is_some()),
            ("cache_requests", !acc.cache_requests.is_empty()),
            ("usage_buckets", !acc.usage_buckets.is_empty()),
            (
                "accepted_usage_totals",
                acc.accepted_usage_totals != UsageTotals::default(),
            ),
            (
                "session_cumulative_usage",
                acc.session_cumulative_usage.is_some(),
            ),
            (
                "org_markers_home",
                acc.claude_org_markers
                    .as_ref()
                    .is_some_and(|markers| markers.home_bound()),
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
                "account_identifier_hash",
                acc.account_identifier_hash.is_some(),
            ),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    fn log_keys(acc: &SnapshotAccumulator, collection: Collection) -> Vec<&String> {
        match collection {
            Collection::ToolUses => acc.seen_claude_capability_tool_uses.keys().collect(),
            Collection::ChangedFiles => acc.activity_changed_file_hashes.iter().collect(),
            _ => Vec::new(),
        }
    }

    fn log_page(collection: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        match collection {
            Collection::ChangedFiles => page_bytes(keys.iter(), |hash, e| {
                hash.put_h(e, "SnapshotAccumulator.activity_changed_file_hashes")
            }),
            _ => page_bytes(keys.iter(), |id, e| id.put(e)),
        }
    }

    fn log_page_keys(
        collection: Collection,
        bytes: &[u8],
    ) -> Result<Vec<String>, ReconstructCause> {
        let mut keys = Vec::new();
        read_page(bytes, LOG_G, |d| {
            keys.push(match collection {
                Collection::ChangedFiles => String::take_h(d)?,
                _ => String::take(d)?,
            });
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
        if acc.codex_agent_label.is_some() {
            return Err(Refuse::NonEmpty("SnapshotAccumulator.codex_agent_label"));
        }
        let scalars = (
            view.recognized_usage_drop_count,
            view.positive_recognized_usage_count,
            view.positive_usage_evidence,
        );
        encode(|e| {
            // Opening-call file paths are content: the opening-settings fact
            // stores them by call id.
            e.with_moved_field("OpeningCall.files", |e| {
                id.put(e)?;
                certificate.put(e)?;
                view.report.put(e)?;
                scalars.put(e)?;
                acc.claude_responses.selectors.put(e)?;
                put_fields(acc, e)
            })
        })
    }

    fn encode_pages(
        acc: &SnapshotAccumulator,
        collection: Collection,
    ) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
        match collection {
            Collection::Responses => {
                let book = &acc.claude_responses;
                let entries: Vec<_> = book.slot_keys().into_iter().zip(book.values()).collect();
                fixed_pages(&entries, RESPONSES_G, |(key, response), e| {
                    e.len_prefixed(key.as_bytes())?;
                    response.put(e)
                })
            }
            Collection::ToolUses | Collection::ChangedFiles => Self::log_keys(acc, collection)
                .chunks(LOG_G as usize)
                .enumerate()
                .map(|(page, keys)| Ok((page as u64, Self::log_page(collection, keys)?)))
                .collect(),
            Collection::CapabilityHours => {
                let mut hours: BTreeMap<u64, Vec<_>> = BTreeMap::new();
                for (key, count) in &acc.activity_capability_buckets {
                    hours
                        .entry(hour_page(&key.0))
                        .or_default()
                        .push((key, count));
                }
                hours
                    .into_iter()
                    .map(|(hour, entries)| {
                        let bytes = page_bytes(entries.iter(), |(key, count), e| {
                            key.put(e)?;
                            count.put(e)
                        })?;
                        Ok((hour, bytes))
                    })
                    .collect()
            }
            Collection::Compactions => fixed_pages(
                &acc.claude_compaction_observations,
                COMPACTIONS_G,
                |observation, e| observation.put(e),
            ),
            Collection::SessionFacts => FACTS
                .into_iter()
                .filter(|fact| fact.present(acc))
                .map(|fact| Ok((fact as u64, encode(|e| fact.put(acc, e))?)))
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
        let selectors = ClaudeSelectorTable::take(&mut d)?;
        let mut acc = take_fields(&mut d)?;
        d.finish()?;
        acc.claude_responses.selectors = selectors;
        *into = acc;
        Ok(DecodedHead {
            certificate,
            report,
            scalars,
        })
    }

    fn decode_page(
        collection: Collection,
        page: u64,
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause> {
        match collection {
            Collection::Responses => {
                let book = &mut into.claude_responses;
                slot_start(page, RESPONSES_G, book.values().len())?;
                read_page(bytes, RESPONSES_G, |d| {
                    let key = String::take(d)?;
                    let response = ClaudeResponseObservation::take(d)?;
                    if book.get_mut(&key).is_some() || !book.insert(key, response) {
                        return Err(ReconstructCause::Corrupt);
                    }
                    Ok(())
                })
            }
            Collection::ToolUses => read_page(bytes, LOG_G, |d| {
                let id = String::take(d)?;
                match into.seen_claude_capability_tool_uses.insert(id, ()) {
                    None => Ok(()),
                    Some(()) => Err(ReconstructCause::Corrupt),
                }
            }),
            Collection::ChangedFiles => read_page(bytes, LOG_G, |d| {
                if into.activity_changed_file_hashes.insert(String::take_h(d)?) {
                    Ok(())
                } else {
                    Err(ReconstructCause::Corrupt)
                }
            }),
            Collection::CapabilityHours => read_page(bytes, 0, |d| {
                let key = <(String, String, String)>::take(d)?;
                let count = u64::take(d)?;
                if hour_page(&key.0) != page
                    || into
                        .activity_capability_buckets
                        .insert(key, count)
                        .is_some()
                {
                    return Err(ReconstructCause::Corrupt);
                }
                Ok(())
            }),
            Collection::Compactions => {
                let observations = &mut into.claude_compaction_observations;
                slot_start(page, COMPACTIONS_G, observations.len())?;
                read_page(bytes, COMPACTIONS_G, |d| {
                    observations.push(ClaudeCompactionObservation::take(d)?);
                    Ok(())
                })
            }
            Collection::SessionFacts => Fact::take(page, bytes, into),
            _ => Err(ReconstructCause::Corrupt),
        }
    }

    /// Request boundaries and marker order: response sequences rise by slot
    /// and stay below the file's response count, and every marker or
    /// compaction position is at most that count.
    fn facts(acc: &SnapshotAccumulator) -> Result<(), ReconstructCause> {
        let total = acc.claude_response_sequence;
        let mut next = 0;
        for response in acc.claude_responses.values() {
            if response.sequence < next || response.sequence >= total {
                return Err(ReconstructCause::Corrupt);
            }
            next = response.sequence + 1;
        }
        let markers_in_order = match acc.claude_org_markers.as_ref() {
            Some(markers) => markers.positions().all(|position| position <= total),
            None => true,
        };
        let compactions_in_order = acc
            .claude_compaction_observations
            .iter()
            .all(|observation| observation.response_count_before <= total);
        if markers_in_order && compactions_in_order {
            Ok(())
        } else {
            Err(ReconstructCause::Corrupt)
        }
    }
}

/// An hourly bucket's page: its hour since the epoch. A start that does not
/// parse (the parser never writes one) shares the last page.
fn hour_page(bucket_start: &str) -> u64 {
    OffsetDateTime::parse(bucket_start, &Rfc3339).map_or(u64::MAX, |start| {
        start.unix_timestamp().div_euclid(3600) as u64
    })
}

#[cfg(test)]
#[path = "claude_tests.rs"]
pub(super) mod tests;
