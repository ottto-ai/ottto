//! The Codex Tail codec.
//!
//! Head: the shared head envelope (`encode_envelope`: the identity, the
//! checkpoint certificate, the read report, the three reduction scalars and
//! the shared field walk), with no lead and the Codex trailer. The trailer
//! holds the
//! walk's `I` fields Codex keeps in its head: whether priority decisions
//! exist, the parse-time totals (head state on Codex, not finish output), the
//! retired parent-proof slots, and the sidecar's projected ordinal this
//! head was made under. Pages: the four dictionaries in
//! stable slots (tombstones for the three that remove), the physical
//! retired signatures, the cache requests, the compaction timestamps, the usage and
//! capability hours through the shared hour codec, the changed-file hashes,
//! and the shared session facts (title, first prompt, workspace, opening
//! settings, agent label, prelude), so content never re-derives. Live fields come from this read's inputs through `install_live`;
//! foreign and finish-only fields stay empty at the seam.
use super::{
    decode_envelope, encode_envelope, fixed_pages, hour, hour_pages, read_hour_page, read_page,
    read_shared_page, read_slot_vec, shared_elements, shared_pages, slot, slot_start,
    CollectionSpec, DecodedHead, HeadIdentity, LiveLoadError, ReconstructCause, TailSource,
    CHANGED_FILES, SESSION_FACTS,
};
use crate::durable_tail_codec::{durable_struct, Durable, HDigest, Refuse};
use crate::snapshots::codex_dictionary_slots::{CodexCountMap, StableSlots};
use crate::snapshots::sampled_scan::codex_cursor::{priority_decisions, PriorityDecisions};
use crate::snapshots::state_v2::Collection;
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const DICTIONARY_G: u32 = 64;
const PRIORITY_G: u32 = 256;
const SIGNATURES_G: u32 = 256;
const REQUESTS_G: u32 = 64;
const COMPACTIONS_G: u32 = 64;
const SLOTS_FIELD: &str = "SnapshotAccumulator.codex_dictionary_slots";

const COLLECTIONS: [CollectionSpec; 11] = [
    slot(Collection::CodexActiveTurns, DICTIONARY_G),
    slot(Collection::CodexOpenCalls, DICTIONARY_G),
    slot(Collection::CodexNameCounts, DICTIONARY_G),
    slot(Collection::PriorityTurns, PRIORITY_G),
    slot(Collection::Signatures, SIGNATURES_G),
    slot(Collection::Requests, REQUESTS_G),
    slot(Collection::Compactions, COMPACTIONS_G),
    hour(Collection::UsageHours),
    hour(Collection::CapabilityHours),
    CHANGED_FILES,
    SESSION_FACTS,
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

/// One priority decision, in its turn's first-seen slot. Decisions only
/// insert, so no slot is ever a tombstone.
struct CodexPriorityTurn {
    turn_id: String,
    priority: bool,
}
durable_struct!(CodexPriorityTurn {
    L turn_id: String,
    N priority: bool,
});

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
        && acc
            .codex_observed_priority_turns
            .as_ref()
            .map_or(true, |observed| {
                observed.len() == slots.priority_turns.len()
                    && observed
                        .keys()
                        .all(|turn| slots.priority_turns.contains(turn))
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
    /// Codex accepts usage while it reads: the trailer stores the totals.
    const USAGE_BEFORE_FINISH: bool = true;

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
                .map_or(0, |_| slots.priority_turns.len()),
            Collection::Signatures => 0,
            Collection::Requests => acc.cache_requests.len(),
            Collection::Compactions => acc.compaction_timestamps.len(),
            Collection::UsageHours => acc.usage_buckets.len(),
            _ => shared_elements(acc, collection),
        }) as u64
    }

    /// The walk's `I` fields Codex never stores: the account hash (joined at
    /// finish), and Claude's and Pi's fields. The shared walk already refuses
    /// a non-empty bootstrap buffer (`E`). Parse-time totals,
    /// usage buckets and cache requests are ordinary Codex state, not on this
    /// list; the live fields are this read's, installed by `install_live`.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str> {
        [
            (
                "account_identifier_hash",
                acc.account_identifier_hash.is_some(),
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
            ("claude_money", acc.claude_money.is_some()),
            ("cache_observations", acc.cache_observations.is_some()),
            ("seen_pi_usage_keys", !acc.seen_pi_usage_keys.is_empty()),
            (
                "claude_compaction_observations",
                !acc.claude_compaction_observations.is_empty(),
            ),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse> {
        let acc = view.accumulator;
        if !slots_cover_live_maps(acc) {
            return Err(Refuse::NonEmpty(SLOTS_FIELD));
        }
        let trailer = Trailer::of(acc);
        encode_envelope(view, certificate, id, |_| Ok(()), |e| trailer.put(e))
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
                let Some(observed) = acc.codex_observed_priority_turns.as_ref() else {
                    return Ok(Vec::new());
                };
                let turns = slots
                    .priority_turns
                    .ordered()
                    .into_iter()
                    .map(|turn| {
                        Ok(CodexPriorityTurn {
                            turn_id: turn.clone(),
                            priority: *observed.get(turn).ok_or(Refuse::NonEmpty(SLOTS_FIELD))?,
                        })
                    })
                    .collect::<Result<Vec<_>, Refuse>>()?;
                fixed_pages(&turns, PRIORITY_G, |turn, e| turn.put(e))
            }
            Collection::Signatures => Ok(Vec::new()),
            Collection::Requests => {
                fixed_pages(&acc.cache_requests, REQUESTS_G, |request, e| request.put(e))
            }
            // A compaction's timestamp, one slot per append and duplicate.
            // Sizes live in the head and are never zipped to these slots.
            Collection::Compactions => {
                fixed_pages(&acc.compaction_timestamps, COMPACTIONS_G, |at, e| at.put(e))
            }
            Collection::UsageHours => hour_pages(&acc.usage_buckets, String::as_str),
            _ => shared_pages::<Self>(acc, collection),
        }
    }

    fn decode_head(
        revision: u32,
        head: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<DecodedHead, ReconstructCause> {
        let (mut acc, (), trailer, decoded) =
            decode_envelope::<Self, _, _>(revision, head, |_| Ok(()), Trailer::take)?;
        if acc.source != Self::SOURCE {
            return Err(ReconstructCause::Corrupt);
        }
        trailer.restore(&mut acc);
        *into = acc;
        Ok(decoded)
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
                let slots = &mut into.codex_dictionary_slots.priority_turns;
                slot_start(page, PRIORITY_G, slots.len())?;
                read_page(bytes, PRIORITY_G, |d| {
                    let CodexPriorityTurn { turn_id, priority } = CodexPriorityTurn::take(d)?;
                    adopt(slots, turn_id.clone())?;
                    match turns.insert(turn_id, priority) {
                        None => Ok(()),
                        Some(_) => Err(ReconstructCause::Corrupt),
                    }
                })
            }
            Collection::Signatures => {
                // Retired pages remain decodable; their contents install no state.
                read_page(bytes, SIGNATURES_G, |d| {
                    let _ = String::take_h(d)?;
                    Ok(())
                })
            }
            Collection::Requests => {
                read_slot_vec(page, bytes, REQUESTS_G, &mut into.cache_requests)
            }
            Collection::Compactions => {
                read_slot_vec(page, bytes, COMPACTIONS_G, &mut into.compaction_timestamps)
            }
            Collection::UsageHours => {
                read_hour_page(page, bytes, &mut into.usage_buckets, String::as_str)
            }
            _ => read_shared_page(collection, page, bytes, into),
        }
    }

    /// The stored state continues only under this read's inputs, and each
    /// check either installs them or names why not: absent evidence holds the
    /// file (`Unavailable`), changed or incompatible evidence is a counted
    /// reconstruction. Never a silent success. In order: the counting rule,
    /// the priority decisions, the sidecar's projected ordinal; then the traces and file
    /// birth. Last, the file's lineage (D131): the stored head continues only
    /// the session its owning header named when it was written, so a header
    /// rewritten to another id is another file (a counted `Identity`
    /// reconstruction), and a header this read cannot read waits. A protected
    /// receipt and a group never reach a load (their replays are counted
    /// where they read); the tier replay is configured after the load, on
    /// the restored state.
    fn install_live(
        stored: &mut SnapshotAccumulator,
        fresh: &CandidateFile,
        live: &SnapshotAccumulator,
    ) -> Result<(), LiveLoadError> {
        let incompatible = LiveLoadError::Reconstruct(ReconstructCause::Incompatible);
        // The same dependency that invalidates the RAM reduction: ownership
        // classification/lineage changes require the existing counted Full.
        if stored.codex_sidecar_binding != live.codex_sidecar_binding {
            return Err(incompatible);
        }
        if !codex_counting_version::reusable(
            stored.codex_counting.as_deref(),
            live.codex_counting.as_deref(),
        ) {
            return Err(incompatible);
        }
        // A stored read that dropped its witnesses cannot show its decisions
        // still hold.
        let Some(observed) = stored.codex_observed_priority_turns.as_ref() else {
            return Err(incompatible);
        };
        match priority_decisions(observed, live.codex_turn_traces.as_ref()) {
            PriorityDecisions::Hold => {}
            PriorityDecisions::Unavailable => return Err(LiveLoadError::Unavailable),
            PriorityDecisions::Changed => return Err(incompatible),
        }
        // The projection only advances with the sidecar; a lower one is
        // another sidecar.
        match (
            stored.codex_sidecar_projected_next_ordinal,
            live.codex_sidecar_projected_next_ordinal,
        ) {
            (Some(_), None) => return Err(LiveLoadError::Unavailable),
            (Some(made_under), Some(now)) if now < made_under => return Err(incompatible),
            _ => {}
        }
        match crate::snapshots::codex_file_join::header_owner(fresh) {
            Ok(owner) if stored.codex_creator_header_id.as_deref() == Some(owner.as_str()) => {}
            Ok(_) => return Err(LiveLoadError::Reconstruct(ReconstructCause::Identity)),
            Err(_) => return Err(LiveLoadError::Unavailable),
        }
        stored.codex_sidecar_projected_next_ordinal = live.codex_sidecar_projected_next_ordinal;
        stored
            .claude_file_birth
            .refresh_opened(&live.claude_file_birth);
        stored.codex_turn_traces = live.codex_turn_traces.clone();
        Ok(())
    }
}

/// Decode-only compatibility for the retired trailer slots. No loaded value
/// reaches the accumulator; new heads write the original empty slots.
mod retired {
    use super::*;
    type WakeStamp = sampled_scan::codex_cursor::OpenStamp;
    pub(super) struct CodexParentPrefixProof {
        parent: String,
        parent_seal: crate::transcript_acquisition::PrefixSeal,
        matched: u64,
        child_digest: String,
        owned: bool,
        published: bool,
    }
    pub(super) enum ProofWake {
        Due,
        ParentChanged {
            parent: WakeStamp,
            child: WakeStamp,
        },
        ChildChanged {
            parent: WakeStamp,
            child: WakeStamp,
        },
        Rewritten {
            parent: Option<WakeStamp>,
            child: WakeStamp,
        },
        Census {
            matches: String,
            child: WakeStamp,
        },
        ParentHeld {
            parent_key: String,
            generation: u64,
            parent_entry: String,
            parent: WakeStamp,
            lineage: bool,
            needed_extent: u64,
        },
        Backoff,
    }
    pub(super) enum ProofRefusal {
        Identity(CodexParentUnresolvable),
        Side(ProofWake),
        Seal(crate::transcript_acquisition::FullReason),
        Decision,
    }
    crate::durable_tail_codec::durable_struct!(CodexParentPrefixProof {
        U parent: String,
        D parent_seal: crate::transcript_acquisition::PrefixSeal,
        N matched: u64,
        H child_digest: String,
        N owned: bool,
        N published: bool,
    });
    crate::durable_tail_codec::durable_enum!(ProofWake {
        0 => Due,
        1 => ParentChanged { D parent: WakeStamp, D child: WakeStamp },
        2 => ChildChanged { D parent: WakeStamp, D child: WakeStamp },
        3 => Rewritten { D parent: Option<WakeStamp>, D child: WakeStamp },
        4 => Census { N matches: String, D child: WakeStamp },
        5 => ParentHeld {
            N parent_key: String,
            N generation: u64,
            N parent_entry: String,
            D parent: WakeStamp,
            N lineage: bool,
            N needed_extent: u64,
        },
        6 => Backoff,
    });
    crate::durable_tail_codec::durable_enum!(ProofRefusal {
        0 => Identity(D reason: CodexParentUnresolvable),
        1 => Side(D wake: ProofWake),
        2 => Seal(D reason: crate::transcript_acquisition::FullReason),
        3 => Decision,
    });
}

use retired::{CodexParentPrefixProof, ProofRefusal};

/// The walk's `I` fields a Codex head keeps after the walk.
struct Trailer {
    priority_present: bool,
    session_cumulative_usage: Option<UsageTotals>,
    accepted_usage_totals: UsageTotals,
    codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    codex_parent_proof_refusal: Option<ProofRefusal>,
    codex_sidecar_projected_next_ordinal: Option<u64>,
    codex_sidecar_binding: Option<String>,
}
durable_struct!(Trailer {
    N priority_present: bool,
    D session_cumulative_usage: Option<UsageTotals>,
    D accepted_usage_totals: UsageTotals,
    D codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    D codex_parent_proof_refusal: Option<ProofRefusal>,
    N codex_sidecar_projected_next_ordinal: Option<u64>,
    H codex_sidecar_binding: Option<String>,
});
impl Trailer {
    fn of(acc: &SnapshotAccumulator) -> Self {
        Self {
            priority_present: acc.codex_observed_priority_turns.is_some(),
            session_cumulative_usage: acc.session_cumulative_usage.clone(),
            accepted_usage_totals: acc.accepted_usage_totals.clone(),
            codex_parent_proof_used: None,
            codex_parent_proof_refusal: None,
            codex_sidecar_projected_next_ordinal: acc.codex_sidecar_projected_next_ordinal,
            codex_sidecar_binding: acc.codex_sidecar_binding.clone(),
        }
    }
    fn restore(self, acc: &mut SnapshotAccumulator) {
        acc.codex_observed_priority_turns = self.priority_present.then(BTreeMap::new);
        acc.session_cumulative_usage = self.session_cumulative_usage;
        acc.accepted_usage_totals = self.accepted_usage_totals;
        acc.codex_sidecar_projected_next_ordinal = self.codex_sidecar_projected_next_ordinal;
        acc.codex_sidecar_binding = self.codex_sidecar_binding;
    }
}

/// The Codex-specific stored layout following the common head envelope.
#[cfg(test)]
pub(super) fn shape_layout(s: &mut crate::durable_tail_codec::Shape) {
    Trailer::shape(s);
    for spec in Codex::collections() {
        s.push(&format!(
            "{:?} {:?} g={}",
            spec.collection, spec.shape, spec.g
        ));
    }
    CodexActiveTurn::shape(s);
    CodexOpenCall::shape(s);
    CodexNameCount::shape(s);
    CodexPriorityTurn::shape(s);
    String::shape_h(s);
    OwnedRequest::shape(s);
    String::shape(s); // Compaction timestamps.
    UsageBucketState::shape(s);
    <(String, String, String)>::shape(s);
    u64::shape(s);
    String::shape_h(s); // Changed files.
    s.push(&format!("fact-version={}", super::FACT_VERSION));
    for fact in super::FACTS {
        s.push(&format!("fact-kind={}", fact as u64));
    }
    crate::codex_prelude_footprint::CodexPreludeParser::shape_fact(s);
}

#[cfg(test)]
#[path = "codex_tests.rs"]
pub(in crate::snapshots) mod tests;
