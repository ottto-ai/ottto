//! The Codex Tail codec.
//!
//! Head: the identity, the checkpoint certificate, the read report and the
//! three reduction scalars, the shared field walk (`put_fields`), the Codex
//! trailer, and the digests of the re-derived fields. The trailer holds the
//! walk's `I` fields Codex keeps in its head: whether priority decisions
//! exist, the parse-time totals (head state on Codex, not finish output), the
//! parent proof's use and refusal, and the sidecar's projected ordinal this
//! head was made under. Pages: the four dictionaries in
//! stable slots (tombstones for the three that remove), the physical
//! signatures, the cache requests, the compaction timestamps, the usage and
//! capability hours through the shared hour codec, and the changed-file
//! hashes. Live fields come from this read's inputs through `install_live`;
//! foreign and finish-only fields stay empty at the seam.
use super::{
    capability_hour, encode, fixed_pages, hour_pages, page_bytes, put_fields, read_hour_page,
    read_page, slot_start, take_fields, CollectionSpec, DecodedHead, HeadIdentity, LiveLoadError,
    ReconstructCause, TailSource,
};
use crate::durable_tail_codec::{
    durable_enum, durable_struct, Dec, Durable, DurableEmpty, HDigest, Refuse,
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
const SLOTS_FIELD: &str = "SnapshotAccumulator.codex_dictionary_slots";

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
            .is_none_or(|observed| {
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
            Collection::Signatures => acc.codex_physical_signatures.len(),
            Collection::Requests => acc.cache_requests.len(),
            Collection::Compactions => acc.compaction_timestamps.len(),
            Collection::UsageHours => acc.usage_buckets.len(),
            Collection::CapabilityHours => acc.activity_capability_buckets.len(),
            Collection::ChangedFiles => acc.activity_changed_file_hashes.len(),
            _ => 0,
        }) as u64
    }

    /// The walk's `I` fields Codex never stores: the bootstrap buffer (raw
    /// lines, which set the file aside while it holds any), the account hash
    /// (joined at finish), and Claude's and Pi's fields. Parse-time totals,
    /// usage buckets and cache requests are ordinary Codex state, not on this
    /// list; the live fields are this read's, installed by `install_live`.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str> {
        [
            (
                "codex_legacy_bootstrap_buffer",
                !acc.codex_legacy_bootstrap_buffer.is_empty(),
            ),
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
            (
                "seen_pi_usage_keys",
                !acc.seen_pi_usage_keys.durable_empty(),
            ),
            (
                "claude_compaction_observations",
                !acc.claude_compaction_observations.is_empty(),
            ),
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
            return Err(Refuse::NonEmpty(SLOTS_FIELD));
        }
        let rederive = rederive_digests(acc, u64::MAX, u64::MAX)?;
        let scalars = (
            view.recognized_usage_drop_count,
            view.positive_recognized_usage_count,
            view.positive_usage_evidence,
        );
        let trailer = Trailer::of(acc);
        encode(|e| {
            e.with_moved_field("OpeningCall.files", |e| {
                id.put(e)?;
                certificate.put(e)?;
                view.report.put(e)?;
                scalars.put(e)?;
                put_fields(acc, e)?;
                trailer.put(e)?;
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
            Collection::UsageHours => hour_pages(&acc.usage_buckets, String::as_str),
            Collection::CapabilityHours => {
                hour_pages(&acc.activity_capability_buckets, capability_hour)
            }
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
        let mut acc = take_fields(&mut d)?;
        let trailer = Trailer::take(&mut d)?;
        let rederive = Rederive::take(&mut d)?;
        d.finish()?;
        if acc.source != Self::SOURCE {
            return Err(ReconstructCause::Corrupt);
        }
        trailer.restore(&mut acc);
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
            Collection::UsageHours => {
                read_hour_page(page, bytes, &mut into.usage_buckets, String::as_str)
            }
            Collection::CapabilityHours => read_hour_page(
                page,
                bytes,
                &mut into.activity_capability_buckets,
                capability_hour,
            ),
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

    /// Codex stores no keyed field.
    fn key_epoch() -> Option<[u8; 32]> {
        None
    }

    /// The stored state continues only under this read's inputs, and each
    /// check either installs them or names why not: absent evidence holds the
    /// file (`Unavailable`), changed or incompatible evidence is a counted
    /// reconstruction. Never a silent success. In order: the counting rule,
    /// the priority decisions, the sidecar's projected ordinal, the parent
    /// evidence the stored boundary used; then the traces, ledgers and file
    /// birth. A protected receipt and a group never reach a load (their
    /// replays are counted where they read); the tier replay is configured
    /// after the load, on the restored state.
    fn install_live(
        stored: &mut SnapshotAccumulator,
        _fresh: &CandidateFile,
        live: &SnapshotAccumulator,
    ) -> Result<(), LiveLoadError> {
        let incompatible = LiveLoadError::Reconstruct(ReconstructCause::Incompatible);
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
        install_parent(stored, live)?;
        stored.codex_sidecar_projected_next_ordinal = live.codex_sidecar_projected_next_ordinal;
        stored
            .claude_file_birth
            .refresh_opened(&live.claude_file_birth);
        stored.codex_turn_traces = live.codex_turn_traces.clone();
        stored.codex_parent_ownership_ledgers = live.codex_parent_ownership_ledgers.clone();
        Ok(())
    }
}

/// The parent prefix the stored boundary used, from this read's evidence.
/// The prefix itself is live (never stored): a child still comparing against
/// its parent gets the same ledger or proof back, or none. A child before its
/// header takes this read's proof, as a fresh read would.
fn install_parent(
    stored: &mut SnapshotAccumulator,
    live: &SnapshotAccumulator,
) -> Result<(), LiveLoadError> {
    let incompatible = LiveLoadError::Reconstruct(ReconstructCause::Incompatible);
    let parent = stored.codex_parent_session_ref.as_deref();
    let ledger = parent.and_then(|parent| {
        live.codex_parent_ownership_ledgers
            .as_ref()
            .and_then(|ledgers| ledgers.lock().ok())
            .and_then(|ledgers| ledgers.get(parent).cloned())
    });
    let proof = live
        .codex_parent_prefix_proof
        .as_ref()
        .filter(|(proof, _)| parent == Some(proof.parent.as_str()));
    if stored.codex_ownership_boundary == CodexOwnershipBoundary::Undetermined {
        stored.codex_parent_prefix_proof = live.codex_parent_prefix_proof.clone();
        return Ok(());
    }
    if !stored.codex_parent_ledger_consulted {
        return Ok(());
    }
    // A proof job's ring is that job's alone.
    if stored.codex_proof_decision_only {
        return Err(incompatible);
    }
    let awaiting = stored.codex_ownership_boundary == CodexOwnershipBoundary::AwaitingParentPrefix;
    if let Some(identity) = stored.codex_parent_ledger_identity_used.as_deref() {
        let Some(ledger) = ledger.filter(|ledger| ledger.scan_complete) else {
            return Err(LiveLoadError::Unavailable);
        };
        if ledger.opened_object_identity != identity || ledger.signatures.is_empty() {
            return Err(incompatible);
        }
        if awaiting {
            stored.codex_parent_signatures = Some(CodexParentPrefix::Ledger(ledger.signatures));
        }
        return Ok(());
    }
    if let Some((used, _)) = stored.codex_parent_proof_used.as_ref() {
        let Some((fresh, digest)) = proof else {
            return Err(LiveLoadError::Unavailable);
        };
        if fresh != used {
            return Err(incompatible);
        }
        if awaiting {
            stored.codex_parent_signatures = Some(CodexParentPrefix::Proof {
                matched: used.matched,
                digest: *digest,
            });
        }
        return Ok(());
    }
    if awaiting {
        // Comparing against a parent prefix neither the ledger nor a proof
        // supplied contradicts the stored state.
        return Err(LiveLoadError::Reconstruct(ReconstructCause::Corrupt));
    }
    if stored.codex_parent_unresolvable.is_some() {
        // A witnessed-unusable parent: the fork stays absorbing, as stored.
        stored.codex_parent_signatures = Some(CodexParentPrefix::Ledger(Vec::new()));
        return Ok(());
    }
    if stored.codex_parent_resolution_pending() {
        // Evidence that has arrived since cures the child only from its start.
        return Err(if ledger.is_some() || proof.is_some() {
            incompatible
        } else {
            LiveLoadError::Unavailable
        });
    }
    Ok(())
}

/// The walk's `I` fields a Codex head keeps after the walk.
struct Trailer {
    priority_present: bool,
    session_cumulative_usage: Option<UsageTotals>,
    accepted_usage_totals: UsageTotals,
    codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    codex_parent_proof_refusal: Option<ProofRefusal>,
    codex_sidecar_projected_next_ordinal: Option<u64>,
}
durable_struct!(Trailer {
    N priority_present: bool,
    D session_cumulative_usage: Option<UsageTotals>,
    D accepted_usage_totals: UsageTotals,
    D codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    D codex_parent_proof_refusal: Option<ProofRefusal>,
    N codex_sidecar_projected_next_ordinal: Option<u64>,
});
impl Trailer {
    fn of(acc: &SnapshotAccumulator) -> Self {
        Self {
            priority_present: acc.codex_observed_priority_turns.is_some(),
            session_cumulative_usage: acc.session_cumulative_usage.clone(),
            accepted_usage_totals: acc.accepted_usage_totals.clone(),
            codex_parent_proof_used: acc.codex_parent_proof_used.clone(),
            codex_parent_proof_refusal: acc.codex_parent_proof_refusal.clone(),
            codex_sidecar_projected_next_ordinal: acc.codex_sidecar_projected_next_ordinal,
        }
    }
    fn restore(self, acc: &mut SnapshotAccumulator) {
        acc.codex_observed_priority_turns = self.priority_present.then(BTreeMap::new);
        acc.session_cumulative_usage = self.session_cumulative_usage;
        acc.accepted_usage_totals = self.accepted_usage_totals;
        acc.codex_parent_proof_used = self.codex_parent_proof_used;
        acc.codex_parent_proof_refusal = self.codex_parent_proof_refusal;
        acc.codex_sidecar_projected_next_ordinal = self.codex_sidecar_projected_next_ordinal;
    }
}

#[cfg(test)]
#[path = "codex_tests.rs"]
pub(in crate::snapshots) mod tests;
