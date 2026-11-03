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
    capability_hour, encode, fact_count, fact_pages, fixed_pages, hour_pages, page_bytes,
    put_fields, read_fact_page, read_hour_page, read_page, slot_start, take_fields, CollectionSpec,
    DecodedHead, HeadIdentity, LiveLoadError, ReconstructCause, TailSource, SESSION_FACTS,
};
use crate::durable_tail_codec::{Dec, Durable, HDigest, Refuse};
use crate::snapshots::state_v2::{Collection, Shape as PageShape};
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const RESPONSES_G: u32 = 256;
const LOG_G: u32 = 256;
const COMPACTIONS_G: u32 = 64;

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
    SESSION_FACTS,
];

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
            Collection::SessionFacts => fact_count(acc),
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
            // Codex's paged, trailer and live fields: never set on Claude.
            ("codex_tier_replay", acc.codex_tier_replay.is_some()),
            (
                "codex_parent_signatures",
                acc.codex_parent_signatures.is_some(),
            ),
            (
                "codex_parent_prefix_proof",
                acc.codex_parent_prefix_proof.is_some(),
            ),
            (
                "codex_parent_proof_used",
                acc.codex_parent_proof_used.is_some(),
            ),
            (
                "codex_parent_proof_refusal",
                acc.codex_parent_proof_refusal.is_some(),
            ),
            ("cache_active_turns", !acc.cache_active_turns.is_empty()),
            (
                "codex_observed_priority_turns",
                acc.codex_observed_priority_turns.is_some(),
            ),
            (
                "codex_physical_signatures",
                !acc.codex_physical_signatures.is_empty(),
            ),
            ("activity_tool_counts", !acc.activity_tool_counts.is_empty()),
            ("activity_call_tools", !acc.activity_call_tools.is_empty()),
            (
                "activity_mcp_tool_counts",
                !acc.activity_mcp_tool_counts.is_empty(),
            ),
            (
                "activity_mcp_tool_usage_counts",
                !acc.activity_mcp_tool_usage_counts.is_empty(),
            ),
            (
                "activity_mcp_call_ids",
                !acc.activity_mcp_call_ids.is_empty(),
            ),
            (
                "compaction_timestamps",
                !acc.compaction_timestamps.is_empty(),
            ),
            (
                "codex_dictionary_slots",
                !acc.codex_dictionary_slots.is_empty(),
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
        // A Claude parse never holds the Codex prelude; its fact is Codex's.
        if acc.session_start.has_codex_prelude() {
            return Err(Refuse::NonEmpty("SessionStartState.codex_prelude"));
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
                hour_pages(&acc.activity_capability_buckets, capability_hour)
            }
            Collection::Compactions => fixed_pages(
                &acc.claude_compaction_observations,
                COMPACTIONS_G,
                |observation, e| observation.put(e),
            ),
            Collection::SessionFacts => fact_pages(acc),
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
            Collection::CapabilityHours => read_hour_page(
                page,
                bytes,
                &mut into.activity_capability_buckets,
                capability_hour,
            ),
            Collection::Compactions => {
                let observations = &mut into.claude_compaction_observations;
                slot_start(page, COMPACTIONS_G, observations.len())?;
                read_page(bytes, COMPACTIONS_G, |d| {
                    observations.push(ClaudeCompactionObservation::take(d)?);
                    Ok(())
                })
            }
            Collection::SessionFacts => read_fact_page(page, bytes, into),
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

    /// The one keyed field is the org markers' `session_context` digest,
    /// an HMAC under the attribution key (#1255).
    fn key_epoch() -> Option<[u8; 32]> {
        claude_request_identity::session_context_key_epoch()
    }

    /// Claude's live inputs (Desktop identity and lineage, account, sidecar
    /// evidence) join at finish, never into the stored state.
    fn install_live(
        _stored: &mut SnapshotAccumulator,
        _fresh: &CandidateFile,
        _live: &SnapshotAccumulator,
    ) -> Result<(), LiveLoadError> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "claude_tests.rs"]
pub(super) mod tests;
