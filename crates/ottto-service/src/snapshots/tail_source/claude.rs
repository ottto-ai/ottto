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
    capability_hour, changed_files, decode_envelope, encode_envelope, fact_count, fact_pages,
    fixed_pages, hour_pages, page_bytes, read_fact_page, read_hour_page, read_page, slot_start,
    CollectionSpec, DecodedHead, HeadIdentity, ReconstructCause, TailSource, SESSION_FACTS,
};
use crate::durable_tail_codec::{Durable, Refuse};
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
            Collection::ChangedFiles => changed_files::keys(acc),
            _ => Vec::new(),
        }
    }

    fn log_page(collection: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        match collection {
            Collection::ChangedFiles => changed_files::page(keys),
            _ => page_bytes(keys.iter(), |id, e| id.put(e)),
        }
    }

    fn log_page_keys(
        collection: Collection,
        bytes: &[u8],
    ) -> Result<Vec<String>, ReconstructCause> {
        if collection == Collection::ChangedFiles {
            return changed_files::page_keys(bytes);
        }
        let mut keys = Vec::new();
        read_page(bytes, LOG_G, |d| {
            keys.push(String::take(d)?);
            Ok(())
        })?;
        Ok(keys)
    }

    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse> {
        let selectors = &view.accumulator.claude_responses.selectors;
        encode_envelope(view, certificate, id, |e| selectors.put(e), |_| Ok(()))
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
            Collection::ToolUses => Self::log_keys(acc, collection)
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
            Collection::ChangedFiles => changed_files::encode(acc),
            Collection::SessionFacts => fact_pages(acc),
            _ => Ok(Vec::new()),
        }
    }

    fn decode_head(
        revision: u32,
        head: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<DecodedHead, ReconstructCause> {
        let (mut acc, selectors, (), decoded) =
            decode_envelope::<Self, _, _>(revision, head, ClaudeSelectorTable::take, |_| Ok(()))?;
        acc.claude_responses.selectors = selectors;
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
            Collection::ChangedFiles => changed_files::decode(bytes, into),
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
}

#[cfg(test)]
#[path = "claude_tests.rs"]
pub(super) mod tests;
