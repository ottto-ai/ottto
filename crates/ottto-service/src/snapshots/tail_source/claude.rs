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
    encode, fixed_pages, hour_pages, page_bytes, put_fields, read_hour_page, read_page, slot_start,
    take_fields, CollectionSpec, DecodedHead, HeadIdentity, LiveLoadError, ReconstructCause,
    TailSource,
};
use crate::durable_tail_codec::{Dec, Durable, Enc, HDigest, Refuse};
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
            // A path never enters a record body (`PathBuf` refuses outside
            // hashing); the workspace path is a parsed JSON string, stored so.
            Self::Workspace => acc
                .workspace_path
                .as_ref()
                .map(|path| {
                    path.to_str()
                        .map(str::to_owned)
                        .ok_or(Refuse::NonEmpty("SnapshotAccumulator.workspace_path"))
                })
                .transpose()?
                .put(e),
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
            Self::Workspace => {
                into.workspace_path = <Option<String> as Durable>::take(&mut d)?.map(PathBuf::from)
            }
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
                hour_pages(&acc.activity_capability_buckets, capability_hour)
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
    ) -> Result<(), LiveLoadError> {
        Ok(())
    }
}

/// A capability bucket's start: the first part of its key.
fn capability_hour(key: &(String, String, String)) -> &str {
    &key.0
}

#[cfg(test)]
#[path = "claude_tests.rs"]
pub(super) mod tests;
