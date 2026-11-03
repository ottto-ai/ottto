//! The Pi Tail codec.
//!
//! Head: the identity, the checkpoint certificate, the read report and the
//! three reduction scalars, every accumulator field stored by its class, the
//! digests of the re-derived fields, then Pi's trailer: the accepted usage
//! totals and the fork state. Pages: the usage dedup ledger (a key and its
//! state, in key order) and the hourly usage buckets. Pi parses its usage at
//! read time, so its buckets and totals are stored, unlike Claude's
//! finish-only ones. The header line is inside the certificate's head sample,
//! so a changed header fails the certificate and reads Full.
use super::{
    encode, fixed_pages, hour_pages, page_bytes, put_fields, read_hour_page, read_page, slot_start,
    take_fields, CollectionSpec, DecodedHead, HeadIdentity, LiveLoadError, ReconstructCause,
    TailSource,
};
use crate::durable_tail_codec::{Dec, Durable, HDigest, Refuse};
use crate::snapshots::sampled_jsonl::durable::{rederive_digests, Rederive};
use crate::snapshots::state_v2::{Collection, Shape as PageShape};
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const USAGE_KEYS_G: u32 = 256;

const COLLECTIONS: [CollectionSpec; 2] = [
    // A pairing changes an older key's state, so the ledger is a `Slot`, not
    // an append-only `Log`: a changed page restates, an unchanged one never.
    CollectionSpec {
        collection: Collection::PiUsageKeys,
        shape: PageShape::Slot,
        g: USAGE_KEYS_G,
        required: true,
    },
    CollectionSpec {
        collection: Collection::UsageHours,
        shape: PageShape::Hour,
        g: 0,
        required: true,
    },
];

/// The Pi source: a marker type, never a value.
pub(in crate::snapshots) enum Pi {}

impl TailSource for Pi {
    const SOURCE: SnapshotSource = SnapshotSource::Pi;
    const REDUCTION_REVISION: u32 = 1;

    fn collections() -> &'static [CollectionSpec] {
        &COLLECTIONS
    }

    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64 {
        (match collection {
            Collection::PiUsageKeys => acc.seen_pi_usage_keys.usage_keys().len(),
            Collection::UsageHours => acc.usage_buckets.len(),
            _ => 0,
        }) as u64
    }

    /// Every `I` field this codec does not store. Pi sets none of them at
    /// read time; one set here would be lost by a load.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str> {
        [
            (
                "account_identifier_hash",
                acc.account_identifier_hash.is_some(),
            ),
            ("codex_turn_traces", acc.codex_turn_traces.is_some()),
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
                "codex_parent_ownership_ledgers",
                acc.codex_parent_ownership_ledgers.is_some(),
            ),
            (
                "codex_sidecar_projected_next_ordinal",
                acc.codex_sidecar_projected_next_ordinal.is_some(),
            ),
            (
                "activity_capability_buckets",
                !acc.activity_capability_buckets.is_empty(),
            ),
            (
                "seen_claude_capability_tool_uses",
                !acc.seen_claude_capability_tool_uses.is_empty(),
            ),
            (
                "activity_changed_file_hashes",
                !acc.activity_changed_file_hashes.is_empty(),
            ),
            (
                "claude_responses",
                acc.claude_responses.values().next().is_some(),
            ),
            (
                "claude_usage_request_ids",
                !acc.claude_usage_request_ids.is_empty(),
            ),
            (
                "claude_usage_occurrences",
                !acc.claude_usage_occurrences.is_empty(),
            ),
            ("cache_observations", acc.cache_observations.is_some()),
            ("cache_requests", !acc.cache_requests.is_empty()),
            ("claude_money", acc.claude_money.is_some()),
            (
                "claude_compaction_observations",
                !acc.claude_compaction_observations.is_empty(),
            ),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    /// Pi has no `Log` collection.
    fn log_keys(_acc: &SnapshotAccumulator, _collection: Collection) -> Vec<&String> {
        Vec::new()
    }

    fn log_page(_collection: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        page_bytes(keys.iter(), |key, e| key.put(e))
    }

    fn log_page_keys(
        _collection: Collection,
        _bytes: &[u8],
    ) -> Result<Vec<String>, ReconstructCause> {
        Err(ReconstructCause::Corrupt)
    }

    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse> {
        let acc = view.accumulator;
        let rederive = rederive_digests(acc, u64::MAX, u64::MAX)?;
        let scalars = (
            view.recognized_usage_drop_count,
            view.positive_recognized_usage_count,
            view.positive_usage_evidence,
        );
        let fork = acc.seen_pi_usage_keys.fork_parts();
        encode(|e| {
            // Opening-call file paths are content: the session-start digest
            // covers them by call id and re-derivation restores them.
            e.with_moved_field("OpeningCall.files", |e| {
                id.put(e)?;
                certificate.put(e)?;
                view.report.put(e)?;
                scalars.put(e)?;
                put_fields(acc, e)?;
                rederive.put(e)?;
                acc.accepted_usage_totals.put(e)?;
                fork.put(e)
            })
        })
    }

    fn encode_pages(
        acc: &SnapshotAccumulator,
        collection: Collection,
    ) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
        match collection {
            Collection::PiUsageKeys => {
                let keys: Vec<_> = acc.seen_pi_usage_keys.usage_keys().iter().collect();
                fixed_pages(&keys, USAGE_KEYS_G, |(key, state), e| {
                    key.put_h(e, "SnapshotAccumulator.seen_pi_usage_keys")?;
                    state.put(e)
                })
            }
            Collection::UsageHours => hour_pages(&acc.usage_buckets, String::as_str),
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
        let rederive = Rederive::take(&mut d)?;
        let accepted = UsageTotals::take(&mut d)?;
        let (has_parent, header_nanos) = <(bool, Option<i128>)>::take(&mut d)?;
        d.finish()?;
        // Only a header that names a parent records its time.
        if !has_parent && header_nanos.is_some() {
            return Err(ReconstructCause::Corrupt);
        }
        acc.accepted_usage_totals = accepted;
        acc.seen_pi_usage_keys = PiLedger::from_parts(BTreeMap::new(), has_parent, header_nanos);
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
            Collection::PiUsageKeys => {
                let keys = into.seen_pi_usage_keys.usage_keys_mut();
                slot_start(page, USAGE_KEYS_G, keys.len())?;
                read_page(bytes, USAGE_KEYS_G, |d| {
                    let key = String::take_h(d)?;
                    let state = PiUsageDedupState::take(d)?;
                    // Pages hold the keys in ascending order, each once.
                    if keys.last_key_value().is_some_and(|(last, _)| *last >= key) {
                        return Err(ReconstructCause::Corrupt);
                    }
                    keys.insert(key, state);
                    Ok(())
                })
            }
            Collection::UsageHours => {
                read_hour_page(page, bytes, &mut into.usage_buckets, String::as_str)
            }
            _ => Err(ReconstructCause::Corrupt),
        }
    }

    /// Every ledger key holds a recorded occurrence or a pair: the reducer
    /// never leaves a key with an empty state.
    fn facts(acc: &SnapshotAccumulator) -> Result<(), ReconstructCause> {
        let empty = acc.seen_pi_usage_keys.usage_keys().values().any(|state| {
            state.message.is_empty()
                && state.message_end.is_empty()
                && state.paired_digests.is_empty()
        });
        if empty {
            Err(ReconstructCause::Corrupt)
        } else {
            Ok(())
        }
    }

    /// Pi stores no keyed field.
    fn key_epoch() -> Option<[u8; 32]> {
        None
    }

    /// Pi has no live input.
    fn install_live(
        _stored: &mut SnapshotAccumulator,
        _fresh: &CandidateFile,
    ) -> Result<(), LiveLoadError> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "pi_tests.rs"]
mod tests;
