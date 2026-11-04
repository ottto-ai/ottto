//! The Pi Tail codec.
//!
//! Head: the identity, the checkpoint certificate, the read report and the
//! three reduction scalars, every accumulator field stored by its class, then
//! Pi's trailer: the accepted usage totals and the fork state. Pages: the
//! usage dedup ledger (a key and its state, in key order), the hourly usage
//! buckets and the shared session facts. Pi parses its usage at read time, so
//! its buckets and totals are stored, unlike Claude's finish-only ones. The
//! header line is inside the certificate's head sample, so a changed header
//! fails the certificate and reads Full.
use super::{
    decode_envelope, encode_envelope, fact_count, fact_pages, fixed_pages, hour, hour_pages,
    read_fact_page, read_hour_page, read_page, slot, slot_start, CollectionSpec, DecodedHead,
    HeadIdentity, ReconstructCause, TailSource, SESSION_FACTS,
};
use crate::durable_tail_codec::{Durable, HDigest, Refuse};
use crate::snapshots::state_v2::Collection;
use crate::snapshots::*;
use crate::transcript_acquisition::DurableCertificate;

const USAGE_KEYS_G: u32 = 256;

const COLLECTIONS: [CollectionSpec; 3] = [
    // A pairing changes an older key's state, so the ledger is a `Slot`, not
    // an append-only `Log`: a changed page restates, an unchanged one never.
    slot(Collection::PiUsageKeys, USAGE_KEYS_G),
    hour(Collection::UsageHours),
    SESSION_FACTS,
];

/// The Pi source: a marker type, never a value.
pub(in crate::snapshots) enum Pi {}

impl TailSource for Pi {
    const SOURCE: SnapshotSource = SnapshotSource::Pi;
    const REDUCTION_REVISION: u32 = 1;
    const USAGE_BEFORE_FINISH: bool = true;

    fn collections() -> &'static [CollectionSpec] {
        &COLLECTIONS
    }

    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64 {
        (match collection {
            Collection::PiUsageKeys => acc.seen_pi_usage_keys.usage_keys().len(),
            Collection::UsageHours => acc.usage_buckets.len(),
            Collection::SessionFacts => fact_count(acc),
            _ => 0,
        }) as u64
    }

    /// A Pi parse sets only the `I` fields this codec stores (the usage
    /// ledger, the hourly buckets and the accepted totals), and Pi has no
    /// live input, so no finish-only or live field can be set at the seam.
    fn finish_field_nonempty(_acc: &SnapshotAccumulator) -> Option<&'static str> {
        None
    }

    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse> {
        let acc = view.accumulator;
        let fork = acc.seen_pi_usage_keys.fork_parts();
        encode_envelope(
            view,
            certificate,
            id,
            |_| Ok(()),
            |e| {
                acc.accepted_usage_totals.put(e)?;
                fork.put(e)
            },
        )
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
            Collection::SessionFacts => fact_pages(acc),
            _ => Ok(Vec::new()),
        }
    }

    fn decode_head(
        revision: u32,
        head: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<DecodedHead, ReconstructCause> {
        let (mut acc, (), (accepted, (has_parent, header_nanos)), decoded) =
            decode_envelope::<Self, _, _>(
                revision,
                head,
                |_| Ok(()),
                |d| Ok((UsageTotals::take(d)?, <(bool, Option<i128>)>::take(d)?)),
            )?;
        // Only a header that names a parent records its time.
        if !has_parent && header_nanos.is_some() {
            return Err(ReconstructCause::Corrupt);
        }
        acc.accepted_usage_totals = accepted;
        acc.seen_pi_usage_keys = PiLedger::from_parts(BTreeMap::new(), has_parent, header_nanos);
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
            Collection::SessionFacts => read_fact_page(page, bytes, into),
            _ => Err(ReconstructCause::Corrupt),
        }
    }

    /// Every ledger key holds a recorded occurrence or a pair, and every
    /// unmatched count is positive: the reducer removes a digest whose count
    /// reaches zero and never leaves a key with an empty state.
    fn facts(acc: &SnapshotAccumulator) -> Result<(), ReconstructCause> {
        let broken = acc.seen_pi_usage_keys.usage_keys().values().any(|state| {
            (state.message.is_empty()
                && state.message_end.is_empty()
                && state.paired_digests.is_empty())
                || state
                    .message
                    .values()
                    .chain(state.message_end.values())
                    .any(|count| *count == 0)
        });
        if broken {
            Err(ReconstructCause::Corrupt)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "pi_tests.rs"]
mod tests;
