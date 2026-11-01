//! Test entry to the settled-history cut (`apply_cut`).
use super::*;

/// `apply_with_accepted_for_test` through the settled-history cut: `cut` is
/// the capability's (`None` off), `segments` the sibling segment ledger.
pub(crate) fn apply_cut(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
    segments: &AcceptedBuckets,
    cut: Option<history_segments::Cut>,
) -> Result<Tagged, Ineligible> {
    apply_cut_held(item, contributions, accepted, segments, cut).0
}

/// `apply_cut`, with the sessions the cut held this pass.
pub(crate) fn apply_cut_held(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
    segments: &AcceptedBuckets,
    cut: Option<history_segments::Cut>,
) -> (Result<Tagged, Ineligible>, BTreeSet<String>) {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for c in contributions {
        grouping.add_at(
            &c.bucket_start,
            &c.row_key,
            &c.usage,
            c.identity.as_ref(),
            Some(&c.bucket_start),
        );
    }
    grouping.accepted_miss = accepted.miss_cause();
    let evidence = ScanEvidence::default()
        .with_accepted_buckets(Some(accepted))
        .with_history_segments(Some(segments), cut);
    let tagged = super::apply_cut(
        item,
        grouping,
        &evidence,
        accepted.get(&item.source_session_id),
        accepted.retained_enabled(),
        &mut Vec::new(),
    );
    (tagged, evidence.history_held.take())
}
