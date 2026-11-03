//! D177 delivery custody, never acceptance: G7 `reason_bits` bit 8 beside the
//! Tail cursor; a retry re-folds from S2 as late evidence. Absence never clears.
use super::*;
use crate::snapshots::state_v2::reason_bits::DELIVERY_DEBT;

fn head(index: &ScanIndex, key: &str) -> Option<(SnapshotSource, state_v2::TailHead)> {
    let path = state_v2::runtime_path(index).ok()??;
    let source = scan_index_integration::scan_index_storage_binding(&path)?.source;
    let source = source.snapshot();
    let head = state_v2::load_head(index, key, reduction_revision(source)?).ok()??;
    Some((source, head))
}

/// The retry gate: a loadable owed head, no upload backoff, no hold (D152a).
pub(in crate::snapshots) fn retry_pending(index: &ScanIndex, key: &str) -> bool {
    let quarantined = |fps: &BTreeSet<String>| {
        fps.iter()
            .any(|fp| index.quarantined_snapshot_fingerprints.contains_key(fp))
    };
    let family = claude_index_path_family_member(Path::new(key));
    head(index, key).is_some_and(|(source, head)| {
        head.common.debt.reason_bits & DELIVERY_DEBT != 0
            && !head.metadata_only
            && crate::snapshot_sync::source_upload_backoff_remaining(source).is_none()
    }) && !index.claude_account_deferred_holds.contains_key(key)
        && !load::set_aside(index, key)
        && !family
            .is_some_and(|(root, _)| index.claude_usage_authority_quarantine.contains_key(&root))
        && !index
            .file_snapshot_fingerprints
            .get(key)
            .is_some_and(quarantined)
}

/// Staged with the file's next save, beside its cursor; a file with no cursor
/// keeps no head, so owes nothing. Other G7 bits stay as written.
fn mark(route: &Path, index: &ScanIndex, key: &str, owe: bool) {
    let mut summary = head(index, key)
        .map(|(_, h)| h.common.debt)
        .unwrap_or_default();
    if (summary.reason_bits & DELIVERY_DEBT != 0) != owe {
        summary.reason_bits ^= DELIVERY_DEBT;
        let now = sampled_scan::now_seconds().saturating_mul(1000);
        let at = summary.earliest_unacked_change_at.unwrap_or(now);
        summary.earliest_unacked_change_at = (summary.reason_bits != 0).then_some(at);
        let observation = state_v2::Observation {
            summary,
            ..Default::default()
        };
        let _ = state_v2::observe_tail(route, key, observation);
    }
}

/// One pass's custody, before its save: a failed or shed publish owes each
/// file whose incident bodies lack an exact ACK; an exact ACK of every incident
/// body clears it. Deferred and rejected bodies keep their quarantine retry.
pub(crate) fn settle(
    source: SnapshotSource,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    accepted: &BTreeMap<String, String>,
    failed: bool,
) {
    let Some(route) = tail_route(source, index) else {
        return;
    };
    let bodies: BTreeMap<_, _> = snapshots
        .iter()
        .map(|it| (&it.snapshot_fingerprint, snapshot_upload_body_witness(it)))
        .collect();
    for (key, entities) in &index.file_snapshot_fingerprints {
        let mut incident = entities
            .iter()
            .filter_map(|fp| Some((fp, bodies.get(fp)?)))
            .peekable();
        if incident.peek().is_some() {
            let exact = incident.all(|(fp, body)| accepted.get(fp) == Some(body));
            if failed || exact {
                mark(&route, index, key, !exact);
            }
        }
    }
}

/// Every page, independent of file change: requeue retry-pending files through
/// the ordinary F5 path. A deleted file waits for its census retirement.
pub(in crate::snapshots) fn wake(source: SnapshotSource, index: &mut ScanIndex) {
    let Some(keys) = tail_route(source, index).and_then(|_| state_v2::tail_head_keys(index).ok())
    else {
        return;
    };
    let keys = keys
        .into_iter()
        .filter(|key| retry_pending(index, key) && Path::new(key).is_file())
        .collect();
    if let Some(traversal) = index.traversal.as_mut() {
        requeue_observed_keys(source, traversal, keys, "delivery_debt");
    }
}

#[cfg(test)]
#[path = "delivery_tests.rs"]
pub(in crate::snapshots) mod tests;
