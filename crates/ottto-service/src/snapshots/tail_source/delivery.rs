//! Delivery custody, never an accepted-history replay. Bodies are rebuilt by
//! the ordinary S2 loader/finalizer; only exact effective-body ACKs retire debt.
//! A source deleted or rewritten before retry can lose its unsent revision.
//! Deletion keeps the obligation visible; neither absence nor age settles it.
use super::*;

fn source(index: &ScanIndex) -> Option<SnapshotSource> {
    let path = state_v2::runtime_path(index).ok()??;
    Some(
        scan_index_integration::scan_index_storage_binding(&path)?
            .source
            .snapshot(),
    )
}

fn head(index: &ScanIndex, key: &str) -> Option<state_v2::TailHead> {
    let revision = reduction_revision(source(index)?)?;
    state_v2::load_head(index, key, revision).ok()?
}

pub(in crate::snapshots) fn owed(index: &ScanIndex, key: &str) -> bool {
    head(index, key).is_some_and(|head| {
        head.common.debt.reason_bits & state_v2::reason_bits::DELIVERY_DEBT != 0
    })
}

/// The debt gate: only retry_pending, never a dormant hold, and never during
/// upload backoff. No policy/context/receipt absence grants this retry.
pub(in crate::snapshots) fn retry_pending(index: &ScanIndex, key: &str) -> bool {
    let Some(source) = source(index) else {
        return false;
    };
    let Some(head) = head(index, key) else {
        return false;
    };
    head.common.debt.reason_bits & state_v2::reason_bits::DELIVERY_DEBT != 0
        && !head.metadata_only
        && Some(head.revision) == reduction_revision(source)
        && crate::snapshot_sync::source_upload_backoff_remaining(source).is_none()
        && !index.decode_holds_file(key)
        && !index.claude_account_deferred_holds.contains_key(key)
        && !load::set_aside(index, key)
        && !claude_index_path_family_member(Path::new(key))
            .is_some_and(|(root, _)| index.claude_usage_authority_quarantine.contains_key(&root))
        && index
            .file_snapshot_fingerprints
            .get(key)
            .into_iter()
            .flatten()
            .all(|fp| {
                index
                    .quarantined_snapshot_fingerprints
                    .get(fp)
                    .map_or(true, |record| {
                        record.disposition == SnapshotQuarantineDisposition::RetryPending
                            && index.quarantine_retry_selects_file(fp, key)
                    })
            })
}

/// One pass's delivery custody, before its save (D177). A failed or shed
/// publish owes every file whose bodies lack an exact ACK; an exact ACK of
/// every incident entity's effective body retires the debt. Deferred and
/// rejected bodies keep their own quarantine retry.
pub(in crate::snapshots) fn settle(
    source: SnapshotSource,
    index: &ScanIndex,
    snapshots: &[SnapshotItem],
    accepted: &BTreeMap<String, String>,
    failed: bool,
) {
    if tail_route(source, index).is_none() || snapshots.is_empty() {
        return;
    }
    let bodies = snapshots
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (key, entities) in index.file_snapshot_fingerprints.iter() {
        let incident = entities
            .iter()
            .filter_map(|fp| bodies.get(fp.as_str()).map(|body| (fp, body)))
            .collect::<Vec<_>>();
        if incident.is_empty() {
            continue;
        }
        let exact = incident
            .iter()
            .all(|(fp, body)| accepted.get(fp.as_str()) == Some(*body));
        if !exact && failed {
            let _ = state_v2::tail_delivery(index, key, true);
        } else if exact && owed(index, key) {
            let _ = state_v2::tail_delivery(index, key, false);
        }
    }
}

/// Periodic wake independent of file changes, outside the watcher hint cap.
/// Reuse the ordinary queue and its acquisition checks; deleted paths stay
/// owed in the head and alarm instead of turning into a repeated failed open.
pub(in crate::snapshots) fn wake(source: SnapshotSource, index: &mut ScanIndex) {
    if tail_route(source, index).is_none() {
        return;
    }
    let Ok(keys) = state_v2::tail_head_keys(index) else {
        return;
    };
    let (mut owed_files, mut deleted_files, mut oldest_age_s, mut unknown_age) =
        (0_u64, 0_u64, 0_u64, false);
    let now = sampled_scan::now_seconds();
    for key in keys {
        let Some(head) = head(index, &key) else {
            continue;
        };
        if head.common.debt.reason_bits & state_v2::reason_bits::DELIVERY_DEBT == 0 {
            continue;
        }
        owed_files += 1;
        if let Some(at) = head.common.debt.earliest_unacked_change_at {
            oldest_age_s = oldest_age_s.max(now.saturating_sub(at / 1000));
        } else {
            unknown_age = true;
        }
        let path = Path::new(&key);
        if fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            deleted_files += 1;
            continue;
        }
        if !retry_pending(index, &key) {
            continue;
        }
        let Some(traversal) = index.traversal.as_mut() else {
            continue;
        };
        if traversal
            .pending_candidates
            .iter()
            .any(|queued| queued.path == path)
        {
            continue;
        }
        if let Some(root) = traversal
            .scan_roots
            .iter()
            .find(|root| path.starts_with(root))
            .cloned()
        {
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root: root,
                path: path.to_owned(),
                census_member: true,
                watcher_hint: false,
            });
        }
    }
    crate::local_resource_diagnostics::traversal_point(
        "freshness_alarm",
        source.api_slug(),
        &serde_json::json!({
            "basis": "delivery_debt", "reason_bits": state_v2::reason_bits::DELIVERY_DEBT,
            "outstanding_files": owed_files, "deleted_unaccepted_files": deleted_files,
            "oldest_age_s": oldest_age_s, "oldest_age_lower_bound": unknown_age,
            "alarm": deleted_files > 0 || unknown_age || oldest_age_s > 6 * 60 * 60,
        }),
    );
}

#[cfg(test)]
#[path = "delivery_tests.rs"]
mod tests;
