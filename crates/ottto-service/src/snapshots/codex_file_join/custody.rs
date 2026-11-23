//! Existing combined-body custody and exact-revision recovery capture.
use super::*;

/// Bind the combined offer to every captured physical revision.
pub(in crate::snapshots) fn fan_out_body_witnesses(
    index: &ScanIndex,
    by_source_file: &mut BTreeMap<String, BTreeSet<String>>,
    by_source_file_body_witness: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let offered = index
        .files
        .values()
        .filter_map(|entry| {
            let marker = entry.codex_joined_member_set.as_ref()?;
            let entities = by_source_file.get(&entry.source_file_fingerprint)?;
            let bodies = by_source_file_body_witness.get(&entry.source_file_fingerprint)?;
            Some((marker.clone(), (entities.clone(), bodies.clone())))
        })
        .collect::<BTreeMap<_, _>>();
    for entry in index.files.values() {
        if let Some((entities, bodies)) = entry
            .codex_joined_member_set
            .as_ref()
            .and_then(|marker| offered.get(marker))
        {
            by_source_file
                .entry(entry.source_file_fingerprint.clone())
                .or_insert_with(|| entities.clone());
            by_source_file_body_witness
                .entry(entry.source_file_fingerprint.clone())
                .or_insert_with(|| bodies.clone());
        }
    }
}

/// The ACK-time twin of `fan_out_body_witnesses`: every joined member of a
/// group whose body this page offers is offered that same body under its own
/// source revision. The caller still requires the member's own entity set and
/// body witness to equal the offered ones, and an exact ACK of every body.
pub(in crate::snapshots) fn fan_out_offered_to_aliases<'a, V: Clone>(
    index: &'a ScanIndex,
    offered: &mut BTreeMap<&'a str, V>,
) {
    let carriers = index
        .files
        .values()
        .filter_map(|entry| {
            let marker = entry.codex_joined_member_set.as_ref()?;
            let value = offered.get(entry.source_file_fingerprint.as_str())?;
            Some((marker, value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    for entry in index.files.values() {
        if let Some(value) = entry
            .codex_joined_member_set
            .as_ref()
            .and_then(|marker| carriers.get(marker))
            .filter(|_| !entry.source_file_fingerprint.is_empty())
        {
            offered
                .entry(entry.source_file_fingerprint.as_str())
                .or_insert_with(|| value.clone());
        }
    }
}

impl ScanIndex {
    /// Stage bounded selector and joined-membership recovery facts without changing any committed
    /// file/body/ACK field. The caller persists this by the existing index CAS
    /// before a protected POST and adopts only that exact saved generation.
    pub(crate) fn stage_codex_recovery_capture(
        &self,
        previous: &ScanIndex,
        snapshots: &[SnapshotItem],
    ) -> (ScanIndex, BTreeSet<String>) {
        let mut staged = previous.clone();
        let mut changed = BTreeSet::new();
        let by_source = snapshots
            .iter()
            .filter_map(|item| {
                item.source_file_fingerprint.as_ref().map(|source| {
                    (
                        source.clone(),
                        resolve_codex_identity(&item.source_session_id),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        let offered_markers = self
            .files
            .values()
            .filter_map(|entry| {
                by_source.get(&entry.source_file_fingerprint)?;
                entry.codex_joined_member_set.clone()
            })
            .collect::<BTreeSet<_>>();
        let joined_items = snapshots
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    resolve_codex_identity(&item.source_session_id),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut by_owner = BTreeMap::<String, Vec<(String, ScanIndexEntry)>>::new();
        for (key, entry) in &self.files {
            let alias_owner = entry.codex_joined_member_set.as_ref().and_then(|marker| {
                if !offered_markers.contains(marker) {
                    return None;
                }
                let incidence = self.file_snapshot_fingerprints.get(key)?;
                if incidence.len() != 1 {
                    return None;
                }
                joined_items.get(incidence.iter().next()?)
            });
            let Some(owner) = by_source
                .get(&entry.source_file_fingerprint)
                .or(alias_owner)
            else {
                continue;
            };
            let receipt = entry.codex_applied_tier_receipt.as_ref();
            let marker = entry
                .codex_joined_member_set
                .as_ref()
                .map(|value| codex_file_join::captured_join(value));
            if receipt.is_none() && marker.is_none() {
                continue;
            }
            let previous_entry = previous.files.get(key);
            let tiers_covered = receipt.map_or(true, |receipt| {
                previous_entry
                    .and_then(|entry| {
                        entry
                            .codex_captured_tier_receipt
                            .as_ref()
                            .or(entry.codex_applied_tier_receipt.as_ref())
                    })
                    .is_some_and(|old| receipt.covered_by(old))
            });
            let join_covered = marker.as_ref().map_or(true, |marker| {
                previous_entry.is_some_and(|old| {
                    old.codex_captured_joined_member_set.as_ref() == Some(marker)
                        || (old.codex_captured_joined_member_set.is_none()
                            && old.codex_joined_member_set == entry.codex_joined_member_set)
                })
            });
            if tiers_covered && join_covered {
                continue;
            }
            let mut capture = previous_entry.cloned().unwrap_or_else(|| {
                let mut uncommitted = entry.clone();
                uncommitted.last_snapshot_fingerprint = None;
                uncommitted.last_upload_body_witness = None;
                claude_history_upgrade::re_owe(
                    &mut uncommitted.effective_upload_body_witness_revision,
                    0,
                    self.active_effective_upload_body_witness_revision,
                );
                uncommitted.codex_joined_member_set = None;
                uncommitted.codex_applied_tier_receipt = None;
                uncommitted.codex_applied_tier_receipt_required = false;
                uncommitted.codex_captured_uncommitted = true;
                uncommitted
            });
            capture.codex_protected_owner = Some(codex_protected_owner(owner));
            capture.codex_captured_joined_member_set = marker;
            if let Some(receipt) = receipt {
                capture.codex_captured_tier_receipt = Some(receipt.clone());
                capture.codex_captured_tier_receipt_required = true;
            }
            by_owner
                .entry(owner.clone())
                .or_default()
                .push((key.clone(), capture));
        }
        for (owner, entries) in by_owner {
            changed.insert(owner);
            for (key, entry) in entries {
                staged.files.insert(key, entry);
            }
        }
        (staged, changed)
    }
}
