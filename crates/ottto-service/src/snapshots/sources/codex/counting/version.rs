//! Historical counting codecs and V2 reduction reuse. No version selection.
use crate::snapshots::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum CountingVersion {
    Legacy,
    V2,
}
crate::durable_tail_codec::durable_enum!(CountingVersion {
    0 => Legacy,
    1 => V2,
});

/// Acknowledgement evidence already present for a session's index entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::snapshots) enum AckEvidence {
    /// No writer has published this session to this destination.
    None,
    /// A V2 writer published it; its bool travels with the ACK fields.
    V2Marked,
    /// Some writer that did not mark V2 already published it.
    LegacyAcked,
}
crate::durable_tail_codec::durable_enum!(AckEvidence {
    0 => None,
    1 => V2Marked,
    2 => LegacyAcked,
});

/// The first valid owner a complete parse proved for this entry. An invalid
/// (corrupt or future-format) binding never masks a valid one.
pub(in crate::snapshots) fn proven_owner(entry: &ScanIndexEntry) -> Option<&str> {
    [
        entry.codex_counting_owner.as_deref(),
        entry.codex_protected_owner.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|owner| valid_codex_protected_owner(owner))
}

/// An accepted old-formula entry is preserved until its physical file changes.
/// ACK facts distinguish it from an unacknowledged entry with an absent marker.
pub(in crate::snapshots) fn proven_legacy(index: &ScanIndex, key: &str) -> bool {
    index.files.get(key).is_some_and(|entry| {
        !entry.codex_counting_v2 && claude_index_file_body_accepted(index, key, entry)
    })
}

pub(in crate::snapshots) fn legacy_head_missing(index: &ScanIndex, key: &str) -> bool {
    proven_legacy(index, key) && tail_source::stored_codex_legacy_totals(index, key).is_none()
}

/// Stat-only; groups normally have no member reductions. Repair debt cannot
/// authorize conversion of unchanged accepted history.
pub(in crate::snapshots) fn unchanged_legacy(index: &ScanIndex, path: &Path) -> bool {
    let key = local_index_key(path);
    unchanged_legacy_with(index, &key, || {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && index.listing_stamp_matches(path, &metadata)
    })
}

/// Inventory already checked the physical head; reuse that observation.
pub(in crate::snapshots) fn unchanged_legacy_with(
    index: &ScanIndex,
    key: &str,
    stamp_matches: impl FnOnce() -> bool,
) -> bool {
    proven_legacy(index, key) && stamp_matches()
}

pub(in crate::snapshots) fn reusable(
    old: &SnapshotAccumulator,
    fresh: &SnapshotAccumulator,
) -> bool {
    match fresh.codex_counting.as_ref() {
        None => old.codex_counting.is_none(),
        Some(_) => old.codex_counting_v2(),
    }
}

/// Diagnose a completed replacement before the committed head is overwritten.
/// This process-local alarm fires before the save and may repeat after refusal or a crash.
pub(in crate::snapshots) fn note_recount(index: &ScanIndex, keys: &[String], new: &UsageTotals) {
    if !keys
        .iter()
        .filter_map(|key| index.files.get(key))
        .any(|entry| !entry.codex_counting_v2)
    {
        return;
    }
    let accepted = keys.iter().any(|key| proven_legacy(index, key));
    let label = if !accepted {
        Some("new_usage")
    } else if keys.len() != 1 {
        // Member-head totals alone do not prove the last ACKed session body.
        Some("baseline_unknown")
    } else {
        match tail_source::stored_codex_legacy_totals(index, &keys[0]) {
            Some(old) if !new.is_monotonic_after(&old) => Some("shrink"),
            Some(_) => None,
            None => Some("baseline_unknown"),
        }
    };
    if let Some(label) = label {
        tail_source::counters::bump(SnapshotSource::Codex, "codex_legacy_recount", label);
    }
}

crate::heap_layout_bound::no_heap!(true; CountingVersion, AckEvidence);
