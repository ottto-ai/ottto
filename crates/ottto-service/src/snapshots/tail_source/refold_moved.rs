//! Counts of files whose semantic components move on an unchanged refold.
use crate::snapshots::*;
pub(in crate::snapshots) type Page = BTreeMap<u64, Vec<u64>>;
// Delete in the PR that ships the refold fix this counter informs, and no later than release
// 0.1.240 (if no fix is sized by then, make it a permanent lean counter or delete it).
pub(super) type Baselines = BTreeMap<(&'static str, u64), (Option<u64>, Vec<u64>)>;
fn digest(parts: &[&str]) -> u64 {
    u64::from_str_radix(&sha256_hex(parts)[..16], 16).unwrap()
}
pub fn unchanged(
    reason: Option<CandidateParseReason>,
    sampling: Option<&sampled_scan::Active>,
) -> bool {
    reason.is_some_and(super::load::late_evidence)
        && sampling
            .is_some_and(|active| active.mode == crate::transcript_acquisition::ReadMode::Unchanged)
}
pub fn page(source: SnapshotSource, pending: &[PendingIndexFinalization]) -> Page {
    pending
        .iter()
        .filter(|p| {
            source == SnapshotSource::ClaudeCode
                && claude_index_path_member_ref(Path::new(&p.index_key))
                    .is_some_and(|m| m.subagent_stem.is_some())
        })
        .map(|p| (digest(&[&p.source_file_fingerprint]), Vec::new()))
        .collect()
}
pub fn capture(item: &SnapshotItem, components: &BTreeMap<&'static str, String>, page: &mut Page) {
    if let Some(file) = item
        .source_file_fingerprint
        .as_deref()
        .and_then(|key| page.get_mut(&digest(&[key])))
    {
        super::counters::with_state(|(_, names, _)| {
            for (&name, hash) in components {
                let next = names.len();
                let slot = *names.entry(name).or_insert(next);
                file.resize(file.len().max(slot + 1), 0);
                file[slot] ^= digest(&[&item.source_session_id, hash]);
            }
        });
    }
}
pub fn observe(
    source: SnapshotSource,
    pending: &PendingIndexFinalization,
    fingerprint: Option<&str>,
    page: &mut Page,
) {
    let Some(file) = page.remove(&digest(&[&pending.source_file_fingerprint])) else {
        return;
    };
    let key = (source.api_slug(), digest(&[&pending.index_key]));
    let current = (fingerprint.map(|fp| digest(&[fp])), file.clone());
    let previous = pending
        .previous_snapshot_fingerprint
        .as_deref()
        .map(|fp| digest(&[fp]));
    let moved = super::counters::with_state(|(_, names, baselines)| {
        let old = baselines.insert(key, current);
        if !pending.refold_unchanged {
            return Vec::new();
        }
        let Some((_, old)) = old.filter(|(saved, _)| saved.is_some() && *saved == previous) else {
            return vec!["baseline_unknown"];
        };
        let mut moved: Vec<_> = names
            .iter()
            .filter(|(_, slot)| old.get(**slot).unwrap_or(&0) != file.get(**slot).unwrap_or(&0))
            .map(|(&name, _)| name)
            .collect();
        if moved.is_empty() {
            moved.push("unchanged");
        }
        moved
    });
    for label in moved {
        super::counters::bump(source, "tail_refold_moved", label);
    }
}
#[cfg(test)]
#[path = "refold_moved_tests.rs"]
mod tests;
