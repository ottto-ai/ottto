//! Temporary counts-only component baseline, removed with the refold fix.
use crate::snapshots::*;
const LABELS: [&str; 8] = [
    "usage_accounting",
    "lifecycle_activity",
    "latency",
    "context_posture",
    "activity_summary",
    "display_identity",
    "attribution",
    "artifacts",
];
type Entities = Box<[(u64, [u64; 8])]>;
pub(in crate::snapshots) type Page = BTreeMap<u64, BTreeMap<u64, [u64; 8]>>;
type Baselines = BTreeMap<(&'static str, u64), (Option<u64>, Entities)>;
#[cfg(not(test))]
static BASELINES: std::sync::Mutex<Baselines> = std::sync::Mutex::new(BTreeMap::new());
#[cfg(test)]
thread_local! {
    static BASELINES: std::cell::RefCell<Baselines> = const { std::cell::RefCell::new(BTreeMap::new()) };
}
fn digest(value: &str) -> u64 {
    prefix(&sha256_hex(&[value]))
}
fn prefix(hash: &str) -> u64 {
    u64::from_str_radix(&hash[..16], 16).unwrap()
}
pub(in crate::snapshots) fn capture(
    source: SnapshotSource,
    item: &SnapshotItem,
    components: &BTreeMap<&'static str, String>,
    page: &mut Page,
) {
    if source == SnapshotSource::ClaudeCode {
        if let Some(file) = item.source_file_fingerprint.as_deref() {
            page.entry(digest(file)).or_default().insert(
                digest(&item.source_session_id),
                LABELS.map(|label| components.get(label).map_or(0, |hash| prefix(hash))),
            );
        }
    }
}
pub(in crate::snapshots) fn observe(
    source: SnapshotSource,
    pending: &PendingIndexFinalization,
    fingerprint: Option<&str>,
    page: &mut Page,
) {
    if source != SnapshotSource::ClaudeCode
        || !claude_index_path_member_ref(Path::new(&pending.index_key))
            .is_some_and(|member| member.subagent_stem.is_some())
    {
        return;
    }
    let entities: Entities = page
        .remove(&digest(&pending.source_file_fingerprint))
        .unwrap_or_default()
        .into_iter()
        .collect();
    let visit = |baselines: &mut Baselines| {
        let old = baselines.insert(
            (source.api_slug(), digest(&pending.index_key)),
            (fingerprint.map(digest), entities.clone()),
        );
        if !pending.refold_unchanged {
            return;
        }
        let bump = |label| super::counters::bump(source, "tail_refold_moved", label);
        let Some((_, old)) = old.filter(|(previous, old)| {
            previous.is_some()
                && *previous == pending.previous_snapshot_fingerprint.as_deref().map(digest)
                && old.iter().map(|e| e.0).eq(entities.iter().map(|e| e.0))
        }) else {
            bump("baseline_unknown");
            return;
        };
        let mut moved = false;
        for ((_, before), (_, hashes)) in old.iter().zip(entities.iter()) {
            for (i, label) in LABELS.iter().enumerate() {
                if before[i] != hashes[i] {
                    bump(label);
                    moved = true;
                }
            }
        }
        if !moved {
            bump("unchanged");
        }
    };
    #[cfg(not(test))]
    visit(
        &mut BASELINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    #[cfg(test)]
    BASELINES.with(|baselines| visit(&mut baselines.borrow_mut()));
}
#[cfg(test)]
#[path = "refold_moved_tests.rs"]
mod tests;
