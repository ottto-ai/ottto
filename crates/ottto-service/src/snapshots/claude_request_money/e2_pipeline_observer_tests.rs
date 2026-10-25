//! Per-page counter observation for acceptance tests, independent of the
//! process-global diagnostic drain used concurrently by other scanner tests.
use super::*;

pub(crate) fn root_fallbacks(items: &[SnapshotItem]) -> u64 {
    items
        .iter()
        .filter_map(|item| item.claude_money.as_deref())
        .map(|fold| fold.root_fallbacks)
        .sum()
}
