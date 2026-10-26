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

pub(crate) fn disclosed(items: &[SnapshotItem]) -> u64 {
    items
        .iter()
        .filter_map(|item| item.claude_money.as_deref())
        .map(|fold| fold.disclosed)
        .sum()
}

/// The census key of the one indexed file named `file_name`.
fn census_key(index: &ScanIndex, file_name: &str) -> String {
    let mut keys = index
        .files
        .keys()
        .filter(|key| Path::new(key).file_name().and_then(|n| n.to_str()) == Some(file_name));
    let key = keys.next().expect("an indexed file").clone();
    assert!(keys.next().is_none(), "one indexed file named {file_name}");
    key
}

/// Retirement as 35 idle days leave a record: its count stays, its request
/// hashes go.
pub(crate) fn retire_census(index: &mut ScanIndex, file_name: &str) {
    let key = census_key(index, file_name);
    let mut record = index
        .claude_request_census
        .take(&key)
        .expect("a census record");
    record.retire();
    index.claude_request_census.insert(key, record);
}

/// An indexed file left without a census record.
pub(crate) fn forget_census(index: &mut ScanIndex, file_name: &str) {
    let key = census_key(index, file_name);
    index.claude_request_census.remove(&key);
    assert!(index.claude_request_census.get(&key).is_none());
}
