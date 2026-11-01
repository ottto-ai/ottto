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

/// Preserve the scan binding but simulate parse loss with only these observed ids.
pub(crate) fn lossy_census(index: &mut ScanIndex, file_name: &str, ids: &[&str]) {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    };
    let key = census_key(index, file_name);
    let old = index.claude_request_census.take(&key).unwrap();
    let mut hashes = ids
        .iter()
        .map(|id| claude_request_hash(id))
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();
    let record = ClaudeRequestCensusRecord::synthetic_for_test(
        &old.fingerprint_hex_for_test(),
        old.window(),
        ClaudeRequestCensusShape::Lossy,
        hashes,
    )
    .with_modified_for_test(old.modified())
    .with_birth_for_test(old.birth());
    index.claude_request_census.insert(key, record);
}

/// The indexed file named `file_name` leaves the index through the
/// production removal path, as when its transcript is deleted.
pub(crate) fn forget_file(index: &mut ScanIndex, file_name: &str) {
    let key = census_key(index, file_name);
    index.remove_file_entry(&key);
    assert!(
        !index.files.contains_key(&key),
        "{file_name} left the index"
    );
}

/// An indexed file left without a census record.
pub(crate) fn forget_census(index: &mut ScanIndex, file_name: &str) {
    let key = census_key(index, file_name);
    index.claude_request_census.remove(&key);
    assert!(index.claude_request_census.get(&key).is_none());
}

/// Requests the legacy fork-prefix exclusion assigns away from `member`.
pub(crate) fn legacy_excluded(index: &ScanIndex, member: &str) -> usize {
    index
        .claude_usage_family_witnesses
        .values()
        .filter_map(|witness| witness.legacy_excluded_request_id_hashes.get(member))
        .map(BTreeSet::len)
        .sum()
}

/// Capture the counters of folds released by one real enrichment. This keeps
/// acceptance assertions independent of fold lifetime, with no retained body.
#[derive(Clone, Copy, Default)]
pub(crate) struct Released {
    pub(crate) root_fallbacks: u64,
    pub(crate) disclosed: u64,
    pub(crate) removed_requests: u64,
}
thread_local! {
    static RELEASED: std::cell::Cell<Option<Released>> = const { std::cell::Cell::new(None) };
}
pub(crate) fn capture_released<T>(run: impl FnOnce() -> T) -> (T, Released) {
    struct Restore(Option<Released>);
    impl Drop for Restore {
        fn drop(&mut self) {
            RELEASED.with(|counts| counts.set(self.0));
        }
    }
    let _restore = Restore(RELEASED.with(|counts| counts.replace(Some(Released::default()))));
    let result = run();
    (
        result,
        RELEASED.with(|counts| counts.get().expect("capture active")),
    )
}
pub(crate) fn releasing(fold: &FileFold) {
    RELEASED.with(|counts| {
        if let Some(mut page) = counts.get() {
            page.root_fallbacks += fold.root_fallbacks;
            page.disclosed += fold.disclosed;
            counts.set(Some(page));
        }
    });
}

/// A fold kept past release only for its settled money marks: a disclosure
/// and no heap storage (no grains, activity, copies or accounts).
pub(crate) fn released_for_marks(fold: &FileFold) -> bool {
    fold.disclosed > 0
        && fold.entity.grains.is_empty()
        && fold.entity.bucket_activity.is_empty()
        && fold.copy.is_none()
        && fold.idless_copy.is_none()
        && fold.prefix_inherited.is_none()
        && fold.accounts.is_none()
        && fold.model_fallbacks.is_empty()
        && fold.skipped.is_empty()
}

thread_local! {
    static IDENTITY: std::cell::RefCell<Option<serde_json::Value>> =
        const { std::cell::RefCell::new(None) };
}
/// The page identity counters `finish_page` recorded, read just before the
/// post-identity release frees the folds they derive from.
pub(crate) fn capture_identity_counts<T>(run: impl FnOnce() -> T) -> (T, serde_json::Value) {
    struct Restore(Option<serde_json::Value>);
    impl Drop for Restore {
        fn drop(&mut self) {
            IDENTITY.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(IDENTITY.with(|slot| slot.borrow_mut().replace(serde_json::json!({}))));
    let result = run();
    let counts = IDENTITY.with(|slot| slot.borrow().clone().expect("capture active"));
    (result, counts)
}
pub(crate) fn before_release(items: &[SnapshotItem]) {
    RELEASED.with(|counts| {
        if let Some(mut page) = counts.get() {
            // Observe final native bodies before the caller's history veto,
            // including disclosing folds that keep inline marks at release.
            page.removed_requests = items
                .iter()
                .map(|item| item.removed_request_count.unwrap_or(0))
                .sum();
            counts.set(Some(page));
        }
    });
    IDENTITY.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            *slot = Some(
                serde_json::to_value(
                    crate::snapshots::claude_request_identity::page_identity_counts(items),
                )
                .expect("identity counts serialize"),
            );
        }
    });
}

/// Both #813 regressions against an actually settled, omitted held NEW key.
/// No process-cache witness is supplied to either money reader.
pub(crate) fn assert_held_new_file_has_no_money_authority(index: &ScanIndex, path: &Path) {
    let key = local_index_key(path);
    assert!(!index.files.contains_key(&key));
    assert!(!path.exists(), "vanished withheld original scenario");
    let record = index
        .claude_request_census
        .get(&key)
        .expect("held native scan");
    assert!(
        record.proves_scan(),
        "exercise matching native census evidence"
    );
    assert_eq!(scan_evidence(index, &key, record), Evidence::None);

    let mut nonproving = index.clone();
    let mut record = nonproving.claude_request_census.take(&key).unwrap();
    record.retire();
    assert!(!record.proves_scan());
    nonproving.claude_request_census.insert(key.clone(), record);
    assert!(holder_order(
        &nonproving.claude_money_birth_store,
        claude_index_path_member_ref(path).unwrap().root,
        &key
    )
    .is_some());
    assert!(!parent_proves(
        &nonproving,
        &key,
        "other-session",
        (i128::MAX, location_key(&key))
    ));
}
