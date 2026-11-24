//! Per-page counter observation for acceptance tests, independent of the
//! process-global diagnostic drain used concurrently by other scanner tests.
use super::*;

type Holders = BTreeMap<LocationKey, Option<LocationKey>>;

thread_local! {
    static HOLDERS: std::cell::RefCell<Option<Holders>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn record_holder(file: LocationKey, first: Option<&(i128, LocationKey)>) {
    HOLDERS.with_borrow_mut(|capture| {
        if let Some(holders) = capture {
            holders.insert(file, first.map(|(_, location)| *location));
        }
    });
}

pub(crate) fn capture_holders<T>(run: impl FnOnce() -> T) -> (T, Holders) {
    struct Reset(Option<Holders>);
    impl Drop for Reset {
        fn drop(&mut self) {
            HOLDERS.with_borrow_mut(|capture| *capture = self.0.take());
        }
    }
    let _reset = Reset(HOLDERS.with_borrow_mut(|capture| capture.replace(BTreeMap::new())));
    let result = run();
    (
        result,
        HOLDERS.with_borrow_mut(|capture| capture.take().unwrap()),
    )
}

pub(crate) fn counted_ids(item: &SnapshotItem) -> BTreeSet<String> {
    let fold = item.claude_money.as_deref().expect("native decision fold");
    item.claude_usage_occurrences
        .iter()
        .filter(|(_, occurrence)| {
            !fold.is_skipped(occurrence.sequence) && !occurrence.usage.is_zero()
        })
        .map(|(id, _)| id.clone())
        .collect()
}

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

/// Observe the saved premise before growth, including after a cold restart:
/// a pre-cutoff, COPY-marked, accepted carrier whose twin's saved removal
/// names it as the holder. Growth must still count r1 once.
pub(crate) fn assert_counting_twin_premise(
    index: &ScanIndex,
    carrier: &Path,
    twin: &Path,
    copied_at: &str,
    own_at: &str,
) {
    let carrier = local_index_key(carrier);
    let twin = local_index_key(twin);
    let here = location_key(&carrier);
    let other = location_key(&twin);
    assert!(
        here < other,
        "the counting carrier wins the equal-birth tie"
    );
    let member = session_member(Path::new(&carrier)).unwrap();
    assert_eq!(session_member(Path::new(&twin)).as_ref(), Some(&member));
    let store = &index.claude_money_birth_store;
    let birth = store.observed_birth(&member, &carrier).unwrap();
    assert_eq!(store.observed_birth(&member, &twin), Some(birth));
    let effective = store.effective_cutoff(&member, &carrier).unwrap();
    assert_eq!(effective, birth, "the carrier retains the pinned cutoff");
    let copied_at = rfc3339_unix_nanos(copied_at).unwrap();
    let own_at = rfc3339_unix_nanos(own_at).unwrap();
    assert!(
        copied_at + SLACK < effective,
        "r1 is a native copied prefix"
    );
    assert!(own_at > birth, "r2 is the first native own response");
    assert!(
        !from_copy_proof_cutoff(own_at),
        "r2 must precede the real cutoff"
    );
    assert_ne!(store.money_marks(here) & money_mark::COPY, 0);
    assert!(
        index.file_has_accepted_body(&carrier),
        "carrier has a real ACK"
    );
    assert!(index.claude_copy_removals.get(here).is_empty());
    assert!(
        index.files.contains_key(&twin),
        "the saved witness is indexed"
    );
    assert!(store.observations(&member).any(|(key, _)| key == other));
    let hash = claude_request_hash("r1");
    assert!(
        index
            .claude_copy_removals
            .get(other)
            .iter()
            .any(|(holder, hashes)| { *holder == here && hashes.binary_search(&hash).is_ok() }),
        "the twin must retain its saved r1 removal naming the carrier"
    );
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

/// Capture the counters of folds released by one real enrichment. This keeps
/// acceptance assertions independent of fold lifetime, with no retained body.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
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

/// Each body as its evidence chunk releases it: the page's count sums them.
pub(crate) fn before_release(item: &SnapshotItem) {
    RELEASED.with(|counts| {
        if let Some(mut page) = counts.get() {
            // Observe final native bodies before the caller's history veto,
            // including disclosing folds that keep inline marks at release.
            page.removed_requests += item.removed_request_count.unwrap_or(0);
            counts.set(Some(page));
        }
    });
}

/// Materialize the released pre-cutoff subagent behavior for an accepted
/// over-counted-head fixture. Reuse native restoration, then run the ordinary
/// enrichment/upload/ACK path; no production gate or alternate money writer.
pub(crate) fn released_subagent_copies(items: &mut [SnapshotItem]) {
    for item in items {
        if item
            .claude_money
            .as_deref()
            .is_some_and(|fold| fold.twin_pending)
        {
            let ids = skipped_ids(item).cloned().collect::<Vec<_>>();
            restore_uncovered(item, &ids);
            item.claude_money.as_deref_mut().unwrap().twin_pending = false;
        }
    }
}

/// Each indexed file still on disk: its durable copy ownership (stored
/// removal groups by holder, money marks, effective birth cutoff) and its
/// upload eligibility (accepted body not held), for comparing two reads of
/// one corpus.
pub(crate) fn durable_ownership(index: &ScanIndex) -> BTreeMap<String, String> {
    index
        .files
        .keys()
        .filter(|key| Path::new(key.as_str()).is_file())
        .map(|key| {
            let location = location_key(key);
            let cutoff = claude_index_path_member_ref(Path::new(key)).and_then(|member| {
                index
                    .claude_money_birth_store
                    .effective_cutoff(member.root, key)
            });
            (
                key.clone(),
                format!(
                    "groups={:?} marks={} cutoff={cutoff:?} eligible={}",
                    index.claude_copy_removals.get(location),
                    index.claude_money_birth_store.money_marks(location),
                    index.file_has_accepted_body_unheld(key),
                ),
            )
        })
        .collect()
}
