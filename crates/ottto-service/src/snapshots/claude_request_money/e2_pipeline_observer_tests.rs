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

/// Capture the counters of folds released by one real enrichment. This keeps
/// acceptance assertions independent of fold lifetime, with no retained body.
#[derive(Clone, Copy, Default)]
pub(crate) struct Released {
    pub(crate) root_fallbacks: u64,
    pub(crate) disclosed: u64,
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
